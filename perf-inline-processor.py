#!/usr/bin/env python3
"""
Resolve inline functions in perf record output using GSYM files.

Usage: perf_inline_resolver.py <perf.data>

This script streams perf script output and resolves inline functions on-the-fly
using llvm-gsymutil, avoiding storing all samples in memory.
"""

import argparse
import asyncio
import subprocess
import sys
import re
import json
from pathlib import Path
from typing import TypedDict


class StackFrame(TypedDict):
    """A stack frame with DSO offset information."""

    offset: int
    dso: str


class SampleHeader(TypedDict):
    """Sample header information."""

    comm: str
    pid: int


class Sample(TypedDict):
    """A complete sample with stack trace."""

    stack: list[StackFrame]
    comm: str | None
    pid: int | None


class StreamingInlineResolver:
    """Streams samples from perf and resolves inline functions on-the-fly."""

    def __init__(
        self,
        perf_data_path: str,
        filter_pid: int | None = None,
        filter_comm: str | None = None,
        remappings: list[tuple[str, str]] | None = None,
        verbose: int = 0,
        gsym_cache_dir: str | None = None,
        json_output: bool = False,
        demangle: bool = False,
    ) -> None:
        self.perf_data_path: str = perf_data_path
        self.filter_pid: int | None = filter_pid
        self.filter_comm: str | None = filter_comm
        self.remappings: list[tuple[str, str]] = remappings or []
        self.verbose: int = verbose
        self.gsym_cache_dir: Path | None = (
            Path(gsym_cache_dir) if gsym_cache_dir else None
        )
        self.json_output: bool = json_output
        self.demangle: bool = demangle

        # Demangling processes (if enabled)
        self.rustfilt_proc: asyncio.subprocess.Process | None = None
        self.cppfilt_proc: asyncio.subprocess.Process | None = None

        # Create cache directory if specified
        if self.gsym_cache_dir:
            self.gsym_cache_dir.mkdir(parents=True, exist_ok=True)
            if self.verbose >= 1:
                print(
                    f"Using GSYM cache directory: {self.gsym_cache_dir}",
                    file=sys.stderr,
                )

        self.sample_count: int = 0

        # Memoization cache: (gsym_path, file_offset) -> inline frames
        self.inline_cache: dict[tuple[str, int], list[str]] = {}

        # Track which DSOs have GSYM files
        self.gsym_paths: dict[str, str | None] = {}  # dso_path -> gsym_path (or None)

        # Statistics
        self.gsymutil_requests: int = 0
        self.cache_hits: int = 0
        self.gsym_files_found: int = 0

    async def run(self) -> None:
        """Main processing loop."""
        if self.verbose >= 1:
            print("Starting llvm-gsymutil process...", file=sys.stderr)

        # Start llvm-gsymutil process
        try:
            gsymutil_proc = await asyncio.create_subprocess_exec(
                "llvm-gsymutil",
                "--addresses-from-stdin",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            if self.verbose >= 1:
                print("llvm-gsymutil started successfully", file=sys.stderr)
        except FileNotFoundError:
            print("Error: llvm-gsymutil not found in PATH", file=sys.stderr)
            sys.exit(1)

        # Start demangling processes if requested
        if self.demangle:
            try:
                self.rustfilt_proc = await asyncio.create_subprocess_exec(
                    "rustfilt",
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                if self.verbose >= 1:
                    print("rustfilt started successfully", file=sys.stderr)
            except FileNotFoundError:
                if self.verbose >= 1:
                    print(
                        "Warning: rustfilt not found, skipping Rust demangling",
                        file=sys.stderr,
                    )

            try:
                self.cppfilt_proc = await asyncio.create_subprocess_exec(
                    "c++filt",
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                if self.verbose >= 1:
                    print("c++filt started successfully", file=sys.stderr)
            except FileNotFoundError:
                if self.verbose >= 1:
                    print(
                        "Warning: c++filt not found, skipping C++ demangling",
                        file=sys.stderr,
                    )

        if self.verbose >= 1:
            print(f"Starting perf script on {self.perf_data_path}...", file=sys.stderr)

        # Start perf script process
        try:
            perf_proc = await asyncio.create_subprocess_exec(
                "perf",
                "script",
                "-i",
                self.perf_data_path,
                "-F",
                "comm,pid,ip,dso,dsoff",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            if self.verbose >= 1:
                print("perf script started successfully", file=sys.stderr)
        except FileNotFoundError:
            print("Error: perf not found in PATH", file=sys.stderr)
            sys.exit(1)

        if self.verbose >= 1:
            print("Streaming and processing samples...", file=sys.stderr)

        if not self.json_output:
            print("\n=== Samples with Inline Functions ===\n")

        # Process perf output line by line
        current_sample: Sample | None = None

        assert perf_proc.stdout is not None
        async for line in perf_proc.stdout:
            line = line.decode("utf-8").rstrip()

            if not line:
                # End of sample - blank line separator
                current_sample = None
            elif line.startswith("\t"):
                # Stack frame (indented with tab)
                # Only process if we're tracking this sample
                if current_sample is not None:
                    frame = self._parse_stack_frame(line.strip())
                    if frame:
                        # Resolve and output this frame immediately
                        await self._resolve_and_output_frame(
                            frame, current_sample, gsymutil_proc
                        )
            else:
                # Sample header - this is the start of a new sample
                header = self._parse_sample_header(line)
                if header and self._should_include_sample_header(header):
                    # This is a sample we want to track
                    self.sample_count += 1
                    current_sample = Sample(
                        stack=[], comm=header["comm"], pid=header["pid"]
                    )

                    comm = header["comm"]
                    pid = header["pid"]

                    if not self.json_output:
                        print(f"Sample {self.sample_count}: {comm} (PID {pid})")

                    if self.verbose >= 2:
                        print(
                            f"[VERBOSE] Processing sample {self.sample_count}: {comm} (PID {pid})",
                            file=sys.stderr,
                        )
                else:
                    # Sample we don't care about - set to None to skip frames
                    current_sample = None

        # Don't forget the last sample
        if current_sample is not None and not self.json_output:
            # End the last sample with a blank line
            print()

        # Clean up
        if self.verbose >= 1:
            print("Waiting for perf script to complete...", file=sys.stderr)
        perf_return = await perf_proc.wait()

        # Check for errors in perf stderr
        if perf_proc.stderr:
            perf_stderr = await perf_proc.stderr.read()
            if perf_stderr:
                print(
                    f"perf script stderr output:\n{perf_stderr.decode('utf-8')}",
                    file=sys.stderr,
                )

        if perf_return != 0:
            print(
                f"Warning: perf script exited with code {perf_return}", file=sys.stderr
            )

        if self.verbose >= 1:
            print("Closing llvm-gsymutil...", file=sys.stderr)

        assert gsymutil_proc.stdin is not None
        gsymutil_proc.stdin.close()
        await gsymutil_proc.wait()

        # Close demangling processes
        if self.rustfilt_proc and self.rustfilt_proc.stdin:
            self.rustfilt_proc.stdin.close()
            await self.rustfilt_proc.wait()

        if self.cppfilt_proc and self.cppfilt_proc.stdin:
            self.cppfilt_proc.stdin.close()
            await self.cppfilt_proc.wait()

        # Print statistics
        print(f"\n=== Statistics ===", file=sys.stderr)
        print(f"Processed {self.sample_count} samples", file=sys.stderr)
        print(f"GSYM files found: {self.gsym_files_found}", file=sys.stderr)
        print(f"Cache entries: {len(self.inline_cache)}", file=sys.stderr)
        print(f"gsymutil requests sent: {self.gsymutil_requests}", file=sys.stderr)
        print(f"Cache hits: {self.cache_hits}", file=sys.stderr)
        if self.gsymutil_requests + self.cache_hits > 0:
            cache_hit_rate = (
                100 * self.cache_hits / (self.gsymutil_requests + self.cache_hits)
            )
            print(f"Cache hit rate: {cache_hit_rate:.1f}%", file=sys.stderr)

    def _should_include_sample_header(self, header: SampleHeader) -> bool:
        """Check if sample header matches filters."""
        if self.filter_pid is not None and header["pid"] != self.filter_pid:
            return False
        if self.filter_comm is not None and header["comm"] != self.filter_comm:
            return False
        return True

    def _parse_sample_header(self, line: str) -> SampleHeader | None:
        """Parse a sample header line to extract comm and pid.

        Format: "comm pid" (no tid when using -F comm,pid,...)
        Example: "rustc 540166"
        """
        match = re.match(r"(\S+)\s+(\d+)", line)
        if match:
            return SampleHeader(comm=match.group(1), pid=int(match.group(2)))
        return None

    async def _demangle_symbol(self, symbol: str) -> str:
        """Demangle a symbol name using rustfilt and c++filt asynchronously."""
        if not self.demangle:
            return symbol

        result = symbol

        # Try rustfilt first
        if (
            self.rustfilt_proc
            and self.rustfilt_proc.stdin
            and self.rustfilt_proc.stdout
        ):
            try:
                self.rustfilt_proc.stdin.write(f"{result}\n".encode("utf-8"))
                await self.rustfilt_proc.stdin.drain()
                demangled_bytes = await self.rustfilt_proc.stdout.readline()
                if demangled_bytes:
                    result = demangled_bytes.decode("utf-8").strip()
            except Exception:
                pass

        # Then try c++filt
        if self.cppfilt_proc and self.cppfilt_proc.stdin and self.cppfilt_proc.stdout:
            try:
                self.cppfilt_proc.stdin.write(f"{result}\n".encode("utf-8"))
                await self.cppfilt_proc.stdin.drain()
                demangled_bytes = await self.cppfilt_proc.stdout.readline()
                if demangled_bytes:
                    result = demangled_bytes.decode("utf-8").strip()
            except Exception:
                pass

        return result

    def _parse_stack_frame(self, line: str) -> StackFrame | None:
        """Parse a stack frame line.

        Format: "address (dso_path+offset)"
        Example: "7faa06292411 (/usr/lib64/ld-linux-x86-64.so.2+0x24411)"
        """
        # Match: address (path+offset) or address ([unknown])
        match = re.match(r"([0-9a-f]+)\s+\((.+?)\+0x([0-9a-f]+)\)", line)
        if match:
            # Ignore the runtime address, use the offset
            offset = int(match.group(3), 16)
            dso = match.group(2)
            return StackFrame(offset=offset, dso=dso)

        # Handle [unknown] or other special cases
        match = re.match(r"([0-9a-f]+)\s+\(\[unknown\]\)", line)
        if match:
            # Skip unknown frames
            return None

        return None

    def _get_gsym_path(self, dso: str) -> str | None:
        """Get the GSYM path for a DSO, with caching and optional conversion."""
        if dso in self.gsym_paths:
            return self.gsym_paths[dso]

        # First, check for .gsym file next to the DSO
        gsym_candidate = Path(dso).with_suffix(Path(dso).suffix + ".gsym")
        if gsym_candidate.exists():
            gsym_path = str(gsym_candidate)
            self.gsym_paths[dso] = gsym_path
            self.gsym_files_found += 1
            if self.verbose >= 1:
                print(f"Found GSYM: {dso}", file=sys.stderr)
            return gsym_path

        # If cache directory is specified, check cache or try to convert
        if self.gsym_cache_dir:
            # Create a cache filename based on the DSO path
            # Use the full path hash to avoid collisions
            import hashlib

            dso_hash = hashlib.sha256(dso.encode()).hexdigest()[:16]
            dso_name = Path(dso).name
            cached_gsym = self.gsym_cache_dir / f"{dso_name}.{dso_hash}.gsym"

            # Check if cached GSYM exists and is newer than the DSO
            dso_path = Path(dso)
            if cached_gsym.exists() and dso_path.exists():
                dso_mtime = dso_path.stat().st_mtime
                cached_mtime = cached_gsym.stat().st_mtime

                if cached_mtime >= dso_mtime:
                    # Cache is valid
                    gsym_path = str(cached_gsym)
                    self.gsym_paths[dso] = gsym_path
                    self.gsym_files_found += 1
                    if self.verbose >= 1:
                        print(f"Found cached GSYM: {cached_gsym}", file=sys.stderr)
                    return gsym_path
                else:
                    if self.verbose >= 1:
                        print(
                            f"Cached GSYM is outdated (DSO modified), will regenerate: {cached_gsym}",
                            file=sys.stderr,
                        )

            # Try to convert the DSO to GSYM
            if dso_path.exists():
                if self.verbose >= 1:
                    print(f"Converting {dso} to GSYM...", file=sys.stderr)

                try:
                    result = subprocess.run(
                        [
                            "llvm-gsymutil",
                            "--convert",
                            dso,
                            "--out-file",
                            str(cached_gsym),
                        ],
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )

                    if result.returncode == 0 and cached_gsym.exists():
                        gsym_path = str(cached_gsym)
                        self.gsym_paths[dso] = gsym_path
                        self.gsym_files_found += 1
                        if self.verbose >= 1:
                            print(
                                f"Successfully converted to GSYM: {cached_gsym}",
                                file=sys.stderr,
                            )
                        return gsym_path
                    else:
                        if self.verbose >= 1:
                            print(
                                f"Failed to convert {dso}: {result.stderr}",
                                file=sys.stderr,
                            )
                except Exception as e:
                    if self.verbose >= 1:
                        print(f"Error converting {dso}: {e}", file=sys.stderr)

        # No GSYM file found or created
        self.gsym_paths[dso] = None
        return None

    async def _resolve_and_output_frame(
        self,
        frame: StackFrame,
        sample: Sample,
        gsymutil_proc: asyncio.subprocess.Process,
    ) -> None:
        """Resolve a single frame and output it immediately."""
        offset = frame["offset"]
        dso = frame["dso"]

        if self.verbose >= 2:
            print(f"[VERBOSE]   Frame: offset=0x{offset:x} dso={dso}", file=sys.stderr)

        # Check if this DSO has a GSYM file
        gsym_path = self._get_gsym_path(dso)

        # Collect resolved frames
        resolved_frames: list[str] = []
        resolved_frames_json: list[dict] = []

        if gsym_path:
            if self.verbose >= 2:
                print(f"[VERBOSE]     Resolving via GSYM: {gsym_path}", file=sys.stderr)

            # Check cache first
            cache_key = (gsym_path, offset)

            if cache_key in self.inline_cache:
                # Cache hit
                self.cache_hits += 1
                inline_frames = self.inline_cache[cache_key]
            else:
                # Need to resolve
                inline_frames = await self._resolve_single_address(
                    offset, gsym_path, gsymutil_proc
                )
                self.inline_cache[cache_key] = inline_frames

                if self.verbose >= 2:
                    print(
                        f"[VERBOSE] Resolved {len(inline_frames)} frames for 0x{offset:x}",
                        file=sys.stderr,
                    )
                    if not inline_frames:
                        print(
                            f"[VERBOSE] No frames returned (likely error or not in GSYM)",
                            file=sys.stderr,
                        )

            # Process frames for output
            if self.verbose >= 2 and inline_frames:
                print(
                    f"[VERBOSE] Processing {len(inline_frames)} frames for output",
                    file=sys.stderr,
                )
            for inline_frame in inline_frames:
                # Skip error messages
                if inline_frame.startswith("error:"):
                    continue

                # Apply remappings
                remapped = inline_frame
                for old, new in self.remappings:
                    remapped = remapped.replace(old, new)
                resolved_frames.append(remapped)

                # Parse for JSON format: "name + offset @ file:line [inlined]"
                # Example: "copy_nonoverlapping<u8> + 41 @ /path/file.rs:547 [inlined]"
                # The [inlined] suffix is optional
                match = re.match(
                    r"(.+?)\s+\+\s+\d+\s+@\s+(.+?):(\d+)(?:\s+\[inlined\])?", remapped
                )
                if match:
                    name = match.group(1)
                    file = match.group(2)
                    line = int(match.group(3))

                    # Demangle the symbol name if requested
                    demangled_name = await self._demangle_symbol(name)

                    resolved_frames_json.append(
                        {"name": demangled_name, "file": file, "line": line}
                    )
                else:
                    # Couldn't parse - this might be an error message or malformed
                    # Don't add it to the JSON output at all, just skip it
                    if self.verbose >= 2:
                        print(
                            f"[VERBOSE] Skipping unparseable frame: {remapped}",
                            file=sys.stderr,
                        )
                    continue

        # Output based on format
        if self.json_output:
            # JSON output - only include frames if we successfully resolved them
            record = {
                "sample": self.sample_count,
                "comm": sample["comm"],
                "pid": sample["pid"],
                "offset": f"0x{offset:x}",
                "dso": dso,
                "frames": resolved_frames_json if resolved_frames_json else None,
            }
            print(json.dumps(record))
        else:
            # Text output
            if resolved_frames:
                # Print first frame with address
                first_frame = resolved_frames[0]
                # Demangle for text output too
                if self.demangle:
                    # Extract and demangle just the symbol name
                    match = re.match(r"(.+?)\s+\+\s+(\d+\s+@\s+.+)", first_frame)
                    if match:
                        name = match.group(1)
                        rest = match.group(2)
                        demangled = await self._demangle_symbol(name)
                        first_frame = f"{demangled} + {rest}"

                print(f"    0x{offset:x}: {first_frame}")

                # Print remaining frames indented
                for resolved_frame in resolved_frames[1:]:
                    # Demangle for text output
                    if self.demangle:
                        match = re.match(r"(.+?)\s+\+\s+(\d+\s+@\s+.+)", resolved_frame)
                        if match:
                            name = match.group(1)
                            rest = match.group(2)
                            demangled = await self._demangle_symbol(name)
                            resolved_frame = f"{demangled} + {rest}"

                    print(f"              {resolved_frame}")
            else:
                # Resolution returned nothing - just show address
                print(f"    0x{offset:x}:")

        if not resolved_frames and self.verbose >= 2:
            print(f"[VERBOSE]     No symbols resolved for {dso}", file=sys.stderr)

    async def _resolve_single_address(
        self, offset: int, gsym_path: str, gsymutil_proc: asyncio.subprocess.Process
    ) -> list[str]:
        """Resolve a single address via gsymutil.

        Args:
            offset: File offset in the DSO
            gsym_path: Path to GSYM file
            gsymutil_proc: The gsymutil process

        Returns:
            List of inline frame strings
        """
        assert gsymutil_proc.stdin is not None
        assert gsymutil_proc.stdout is not None

        # Check if process is still alive
        if gsymutil_proc.returncode is not None:
            print(
                f"Error: gsymutil process died with return code {gsymutil_proc.returncode}",
                file=sys.stderr,
            )
            if gsymutil_proc.stderr:
                stderr_data = await gsymutil_proc.stderr.read()
                if stderr_data:
                    print(
                        f"gsymutil stderr: {stderr_data.decode('utf-8')}",
                        file=sys.stderr,
                    )
            return []

        try:
            # Send request
            line = f"0x{offset:x} {gsym_path}\n"
            gsymutil_proc.stdin.write(line.encode("utf-8"))
            await gsymutil_proc.stdin.drain()
            self.gsymutil_requests += 1

            if self.verbose >= 2:
                print(
                    f"[VERBOSE] Sent request: 0x{offset:x} {gsym_path}", file=sys.stderr
                )

            # Read response
            frames = await self._read_gsymutil_response_async(
                gsymutil_proc.stdout, offset
            )

            if self.verbose >= 2:
                print(
                    f"[VERBOSE] Received response for 0x{offset:x}: {len(frames)} frames",
                    file=sys.stderr,
                )

            return frames
        except (ConnectionResetError, BrokenPipeError) as e:
            print(f"Error communicating with gsymutil: {e}", file=sys.stderr)
            print(f"Last request was: 0x{offset:x} {gsym_path}", file=sys.stderr)
            if gsymutil_proc.stderr:
                stderr_data = await gsymutil_proc.stderr.read()
                if stderr_data:
                    print(
                        f"gsymutil stderr: {stderr_data.decode('utf-8')}",
                        file=sys.stderr,
                    )
            return []

    async def _read_gsymutil_response_async(
        self, stdout: asyncio.StreamReader, expected_offset: int
    ) -> list[str]:
        """Read one address worth of output from gsymutil asynchronously.

        Args:
            stdout: The stdout stream from gsymutil
            expected_offset: The file offset we requested (for correlation)

        Returns:
            List of inline frame strings (empty list if error or not found)
        """
        frames: list[str] = []

        # Read the first line which should start with our address (column 0)
        first_line_bytes = await stdout.readline()
        if not first_line_bytes:
            return frames

        first_line = first_line_bytes.decode("utf-8").rstrip()

        # Verify this is a response for our address
        # Format: "0xADDRESS: function + offset @ file:line [inlined]"
        #     or: "0xADDRESS: error: ..."
        match = re.match(r"0x([0-9a-f]+):\s+(.+)", first_line)
        if not match:
            return frames

        response_addr = int(match.group(1), 16)
        content = match.group(2)

        if response_addr != expected_offset:
            print(
                f"Warning: Expected response for 0x{expected_offset:x} but got 0x{response_addr:x}",
                file=sys.stderr,
            )

        # Check if the content is an error message
        if content.startswith("error:"):
            # This is an error - consume until blank line and return empty
            if self.verbose >= 2:
                print(f"[VERBOSE] gsymutil returned error: {content}", file=sys.stderr)
            while True:
                line_bytes = await stdout.readline()
                if not line_bytes:
                    break
                line = line_bytes.decode("utf-8").rstrip()
                if not line:
                    break
            return []

        frames.append(content)

        # Read continuation lines until we hit a blank line or a new address at column 0
        while True:
            line_bytes = await stdout.readline()
            if not line_bytes:
                # EOF
                break

            line = line_bytes.decode("utf-8").rstrip()

            if not line:
                # Blank line separator - end of this response
                break

            if line[0] != " ":
                # New address at column 0 - we've read too far
                # This shouldn't happen if there's a blank line separator
                print(
                    f"Warning: Found non-indented line without blank separator: {line}",
                    file=sys.stderr,
                )
                break

            # This is an indented continuation line
            frames.append(line.strip())

        return frames


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Resolve inline functions in perf record output using GSYM files"
    )
    parser.add_argument("perf_data", help="Path to perf.data file")
    parser.add_argument(
        "--remap",
        action="append",
        metavar="OLD=NEW",
        help="Remap source paths (can be specified multiple times). "
        "Example: --remap /rustc/hash=/home/user/rust",
    )
    parser.add_argument("--pid", type=int, help="Filter to specific process ID")
    parser.add_argument("--comm", help="Filter to specific command name (e.g., rustc)")
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (-v for basic progress, -vv for detailed record processing)",
    )
    parser.add_argument(
        "--gsym-cache",
        metavar="DIR",
        help="Directory to cache generated GSYM files. If specified, will attempt to convert "
        "binaries to GSYM format using llvm-gsymutil --convert",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON Lines format (one JSON object per line)",
    )
    parser.add_argument(
        "--demangle",
        action="store_true",
        help="Demangle symbol names using rustfilt and c++filt",
    )
    args = parser.parse_args()

    # Parse remap arguments
    remappings: list[tuple[str, str]] = []
    if args.remap:
        for remap_str in args.remap:
            if "=" not in remap_str:
                print(
                    f"Error: Invalid remap format '{remap_str}'. Expected OLD=NEW",
                    file=sys.stderr,
                )
                sys.exit(1)
            old, new = remap_str.split("=", 1)
            remappings.append((old, new))

    # Run streaming processor
    resolver = StreamingInlineResolver(
        args.perf_data,
        filter_pid=args.pid,
        filter_comm=args.comm,
        remappings=remappings,
        verbose=args.verbose,
        gsym_cache_dir=args.gsym_cache,
        json_output=args.json,
        demangle=args.demangle,
    )

    try:
        asyncio.run(resolver.run())
    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
