#!/usr/bin/env python3
"""
Resolve inline functions in perf record output using multiple symbolizer backends.

Usage: perf_inline_resolver.py <perf.data> [--symbolizer {gsym,addr2line}]

This script streams perf script output and resolves inline functions on-the-fly
using different symbolizer backends (llvm-gsymutil, llvm-addr2line), avoiding
storing all samples in memory.
"""

import argparse
import asyncio
import subprocess
import sys
import re
import json
import hashlib
from pathlib import Path
from typing import TypedDict, Protocol
from abc import ABC, abstractmethod
from enum import Enum


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


class SampleOutput(TypedDict):
    """Output format for a complete sample in JSON mode."""

    sample: int
    comm: str | None
    pid: int | None
    frames: list[dict]


class SymbolInfo(TypedDict):
    """Standardized symbol information across all backends."""

    name: str
    file: str | None
    line: int
    offset: int | None
    inlined: bool


class SymbolizerBackend(ABC):
    """Abstract base class for all symbolizer backends."""

    def __init__(self, verbose: int = 0, **kwargs):
        self.verbose = verbose
        self.cache: dict[tuple[str, int], list[SymbolInfo]] = {}
        self.cache_hits = 0
        self.requests_made = 0

    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the symbolizer (start processes, etc.)"""
        pass

    @abstractmethod
    async def cleanup(self) -> None:
        """Clean up resources (close processes, etc.)"""
        pass

    @abstractmethod
    def can_symbolize(self, dso_path: str) -> bool:
        """Check if this backend can symbolize the given DSO"""
        pass

    @abstractmethod
    async def resolve_address(self, dso_path: str, offset: int) -> list[SymbolInfo]:
        """
        Resolve an address to symbol information

        Args:
            dso_path: Path to the DSO/binary
            offset: File offset within the DSO

        Returns:
            List of SymbolInfo in call order (outermost first)
        """
        pass

    @property
    @abstractmethod
    def backend_name(self) -> str:
        """Name of this symbolizer backend"""
        pass

    def get_stats(self) -> dict[str, int]:
        """Get statistics for this backend"""
        return {
            "requests_made": self.requests_made,
            "cache_hits": self.cache_hits,
            "cache_entries": len(self.cache),
        }


class GSYMSymbolizer(SymbolizerBackend):
    """Symbolizer backend using llvm-gsymutil and GSYM files"""

    def __init__(self, verbose: int = 0, gsym_cache_dir: str | None = None, **kwargs):
        super().__init__(verbose, **kwargs)
        self.gsym_cache_dir = Path(gsym_cache_dir) if gsym_cache_dir else None
        self.gsym_paths: dict[str, str | None] = {}
        self.gsymutil_proc: asyncio.subprocess.Process | None = None
        self.gsym_files_found = 0

        if self.gsym_cache_dir:
            self.gsym_cache_dir.mkdir(parents=True, exist_ok=True)

    @property
    def backend_name(self) -> str:
        return "gsym"

    async def initialize(self) -> None:
        """Start the llvm-gsymutil process"""
        try:
            self.gsymutil_proc = await asyncio.create_subprocess_exec(
                "llvm-gsymutil",
                "--addresses-from-stdin",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            if self.verbose >= 1:
                print(f"[{self.backend_name}] Started llvm-gsymutil", file=sys.stderr)
        except FileNotFoundError:
            raise RuntimeError("llvm-gsymutil not found in PATH")

    async def cleanup(self) -> None:
        """Clean up the gsymutil process"""
        if self.gsymutil_proc and self.gsymutil_proc.stdin:
            self.gsymutil_proc.stdin.close()
            await self.gsymutil_proc.wait()

    def can_symbolize(self, dso_path: str) -> bool:
        """Check if we can find or create a GSYM file for this DSO"""
        gsym_path = self._get_gsym_path(dso_path)
        return gsym_path is not None

    def _get_gsym_path(self, dso_path: str) -> str | None:
        """Get GSYM path for DSO, with caching and conversion"""
        if dso_path in self.gsym_paths:
            return self.gsym_paths[dso_path]

        # Check for existing .gsym file
        gsym_candidate = Path(dso_path).with_suffix(Path(dso_path).suffix + ".gsym")
        if gsym_candidate.exists():
            gsym_path = str(gsym_candidate)
            self.gsym_paths[dso_path] = gsym_path
            self.gsym_files_found += 1
            if self.verbose >= 1:
                print(f"[{self.backend_name}] Found GSYM: {dso_path}", file=sys.stderr)
            return gsym_path

        # Try to convert if cache directory is available
        if self.gsym_cache_dir:
            return self._try_convert_to_gsym(dso_path)

        self.gsym_paths[dso_path] = None
        return None

    def _try_convert_to_gsym(self, dso_path: str) -> str | None:
        """Try to convert DSO to GSYM format"""
        dso_hash = hashlib.sha256(dso_path.encode()).hexdigest()[:16]
        dso_name = Path(dso_path).name
        cached_gsym = self.gsym_cache_dir / f"{dso_name}.{dso_hash}.gsym"

        dso_file = Path(dso_path)
        if cached_gsym.exists() and dso_file.exists():
            if cached_gsym.stat().st_mtime >= dso_file.stat().st_mtime:
                self.gsym_paths[dso_path] = str(cached_gsym)
                self.gsym_files_found += 1
                if self.verbose >= 1:
                    print(
                        f"[{self.backend_name}] Found cached GSYM: {cached_gsym}",
                        file=sys.stderr,
                    )
                return str(cached_gsym)
            else:
                if self.verbose >= 1:
                    print(
                        f"[{self.backend_name}] Cached GSYM outdated, regenerating: {cached_gsym}",
                        file=sys.stderr,
                    )

        # Convert DSO to GSYM
        if dso_file.exists():
            if self.verbose >= 1:
                print(
                    f"[{self.backend_name}] Converting {dso_path} to GSYM...",
                    file=sys.stderr,
                )

            try:
                result = subprocess.run(
                    [
                        "llvm-gsymutil",
                        "--convert",
                        dso_path,
                        "--out-file",
                        str(cached_gsym),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )

                if result.returncode == 0 and cached_gsym.exists():
                    self.gsym_paths[dso_path] = str(cached_gsym)
                    self.gsym_files_found += 1
                    if self.verbose >= 1:
                        print(
                            f"[{self.backend_name}] Successfully converted to GSYM: {cached_gsym}",
                            file=sys.stderr,
                        )
                    return str(cached_gsym)
                else:
                    if self.verbose >= 1:
                        print(
                            f"[{self.backend_name}] Failed to convert {dso_path}: {result.stderr}",
                            file=sys.stderr,
                        )
            except Exception as e:
                if self.verbose >= 1:
                    print(
                        f"[{self.backend_name}] Error converting {dso_path}: {e}",
                        file=sys.stderr,
                    )

        self.gsym_paths[dso_path] = None
        return None

    async def resolve_address(self, dso_path: str, offset: int) -> list[SymbolInfo]:
        """Resolve address using GSYM"""
        gsym_path = self._get_gsym_path(dso_path)
        if not gsym_path:
            return []

        cache_key = (gsym_path, offset)
        if cache_key in self.cache:
            self.cache_hits += 1
            return self.cache[cache_key]

        if not self.gsymutil_proc:
            return []

        # Send request to gsymutil
        line = f"0x{offset:x} {gsym_path}\n"
        assert self.gsymutil_proc.stdin is not None
        self.gsymutil_proc.stdin.write(line.encode("utf-8"))
        await self.gsymutil_proc.stdin.drain()
        self.requests_made += 1

        if self.verbose >= 2:
            print(
                f"[{self.backend_name}] Sent request: 0x{offset:x} {gsym_path}",
                file=sys.stderr,
            )

        # Parse response
        symbols = await self._parse_gsymutil_response(offset)
        self.cache[cache_key] = symbols
        return symbols

    async def _parse_gsymutil_response(self, expected_offset: int) -> list[SymbolInfo]:
        """Parse gsymutil response into SymbolInfo objects"""
        if not self.gsymutil_proc or not self.gsymutil_proc.stdout:
            return []

        symbols: list[SymbolInfo] = []

        # Read the first line which should start with our address
        first_line_bytes = await self.gsymutil_proc.stdout.readline()
        if not first_line_bytes:
            return symbols

        first_line = first_line_bytes.decode("utf-8").rstrip()

        # Verify this is a response for our address
        match = re.match(r"0x([0-9a-f]+):\s+(.+)", first_line)
        if not match:
            return symbols

        response_addr = int(match.group(1), 16)
        content = match.group(2)

        if response_addr != expected_offset:
            print(
                f"Warning: Expected response for 0x{expected_offset:x} but got 0x{response_addr:x}",
                file=sys.stderr,
            )

        # Check if the content is an error message
        if content.startswith("error:"):
            if self.verbose >= 2:
                print(
                    f"[{self.backend_name}] gsymutil returned error: {content}",
                    file=sys.stderr,
                )
            # Consume until blank line
            while True:
                line_bytes = await self.gsymutil_proc.stdout.readline()
                if not line_bytes:
                    break
                line = line_bytes.decode("utf-8").rstrip()
                if not line:
                    break
            return []

        # Parse first frame
        frame_info = self._parse_gsym_frame(content)
        if frame_info:
            symbols.append(frame_info)

        # Read continuation lines until blank line
        while True:
            line_bytes = await self.gsymutil_proc.stdout.readline()
            if not line_bytes:
                break

            line = line_bytes.decode("utf-8").rstrip()
            if not line:
                break

            if line[0] != " ":
                print(
                    f"Warning: Found non-indented line without blank separator: {line}",
                    file=sys.stderr,
                )
                break

            frame_info = self._parse_gsym_frame(line.strip())
            if frame_info:
                symbols.append(frame_info)

        if self.verbose >= 2:
            print(
                f"[{self.backend_name}] Received response for 0x{expected_offset:x}: {len(symbols)} frames",
                file=sys.stderr,
            )

        return symbols

    def _parse_gsym_frame(self, frame_text: str) -> SymbolInfo | None:
        """Parse a single GSYM frame into SymbolInfo"""
        # Example: "copy_nonoverlapping<u8> + 41 @ /path/file.rs:547 [inlined]"
        match = re.match(
            r"(.+?)\s+\+\s+(\d+)\s+@\s+(.+?):(\d+)(?:\s+\[inlined\])?", frame_text
        )
        if match:
            name = match.group(1)
            offset = int(match.group(2))
            file = match.group(3)
            line = int(match.group(4))
            inlined = "[inlined]" in frame_text

            return SymbolInfo(
                name=name, file=file, line=line, offset=offset, inlined=inlined
            )
        return None


class Addr2LineSymbolizer(SymbolizerBackend):
    """Symbolizer backend using llvm-symbolizer with DWARF"""

    def __init__(self, verbose: int = 0, **kwargs):
        super().__init__(verbose, **kwargs)
        self.addr2line_procs: dict[str, asyncio.subprocess.Process] = {}

    @property
    def backend_name(self) -> str:
        return "addr2line"

    async def initialize(self) -> None:
        """Initialize - addr2line processes are created per-DSO as needed"""
        pass

    async def cleanup(self) -> None:
        """Clean up all symbolizer processes"""
        for proc in self.addr2line_procs.values():
            if proc.stdin:
                proc.stdin.close()
                await proc.wait()
        self.addr2line_procs.clear()

    def can_symbolize(self, dso_path: str) -> bool:
        """Always return True - we'll try the lookup and see if it works"""
        return Path(dso_path).exists()

    async def resolve_address(self, dso_path: str, offset: int) -> list[SymbolInfo]:
        """Resolve address using addr2line"""
        cache_key = (dso_path, offset)
        if cache_key in self.cache:
            self.cache_hits += 1
            return self.cache[cache_key]

        # Get or create symbolizer process for this DSO
        proc = await self._get_symbolizer_process(dso_path)
        if not proc:
            return []

        # Send address to addr2line
        assert proc.stdin is not None
        proc.stdin.write(f"0x{offset:x}\n".encode("utf-8"))
        await proc.stdin.drain()
        self.requests_made += 1

        if self.verbose >= 2:
            print(
                f"[{self.backend_name}] Sent request: 0x{offset:x} to {dso_path}",
                file=sys.stderr,
            )

        # Parse response
        symbols = await self._parse_symbolizer_response(proc)

        self.cache[cache_key] = symbols

        if self.verbose >= 2:
            print(
                f"[{self.backend_name}] Received response for 0x{offset:x}: {len(symbols)} frames",
                file=sys.stderr,
            )

        return symbols

    async def _get_symbolizer_process(
        self, dso_path: str
    ) -> asyncio.subprocess.Process | None:
        """Get or create llvm-symbolizer process for a specific DSO"""
        if dso_path in self.addr2line_procs:
            return self.addr2line_procs[dso_path]

        try:
            proc = await asyncio.create_subprocess_exec(
                "llvm-symbolizer",
                "--obj",
                dso_path,
                "--debuginfod",
                "--functions",  # Show function names
                "--inlines",  # Show inlined functions
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            self.addr2line_procs[dso_path] = proc
            if self.verbose >= 2:
                print(
                    f"[{self.backend_name}] Started llvm-symbolizer process for {dso_path}",
                    file=sys.stderr,
                )
            return proc
        except FileNotFoundError:
            if self.verbose >= 1:
                print(
                    f"[{self.backend_name}] llvm-symbolizer not found in PATH",
                    file=sys.stderr,
                )
            return None

    async def _parse_symbolizer_response(
        self, proc: asyncio.subprocess.Process
    ) -> list[SymbolInfo]:
        """Parse llvm-symbolizer output - responses are separated by blank lines"""
        symbols: list[SymbolInfo] = []

        assert proc.stdout is not None

        # Read function/location pairs until we hit a blank line
        while True:
            func_line_bytes = await proc.stdout.readline()
            if not func_line_bytes:
                break
            func_name = func_line_bytes.decode("utf-8").strip()

            # Empty line means end of this address's response
            if not func_name:
                break

            # Read location line
            location_line_bytes = await proc.stdout.readline()
            if not location_line_bytes:
                break
            location = location_line_bytes.decode("utf-8").strip()

            # If we get ?? for function name, no symbols available
            if func_name == "??":
                break

            # Try to parse file:line:column (we ignore column)
            if ":" in location and not location.startswith("??:"):
                # Split on : but only take first two parts (file:line)
                parts = location.split(":")
                if len(parts) >= 2:
                    file_path = parts[0]
                    try:
                        line_num = int(parts[1])
                        symbols.append(
                            SymbolInfo(
                                name=func_name,
                                file=file_path,
                                line=line_num,
                                offset=None,  # symbolizer doesn't provide offset within function
                                inlined=len(symbols)
                                > 0,  # First is main function, rest are inlined
                            )
                        )
                        continue
                    except ValueError:
                        pass  # Fall through to function-only case

            # Accept function name even without valid source location
            symbols.append(
                SymbolInfo(
                    name=func_name,
                    file=None,
                    line=0,
                    offset=None,
                    inlined=len(symbols) > 0,
                )
            )

        return symbols


class SymbolizerType(Enum):
    GSYM = "gsym"
    ADDR2LINE = "addr2line"


class SymbolizerFactory:
    """Factory for creating symbolizer backends"""

    @staticmethod
    def create_symbolizer(
        symbolizer_type: SymbolizerType, verbose: int = 0, **kwargs
    ) -> SymbolizerBackend:
        """Create a symbolizer backend of the specified type"""

        if symbolizer_type == SymbolizerType.GSYM:
            return GSYMSymbolizer(verbose=verbose, **kwargs)
        elif symbolizer_type == SymbolizerType.ADDR2LINE:
            return Addr2LineSymbolizer(verbose=verbose, **kwargs)
        else:
            raise ValueError(f"Unknown symbolizer type: {symbolizer_type}")


class StreamingInlineResolver:
    """Streams samples from perf and resolves inline functions using pluggable backends."""

    def __init__(
        self,
        perf_data_path: str,
        symbolizer_type: SymbolizerType = SymbolizerType.ADDR2LINE,
        filter_pid: int | None = None,
        filter_comm: str | None = None,
        remappings: list[tuple[str, str]] | None = None,
        verbose: int = 0,
        gsym_cache_dir: str | None = None,
        json_output: bool = False,
        demangle: bool = False,
    ) -> None:
        self.perf_data_path = perf_data_path
        self.filter_pid = filter_pid
        self.filter_comm = filter_comm
        self.remappings = remappings or []
        self.verbose = verbose
        self.json_output = json_output
        self.demangle = demangle
        self.sample_count = 0

        # Create symbolizer backend
        self.symbolizer = SymbolizerFactory.create_symbolizer(
            symbolizer_type, verbose=verbose, gsym_cache_dir=gsym_cache_dir
        )

        # Demangling processes (if enabled)
        self.rustfilt_proc: asyncio.subprocess.Process | None = None
        self.cppfilt_proc: asyncio.subprocess.Process | None = None

    async def run(self) -> None:
        """Main processing loop."""
        if self.verbose >= 1:
            print(
                f"Using symbolizer backend: {self.symbolizer.backend_name}",
                file=sys.stderr,
            )

        # Initialize symbolizer
        await self.symbolizer.initialize()

        try:
            # Start demangling processes if requested
            if self.demangle:
                await self._start_demangling_processes()

            # Process perf output
            await self._process_perf_output()

        finally:
            # Clean up
            await self.symbolizer.cleanup()
            await self._cleanup_demangling_processes()

        # Print statistics
        self._print_statistics()

    async def _start_demangling_processes(self) -> None:
        """Start demangling processes if requested"""
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

    async def _cleanup_demangling_processes(self) -> None:
        """Clean up demangling processes"""
        if self.rustfilt_proc and self.rustfilt_proc.stdin:
            self.rustfilt_proc.stdin.close()
            await self.rustfilt_proc.wait()

        if self.cppfilt_proc and self.cppfilt_proc.stdin:
            self.cppfilt_proc.stdin.close()
            await self.cppfilt_proc.wait()

    async def _process_perf_output(self) -> None:
        """Process perf script output line by line"""
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
            line_str = line.decode("utf-8").rstrip()

            if self.verbose >= 2:
                print(f"[VERBOSE] Read line: {repr(line_str)}", file=sys.stderr)

            if not line_str:
                # End of sample - blank line separator
                if current_sample is not None:
                    if self.verbose >= 2:
                        print(
                            f"[VERBOSE] End of sample {self.sample_count}, outputting {len(current_sample['stack'])} frames",
                            file=sys.stderr,
                        )
                    await self._output_sample(current_sample)
                current_sample = None
            elif line_str.startswith("\t"):
                # Stack frame (indented with tab)
                if current_sample is not None:
                    frame = self._parse_stack_frame(line_str.strip())
                    if frame:
                        current_sample["stack"].append(frame)
                        if self.verbose >= 2:
                            print(f"[VERBOSE] Added frame: {frame}", file=sys.stderr)
            else:
                # Sample header
                # If we have a current sample, process it before starting new one
                if current_sample is not None:
                    if self.verbose >= 2:
                        print(
                            f"[VERBOSE] Starting new sample, outputting current sample {self.sample_count} with {len(current_sample['stack'])} frames",
                            file=sys.stderr,
                        )
                    await self._output_sample(current_sample)

                header = self._parse_sample_header(line_str)
                if header and self._should_include_sample_header(header):
                    self.sample_count += 1
                    current_sample = Sample(
                        stack=[], comm=header["comm"], pid=header["pid"]
                    )

                    if not self.json_output:
                        print(
                            f"Sample {self.sample_count}: {header['comm']} (PID {header['pid']})"
                        )

                    if self.verbose >= 2:
                        print(
                            f"[VERBOSE] Processing sample {self.sample_count}: {header['comm']} (PID {header['pid']})",
                            file=sys.stderr,
                        )
                else:
                    current_sample = None

        # Process the last sample if we have one
        if current_sample is not None:
            if self.verbose >= 2:
                print(
                    f"[VERBOSE] EOF reached, outputting final sample {self.sample_count} with {len(current_sample['stack'])} frames",
                    file=sys.stderr,
                )
            await self._output_sample(current_sample)

        # Wait for perf script to complete
        perf_return = await perf_proc.wait()

        # Check for errors
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

    def _should_include_sample_header(self, header: SampleHeader) -> bool:
        """Check if sample header matches filters."""
        if self.filter_pid is not None and header["pid"] != self.filter_pid:
            return False
        if self.filter_comm is not None and header["comm"] != self.filter_comm:
            return False
        return True

    def _parse_sample_header(self, line: str) -> SampleHeader | None:
        """Parse a sample header line to extract comm and pid."""
        match = re.match(r"(\S+)\s+(\d+)", line)
        if match:
            return SampleHeader(comm=match.group(1), pid=int(match.group(2)))
        return None

    def _parse_stack_frame(self, line: str) -> StackFrame | None:
        """Parse a stack frame line."""
        # Match: address (path+offset)
        match = re.match(r"([0-9a-f]+)\s+\((.+?)\+0x([0-9a-f]+)\)", line)
        if match:
            offset = int(match.group(3), 16)
            dso = match.group(2)
            return StackFrame(offset=offset, dso=dso)

        # Handle [unknown] or other special cases
        match = re.match(r"([0-9a-f]+)\s+\(\[unknown\]\)", line)
        if match:
            return None

        return None

    async def _output_sample(self, sample: Sample) -> None:
        """Output a complete sample with all resolved frames."""
        if self.json_output:
            await self._output_sample_json(sample)
        else:
            await self._output_sample_text(sample)
            print()  # Blank line after sample

    async def _output_sample_json(self, sample: Sample) -> None:
        """Output sample in JSON format."""
        frames = []

        for frame in sample["stack"]:
            offset = frame["offset"]
            dso = frame["dso"]

            if self.verbose >= 2:
                print(
                    f"[VERBOSE]   Frame: offset=0x{offset:x} dso={dso}", file=sys.stderr
                )

            # Resolve using the symbolizer backend
            symbols = await self.symbolizer.resolve_address(dso, offset)

            # Apply remappings and demangle
            resolved_symbols = []
            for symbol in symbols:
                # Apply remappings
                file_path = symbol["file"]
                if file_path:
                    for old, new in self.remappings:
                        file_path = file_path.replace(old, new)

                # Demangle symbol name
                name = (
                    await self._demangle_symbol(symbol["name"])
                    if self.demangle
                    else symbol["name"]
                )

                resolved_symbols.append(
                    {"name": name, "file": file_path, "line": symbol["line"]}
                )

            frame_record = {
                "offset": f"0x{offset:x}",
                "dso": dso,
                "symbols": resolved_symbols if resolved_symbols else None,
            }
            frames.append(frame_record)

        sample_record = SampleOutput(
            sample=self.sample_count,
            comm=sample["comm"],
            pid=sample["pid"],
            frames=frames,
        )
        print(json.dumps(sample_record))

    async def _output_sample_text(self, sample: Sample) -> None:
        """Output sample in text format."""
        for frame in sample["stack"]:
            offset = frame["offset"]
            dso = frame["dso"]

            if self.verbose >= 2:
                print(
                    f"[VERBOSE]   Frame: offset=0x{offset:x} dso={dso}", file=sys.stderr
                )

            # Resolve using the symbolizer backend
            symbols = await self.symbolizer.resolve_address(dso, offset)

            # Apply remappings
            for symbol in symbols:
                if symbol["file"]:
                    for old, new in self.remappings:
                        symbol["file"] = symbol["file"].replace(old, new)

            await self._output_text_frame(frame, symbols)

    async def _output_text_frame(
        self, frame: StackFrame, symbols: list[SymbolInfo]
    ) -> None:
        """Output a single frame in text format."""
        if symbols:
            # Print first frame with address
            first_symbol = symbols[0]
            name = (
                await self._demangle_symbol(first_symbol["name"])
                if self.demangle
                else first_symbol["name"]
            )

            if first_symbol["offset"] is not None:
                first_line = f"{name} + {first_symbol['offset']} @ {first_symbol['file']}:{first_symbol['line']}"
            else:
                if first_symbol["file"]:
                    first_line = (
                        f"{name} @ {first_symbol['file']}:{first_symbol['line']}"
                    )
                else:
                    first_line = f"{name}"

            print(f"    0x{frame['offset']:x}: {first_line}")

            # Print remaining frames indented
            for symbol in symbols[1:]:
                name = (
                    await self._demangle_symbol(symbol["name"])
                    if self.demangle
                    else symbol["name"]
                )

                if symbol["offset"] is not None:
                    frame_line = f"{name} + {symbol['offset']} @ {symbol['file']}:{symbol['line']}"
                else:
                    if symbol["file"]:
                        frame_line = f"{name} @ {symbol['file']}:{symbol['line']}"
                    else:
                        frame_line = f"{name}"

                print(f"              {frame_line}")
        else:
            # No symbols resolved
            print(f"    0x{frame['offset']:x}:")

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

    def _print_statistics(self) -> None:
        """Print processing statistics"""
        print(f"\n=== Statistics ===", file=sys.stderr)
        print(f"Processed {self.sample_count} samples", file=sys.stderr)

        backend_stats = self.symbolizer.get_stats()
        print(f"Symbolizer backend: {self.symbolizer.backend_name}", file=sys.stderr)
        print(f"Symbolizer requests: {backend_stats['requests_made']}", file=sys.stderr)
        print(f"Cache hits: {backend_stats['cache_hits']}", file=sys.stderr)
        print(f"Cache entries: {backend_stats['cache_entries']}", file=sys.stderr)

        if hasattr(self.symbolizer, "gsym_files_found"):
            print(
                f"GSYM files found: {self.symbolizer.gsym_files_found}", file=sys.stderr
            )

        total_requests = backend_stats["requests_made"] + backend_stats["cache_hits"]
        if total_requests > 0:
            cache_hit_rate = 100 * backend_stats["cache_hits"] / total_requests
            print(f"Cache hit rate: {cache_hit_rate:.1f}%", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Resolve inline functions in perf record output using multiple symbolizer backends"
    )
    parser.add_argument("perf_data", help="Path to perf.data file")

    # Symbolizer selection
    parser.add_argument(
        "--symbolizer",
        choices=["gsym", "addr2line"],
        default="addr2line",
        help="Symbolizer backend to use (default: addr2line)",
    )

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
        help="Directory to cache generated GSYM files (only used with gsym backend)",
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

    symbolizer_type = SymbolizerType(args.symbolizer)

    # Run streaming processor
    resolver = StreamingInlineResolver(
        args.perf_data,
        symbolizer_type=symbolizer_type,
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
