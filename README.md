# perf-processor

A Python tool for resolving inline functions in `perf record` output using multiple symbolizer backends.

## Overview

This tool processes Linux `perf` profiling data to resolve inline function call stacks, providing detailed source-level information about where your program spends time. It supports multiple symbolization backends (GSYM and DWARF via llvm-symbolizer) and streams samples to avoid loading everything into memory.

## Features

- **Multiple Symbolizer Backends**:
  - `gsym`: Uses llvm-gsymutil with GSYM debug files (fast, compact format)
  - `addr2line`: Uses llvm-symbolizer with DWARF debug info (standard format)

- **Inline Function Resolution**: Expands inlined functions to show complete call stacks

- **Streaming Processing**: Processes samples on-the-fly without loading all data into memory

- **Source Path Remapping**: Remap paths (e.g., `/rustc/hash` → actual source location)

- **Symbol Demangling**: Demangle Rust and C++ symbols for readability

- **Multiple Output Formats**: Text or JSON Lines format

- **Filtering**: Filter by PID or command name

- **Caching**: Built-in cache for symbolization results

## Requirements

- Python 3.10+
- Linux `perf` tool
- `llvm-symbolizer` (for addr2line backend)
- `llvm-gsymutil` (for gsym backend)
- Optional: `rustfilt` and `c++filt` for demangling

## Installation

Clone this repository:

```bash
git clone <repository-url>
cd perf-processor
```

Ensure required tools are in your PATH:

```bash
# Check for required tools
which perf llvm-symbolizer llvm-gsymutil

# Optional: install demangling tools
# For Rust: cargo install rustfilt
# For C++: usually included with binutils
```

## Usage

Basic usage:

```bash
./perf-inline-processor.py perf.data
```

### Examples

**Use GSYM backend with cache directory:**
```bash
./perf-inline-processor.py perf.data --symbolizer gsym --gsym-cache ~/.cache/gsym
```

**Filter by process and output JSON:**
```bash
./perf-inline-processor.py perf.data --pid 12345 --json > output.jsonl
```

**Remap source paths and demangle symbols:**
```bash
./perf-inline-processor.py perf.data \
  --remap /rustc/abc123=/home/user/rust-src \
  --demangle
```

**Verbose output for debugging:**
```bash
./perf-inline-processor.py perf.data -vv
```

### Command-line Options

```
positional arguments:
  perf_data             Path to perf.data file

optional arguments:
  --symbolizer {gsym,addr2line}
                        Symbolizer backend to use (default: addr2line)
  --remap OLD=NEW       Remap source paths (can be specified multiple times)
  --pid PID             Filter to specific process ID
  --comm COMM           Filter to specific command name
  -v, --verbose         Increase verbosity (-v for progress, -vv for details)
  --gsym-cache DIR      Directory to cache generated GSYM files
  --json                Output in JSON Lines format
  --demangle            Demangle symbol names using rustfilt and c++filt
```

## Output Format

### Text Format (default)

```
Sample 1: myapp (PID 12345)
    0x1234: function_name + 42 @ /path/to/file.rs:123
              inlined_function + 10 @ /path/to/file.rs:456

Sample 2: myapp (PID 12345)
    ...
```

### JSON Format (--json)

Each line is a JSON object:

```json
{
  "sample": 1,
  "comm": "myapp",
  "pid": 12345,
  "frames": [
    {
      "offset": "0x1234",
      "dso": "/path/to/binary",
      "symbols": [
        {"name": "function_name", "file": "/path/to/file.rs", "line": 123},
        {"name": "inlined_function", "file": "/path/to/file.rs", "line": 456}
      ]
    }
  ]
}
```

## Performance

The tool includes built-in caching and statistics reporting:

```
=== Statistics ===
Processed 1000 samples
Symbolizer backend: addr2line
Symbolizer requests: 5432
Cache hits: 3210
Cache entries: 1024
Cache hit rate: 37.1%
```

## Architecture

The tool uses a pluggable backend architecture:

- `SymbolizerBackend`: Abstract base class for symbolization
- `GSYMSymbolizer`: GSYM-based symbolization with automatic conversion
- `Addr2LineSymbolizer`: DWARF-based symbolization via llvm-symbolizer
- `StreamingInlineResolver`: Main orchestrator that processes perf output

## License

See repository for license information.
