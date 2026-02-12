# sontag

the C++ interpreter against simply interpreting

## Requirements

- Linux
- CMake
- Ninja
- Latest stable LLVM toolchain (>= 20), including:
  - `clang++` (C++23 compiler; available in `PATH` or set via `--clang`)
  - `llvm-mca` (for `:mca`)
  - `llvm-objdump`
- `nm` (binutils) for symbol discovery

## Build

```bash
mkdir -p build
cd build
cmake ..
ninja -v
```

### Binary output:

```bash
./sontag
```

## Quickstart

```text
:decl #include <cstdint>
:decl uint64_t value = 64;
:decl uint64_t values[2];
values[0] = value;
values[1] = value * 2
:show all
:symbols
:asm
:dump
:ir
:mca
```

## Current Functionality

- interactive C++ cell entry in a REPL loop
- top-level declaration cells (`:decl`) and executable cells
- generated translation unit preview (`:show all`)
- symbol listing from compiled output (`:symbols`)
- assembly output (`:asm`)
- object disassembly via `llvm-objdump` (`:dump`)
- LLVM IR output (`:ir`)
- compiler diagnostics output (`:diag`)
- microarchitecture analysis via `llvm-mca` (`:mca`)

## How Input Works

- `:decl <code>` stores top-level declarations (includes, globals, functions).
- non-command input stores executable cells in synthesized `__sontag_repl_main()`.
- press `Shift+Tab` to insert a newline while composing a multi-line cell.
- use `:show all` to inspect the full generated source in order: declarations first, then executable cells wrapped in the synthesized function.

## Snapshots and `@last`

- a snapshot is a persisted point-in-time code state (all current `:decl` cells + executable cells) identified by cell count.
- `:mark <name>` records a named snapshot marker at the current state.
- `:snapshots` lists recorded markers in the session.
- `@last` in analysis commands means analyze the latest/current snapshot state.

## Analysis Functionalities

- `:symbols` compiles the current snapshot to an object file, runs symbol discovery, and prints symbol kind/name entries.
- `:asm [symbol|@last]` compiles the current snapshot to assembly and prints full assembly text or a symbol-scoped assembly block.
- `:dump [symbol|@last]` compiles the current snapshot to an object file, disassembles it, and prints instruction-level object disassembly.
- `:ir [symbol|@last]` compiles the current snapshot with LLVM IR emission and prints full IR text or a symbol-scoped IR definition.
- `:diag [symbol|@last]` runs compile diagnostics on the current snapshot and prints compiler errors/warnings (optionally filtered by symbol).
- `:mca [symbol|@last]` compiles to assembly, runs microarchitecture analysis, and prints throughput/latency/resource-pressure analysis text.
- `:mca` does not operate on data symbols (for example `[D]`/`[B]` entries from `:symbols`).

## Tests

```bash
./build/tests/alltests
```
