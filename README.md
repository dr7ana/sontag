```text
███████╗ ██████╗ ███╗   ██╗████████╗ █████╗  ██████╗
██╔════╝██╔═══██╗████╗  ██║╚══██╔══╝██╔══██╗██╔════╝
███████╗██║   ██║██╔██╗ ██║   ██║   ███████║██║  ███╗
╚════██║██║   ██║██║╚██╗██║   ██║   ██╔══██║██║   ██║
███████║╚██████╔╝██║ ╚████║   ██║   ██║  ██║╚██████╔╝
╚══════╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝
```

a C++ interpreter, assembly explorer, analysis-focused code execution harness

## Command Paradigm

sontag commands are organized by output mode:

- `static`: base command, deterministic text output
  - examples: `:asm`, `:ir`, `:graph cfg`, `:graph call`
- `explore`: interactive TTY mode (arrows, `j/k`, enter/quit depending on command)
  - examples: `:asm explore`, `:ir explore`
- `inspect`: structured JSON export for downstream tooling
  - examples: `:inspect asm`, `:inspect mca summary`, `:inspect mca heatmap`

## Requirements

- Linux or macOS
- CMake
- Ninja
- LLVM/Clang toolchain (clang >= 20), including:
  - `clang++`
  - `llvm-mca`
  - `llvm-objdump`
  - `llvm-nm`

macOS:

- install LLVM from Homebrew:
  - `brew install llvm@21`

## Build

### Linux

```bash
mkdir -p build
cd build
cmake .. -G Ninja \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_COMPILER=clang++
ninja -v
```

### macOS

`CMakeLists.txt` auto-detects Homebrew LLVM by default.

```bash
mkdir -p build
cd build
cmake .. -G Ninja
ninja -v
```

Optional toolchain bin override:

```bash
cmake .. -G Ninja -DSONTAG_TOOLCHAIN_BIN_DIR=/custom/llvm/bin
```

### Run

```bash
./build/sontag
```

### Tests

```bash
./build/tests/alltests
```

## Quickstart

```text
:decl int value = 64;
:decl int values[4];
values[0] = value;
values[1] = value * 2;
values[2] = values[0] + values[1];
:show all
:symbols
:asm
:ir
:ir explore
```

## Explore Mode

### `:asm explore`

Interactive assembly view with:

- opcode summary
- per-instruction rows (offset, encodings, instruction text, definitions)
- selected instruction metadata
- optional enter-on-call traversal into callee symbol

Controls:

- `Up`/`Down` or `j`/`k`: move selection
- `Enter`: follow callable symbol on selected row (when available)
- `q`: exit

![asm explore demo](docs/asm_explore.gif)

### `:ir explore`

Interactive IR view with:

- full node table (`id`, `out`, `in`, `label`)
- Sugiyama layout below the table
- selected/incoming/outgoing node id coloring in the layout

Controls:

- `Up`/`Down` or `j`/`k`: move selection
- `q`: exit

![ir explore demo](docs/ir_explore.gif)

### ARM Instruction Support
Note: tested on Apple Silicon (M4), welcoming any feedback on x86 Intel Mac performance (I don't own one)

![arm demo](docs/arm.gif)

## State and Session Commands

- `:decl <code>`: append declarative cell
- `:declfile <path>`: import full file as one declarative cell
- `:file <path>`: import file as decl + exec split from `main`/`__sontag_main`
- `:openfile <path>`: open editor, run repo `.clang-format`, import with `:file` semantics
- bare input (non-command): append executable cell
- `:show <config|decl|exec|all>`: inspect current state
- `:symbols`: list discovered symbols from current snapshot
- `:clear`: clear terminal screen
- `:help`: print command help
- `:quit`: exit REPL

## Reset and Snapshot Semantics

- snapshots persist across normal `:reset`
- `:mark <name>`: create/update snapshot tag
- `:snapshots`: list named snapshots
- `:reset`: clear active state (cells + transactions), keep snapshots
- `:reset last`: undo last successful mutation transaction
- `:reset file <path>`: undo most recent import transaction for that normalized path
- `:reset snapshots`: clear snapshot store

## Config Semantics

` :config` is category-driven:

- `:config`: interactive category menu (`build`, `ui`, `session`, `editor`)
- `:config <category>`: print keys/values for one category
- `:config <key>=<value>`: set one key
- `:config reset`: restore mutable keys to defaults

## Static Analysis Commands

### `:asm [symbol|@last]`

- default symbol: `__sontag_main` (equivalent to `main`)
- prints operation summary, opcode counts, and normalized assembly rows

### `:ir [symbol|@last]`

- default symbol: `__sontag_main`
- prints IR node table plus Sugiyama layout keyed by `n*` ids

### `:diag [symbol|@last]`

- compile diagnostics for current snapshot/symbol

### `:mca [symbol|@last]`

- runs `llvm-mca` and prints throughput/latency/resource data
- data symbols are invalid targets
- macOS arm64 note: `.subsections_via_symbols` is stripped before invoking `llvm-mca` for stable compatibility ([bugfix](https://github.com/llvm/llvm-project/pull/182694))

### `:delta`

Modes:

- `:delta [target_opt] [symbol|@last]`: pairwise (`O0 -> target_opt`, default target `O2`)
- `:delta spectrum [target_opt] [symbol|@last]`: multi-level (`O0..target_opt`)
- `:delta <snapshot> [target_opt]`: current-vs-snapshot comparison

Snapshot mode defaults to implicit symbol scope:

- `:delta <snapshot>` == `:delta <snapshot> __sontag_main`
- `main` and `__sontag_main` are treated as equivalent

N-way snapshot compare:

- `:delta <snapshot1>,<snapshot2>,<snapshot3>`
  - compares `current` against each listed snapshot in one command

### `:graph`

Supported graph subcommands:

- `:graph cfg [symbol|@last]`
- `:graph cfg export [symbol|@last]`
- `:graph call [symbol|@last]`
- `:graph call export [symbol|@last]`

Behavior:

- `:graph cfg` / `:graph call` render terminal Sugiyama graph and append `dot:` / `rendered:` artifact paths
- `:graph cfg export` / `:graph call export` print artifact summary and emit DOT (+ rendered image if available)

### `:inspect`

Structured JSON payload exporters:

- `:inspect asm [symbol|@last]`
- `:inspect mca [summary|heatmap] [symbol|@last]`

Artifacts are written under `artifacts/inspect/...`.

## Full Command List

```text
:help
:clear
:show <config|decl|exec|all>
:symbols
:decl <code>
:declfile <path>
:file <path>
:openfile <path>
:config
:config <category>
:config <key>=<value>
:config reset
:reset
:reset last
:reset snapshots
:reset file <path>
:mark <name>
:snapshots
:asm [symbol|@last]
:asm explore [symbol|@last]
:ir [symbol|@last]
:ir explore [symbol|@last]
:diag [symbol|@last]
:mca [symbol|@last]
:delta [spectrum] [target_opt] [symbol|@last]
:delta <snapshot> [target_opt]
:inspect asm [symbol|@last]
:inspect mca [summary|heatmap] [symbol|@last]
:graph cfg [symbol|@last]
:graph cfg export [symbol|@last]
:graph call [symbol|@last]
:graph call export [symbol|@last]
:quit
```

## Notes

- `color_scheme` currently supports `classic` and `vaporwave` (default).
- default `build.opt` is `O0`.
- generated source ensures synthesis of a single trailing `return` in `__sontag_main`.
