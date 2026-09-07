# Ananta Lua Dumper

Extract LuaJIT bytecode from Ananta's game archives and decompile it into
readable Lua, preserving script names and directory layout.

Validated on **2,760 packaged scripts**, all decompiled and accepted by the
game's Lua compiler. Results depend on the build and archives provided.

## Requirements

- Windows x64 with 64-bit Python 3.10 or newer.
- Ananta installation containing `Ananta_Data` and its matching `tolua.dll`.

## Setup and usage

Clone with `git clone --recurse-submodules https://github.com/Taiga74164/Ananta-Lua-Dumper`, then open the
repository folder. For an existing clone, initialize the pinned LJD submodule:

```powershell
git submodule update --init --recursive
```

Run the dumper against your game installation:

```powershell
python dump.py --game-root "D:\Games\Ananta"
```

Output goes to this project's `output/` folder. A full dump can take several
minutes; add `--resume` to reuse checked files and retry incomplete scripts.

## Options

| Option | Description |
| --- | --- |
| `--game-root PATH` | Game directory. Defaults to this project's parent. |
| `-o, --output PATH` | Output directory. Defaults to this project's `output/`. |
| `--resume` | Reuse unchanged, syntax-checked Lua and retry incomplete scripts. |
| `--extract-only` | Save original and normalized bytecode without decompiling. LJD is optional in this mode. |
| `--workers N` | Parallel decompilers. Default: `4`. |
| `--timeout SECONDS` | Time limit per script. Default: `600`. |
| `--block PATH` | Override archive discovery. Repeat for multiple archives. |
| `--runtime PATH` | Override the path to the matching game `tolua.dll`. |
| `--ljd PATH` | Override the LJD checkout. Defaults to this project's `vendor/ljd`. |

The dumper finds archives under
`Ananta_Data/StreamingAssets/AssetsNotPatch/Blocks/vfc_*` and loads
`Ananta_Data/Plugins/x86_64/tolua.dll` from the same installation.

`--help` lists all options; `--version` prints the tool version.
Exit codes: `0` for success, `1` for setup/input errors, `2` for an incomplete dump
or argument-parsing errors.

## Output

| Path | Contents |
| --- | --- |
| `lua/` | Decompiled Lua that passes the game's syntax check. |
| `raw/` | Original `.luajit` chunks from the archives. |
| `normalized/` | `.luajit` chunks with decoded strings and standard opcodes. |
| `manifest.json` | Input paths, hashes, chunk offsets, and each script's result or error. |

Original chunk names and bytecode paths are recorded in `manifest.json`.
Failed decompilations retain their bytecode; errors are recorded in `manifest.json`.

## How it works

The scanner validates LuaJIT chunks, decodes encrypted strings using the game
runtime, and recovers the custom opcode mapping from its exports. A local LJD
adapter handles control flow, local variables, and binary strings. The submodule
source stays unchanged.

Recovered source may contain generated labels or temporary variables. Syntax
checks do not prove identical behavior; retain the bytecode for comparison.
The dumper compiles recovered Lua to check syntax but never executes it. Coverage
is limited to packaged Lua in the supplied archives.

## Development

Run the tests from the repository folder:

```powershell
python -m unittest discover -s tests -v
```

Tests that need LJD or the game runtime skip when those dependencies are absent.
Native behavior tests execute only synthetic fixtures, with subprocess time limits.
To include all native tests, place this project inside the game directory.

Generated output, local research, and game binaries are excluded from Git.

## Credits

Decompilation uses [Aussiemon's LJD](https://github.com/Aussiemon/ljd)
