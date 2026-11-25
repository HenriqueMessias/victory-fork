# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A fork of VIctory, a compatibility layer that runs an Xbox Series title's x86-64 code natively on Windows, with console GPU code recompiled to DXIL. `README.md` has the fork's status on top and upstream's README, unchanged, below the line. `docs/architecture.md` has the crate table, import resolution and shader stages; `docs/fork-ray-tracing.md` covers the ray-tracing work (off by default).

## Rule #1: the asset policy

Nothing from the game or any other proprietary source enters the repository in any form (files, literals, fixtures, snapshots, disassembly, shader dumps, screenshots). See `docs/asset-policy.md`.

- `cargo xtask policy` is an allowlist by file extension/name, also run as a test (`repository_passes_policy`) and by the pre-commit hook: text only, under 512 KiB, no long hex/base64 runs (over 512 characters). A new file type fails unless added in `xtask/src/policy.rs`.
- Code that writes derived data must call `victory_core::ensure_outside_repo`. `.victory-root` marks the tree it refuses.
- Tests use synthetic data. Those needing real files take paths from environment variables, skip when unset, and assert on properties, never snapshots.
- The game is not named in the tree; code, comments and docs say "the title" (commit 4e17478).

## Commands

Target is `x86_64-pc-windows-msvc` with the toolchain pinned in `rust-toolchain.toml`. Much of the code and most GPU/loader tests are `#[cfg(windows)]`. On another host `victory-gpu`, `victory-loader` and what depends on them do not build natively; `cargo clippy --target x86_64-pc-windows-msvc` type-checks everything (set `CARGO_FEATURE_PURE=1`, so that `blake3` needs no MSVC), and `cargo test -p victory-shader` runs its portable tests.

```sh
cargo build --release -p victory
cargo build --profile diag -p victory --features diagnostics   # debugging aids; target/diag/

# What CI runs (windows-latest)
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked                                 # needs no game data

cargo test -p victory-shader waterfall                          # tests matching a name
cargo test -p victory-loader --test load_probe                  # one integration test file

cargo xtask policy            # asset-policy check
cargo xtask install-hooks     # pre-commit hook
```

The `diagnostics` feature gates code as well as switches, so check both clippy configurations.

Running the title needs `victory.toml` (copy `victory.example.toml`; all paths outside the repo): `victory run <exe> --execute`. Without `--execute` it only maps and binds. `victory translate [paths] --validate --pipelines` runs shaders found on disk through the translator and reports what it cannot handle; `victory census --missing` lists unimplemented imports. The README's Debugging section lists the `VICTORY_*` variables of diagnostics builds.

Some GPU tests report "skipped" and pass when something is missing: an SM 6.6 device, `dxil.dll` (validation), or for `diff_tests` the console and PC `dxc.exe` (`VICTORY_CONSOLE_DXC`, `VICTORY_PC_DXC`). A green run does not by itself mean they ran. GPU tests also run on WARP, and serialise through `valu_tests::ONE_AT_A_TIME`.

## Architecture

Flow: `victory-loader` prepares the executable as a DLL that Windows maps without running its code, then binds each import through `victory-hle`. Console D3D12.X calls reach `victory-gpu`, which drives host D3D12 and calls `victory-shader` for pipelines.

**HLE** (`victory-hle`): `modules/*` each return an `HleModule` (DLL names with optional trailing `*`, plus exports made with `hle_export!`), gathered in `modules::all()`. Our implementation always wins over `HostPolicy` pass-through, so to change a host API's behaviour, add an export there. `xgameruntime` APIs are COM-like objects handed out by `QueryApiImpl` by provider and interface id. Online areas answer as an offline console.

**GPU** (`victory-gpu`):
- The title's inlined command recording is defeated by keeping the list's put-pointer limits at zero, so every command arrives as a method call (`list.rs`), recorded onto a host list with draw state in `draw.rs`. Unimplemented device/list methods log their caller or table offset.
- Title GPU addresses are CPU addresses (unified memory). `shadow.rs` holds host copies of title buffers; `watch.rs` finds which pages the title wrote (write watching, or read-only guards on physical-page views); ranges shaders write are copied back after the submission. `memory.rs` serves shaders that use raw 40-bit addresses through a page directory; a page with no host copy is a lost access. `inplace.rs` is the experimental alternative to copying.
- Title descriptor heaps keep console sizes (views 32 bytes, samplers 16), and host heaps keep the title's descriptor order because shaders index them directly.
- Host pipelines are made on first use by worker threads (`pipeline/make.rs`); a draw whose pipeline is not ready within the frame's wait budget is dropped, as is one whose shader does not translate. So missing geometry may be a translation failure or a timeout.

**Shaders** (`victory-shader`): DXBC container → `native.rs` (GFX10 programs from the `DXIL` part) → `ir.rs` (one SSA instruction per machine instruction, implicit operands explicit) → `structure.rs` (EXEC removed: lane masks become per-lane booleans) → `resource.rs` (each descriptor/address traced to its root parameter) → `emit/lower.rs` and `emit/bitcode*` (DXIL, then clean-up passes in `emit/bitcode/opt.rs`).
- The header of `emit/mod.rs` is the binding contract between translated shaders and `victory-gpu`'s pipeline/descriptor code (user data, root views, heap indexing, buffer view kinds, mesh, rectangle lists). Changing one side requires the other.
- Unsupported code returns `ShaderError::Unsupported` rather than a guess.
- `bvh.rs` is the Rust reference for the emulated ray/node test; GPU tests compare emitted DXIL with it bit for bit.

**Caches** live under `cache_dir`. `victory-gpu/src/shader_cache.rs` keys translations by our executable's hash plus the settings that affect translation. A new environment switch that changes emitted code must be listed in `victory_shader::emit::SWITCHES` (a test finds unlisted ones), or old translations are served. A new `HostShader` field must be added to its `encode` and `decode`. For `victory-pipeline` converters, bump `version()` when output changes.

Only `victory-game` is meant to be title-specific; other crates are platform-level.

## Conventions

- Deliberate approximations are marked `shortcut:` in comments.
- Comments cite "decision NNNN"; those documents are not in this repository.
- Newer behaviour sits behind `VICTORY_*` environment switches, mostly off by default, each described in a comment where it is read.
