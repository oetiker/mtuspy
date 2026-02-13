# CLAUDE.md — mtuspy project notes

## Project

Cross-platform Path MTU discovery tool using native ICMP sockets. Rust 2024 edition (1.85+).
Supports Linux, macOS, Windows, and Illumos.

## Build & verify

```bash
cargo fmt               # format code
cargo clippy -- -D warnings  # lint (zero warnings policy)
cargo test              # run all tests
cargo build             # debug build
make release            # release build (runs fmt + clippy first)
```

Always run `cargo clippy -- -D warnings` and `cargo test` before committing.

## Changelog

Update `CHANGES.md` under the `## Unreleased` section when making user-visible changes.
Use the appropriate subsection: `### New` for features, `### Changed` for modifications, `### Fixed` for bug fixes.
The release workflow automatically moves unreleased entries into a versioned section.

## Git workflow

The release workflow (`gh workflow_dispatch`) bumps versions and pushes tags automatically.
This means the remote may have commits you don't have locally.

**Always `git pull --rebase` before pushing.** The CI may have pushed release commits.

## Architecture

- `src/main.rs` — CLI entry point (clap derive), DNS resolution, verbose/quiet reporters
- `src/icmp.rs` — ICMP socket creation, packet construction, DF bit, permission errors
- `src/discover.rs` — binary search MTU discovery algorithm, ProbeReporter trait
- `build.rs` — BUILD_DATE injection (pure Rust, no external commands)

## Platform-specific code

All platform differences are in `src/icmp.rs` behind `#[cfg]` attributes:

- **DF bit** (`set_df_bit`): `IP_MTU_DISCOVER` on Linux, `IP_DONTFRAG` on macOS (28) / Illumos (27), `IP_DONTFRAGMENT` (14) on Windows
- **EMSGSIZE detection** (`MSG_SIZE_ERROR`): `libc::EMSGSIZE` on Unix, `10040` (WSAEMSGSIZE) on Windows
- **Permission errors** (`permission_error`): platform-specific advice (sudo/setuid/setcap/sysctl on Linux, sudo/setuid on macOS, Run as Administrator on Windows, sudo/RBAC on Illumos)
- **Winsock FFI**: inline `unsafe extern "system"` block for `setsockopt` on Windows (linked to `ws2_32`)
- Unix platforms share a `setsockopt_int` helper

## GitHub Actions

- `ci.yml` — fmt, clippy, test, smoke test (MTU discovery against localhost) on push/PR to main
- `release.yml` — multi-platform binary releases (workflow_dispatch)

## Release process

Releases are fully automated via `release.yml` (workflow_dispatch). To trigger:

```bash
gh workflow run release.yml -f release_type=bugfix    # 0.1.0 -> 0.1.1
gh workflow run release.yml -f release_type=feature   # 0.1.0 -> 0.2.0
gh workflow run release.yml -f release_type=major     # 0.1.0 -> 1.0.0
```

The workflow will:

1. Verify it's running on `main`
2. Calculate the new version from the latest git tag
3. Update `Cargo.toml` version
4. Move `## Unreleased` entries in `CHANGES.md` into a new versioned section
5. Commit, tag (`vX.Y.Z`), and push to `main`
6. Build binaries for 7 targets: Linux (x86_64/aarch64 musl), macOS (x86_64/aarch64), Windows (x86_64/aarch64 MSVC), Illumos (x86_64)
7. Create a GitHub Release with the changelog excerpt and binary archives

**Important:** After a release, `git pull --rebase` before further work — the CI pushes a version-bump commit.
