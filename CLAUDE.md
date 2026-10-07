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

Update `CHANGES.md` under the `## [Unreleased]` section when making user-visible changes.
Use the appropriate subsection: `### New` for features, `### Changed` for modifications, `### Fixed` for bug fixes.
Create release PR moves the unreleased entries into a versioned section.
A pull request without a changelog entry fails the `changelog-updated` check unless it carries the `no-changelog` label.

**Always update CHANGES.md with every commit that changes behavior, fixes bugs, or adds features.**

## Git workflow

`main` is protected: every change goes through a pull request that needs the checks `ci-passed` and `changelog-updated`.
A merged release pull request moves `main`, so the remote may have commits you don't have locally.

**Always `git pull --rebase` before pushing.**

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

## Infrastructure (repo-infra)

The CI and release workflows follow the repo-infra standard.
Files whose first comment line reads `# repo-infra: <piece> vN` (the `ri-*.yml` workflows, `changelog.yml`, `release-pr.yml`, `lib/`, `dependabot.yml`, `build/man.mk`, `build/man-deflist.lua`) are pieces: never edit them, upgrade them with `/repo-infra:apply`.
The callers and the project-owned files are ours:

- `ci.yml` — calls the pieces (`ri-ci-rust`, `ri-ci-rust-musl`, `ri-ci-man`, ...) and `ci-local.yml`
- `ci-local.yml` — smoke test (MTU discovery against localhost)
- `release-build.yml` / `release-build-local.yml` — binaries for 7 targets, `.deb`/`.rpm`, Homebrew bottles and the rewritten `Formula/mtuspy.rb`
- `release-publish.yml` — tags, uploads `.deb`/`.rpm` to gitea.oetiker.ch, publishes the release
- `.github/repo-infra.json` — version files, expected release assets, Gitea target

## Man page and packages

- `docs/manual.md` is the man page source; `make man` builds `man/mtuspy.1` (needs pandoc, `man/` is gitignored).
- `.deb`/`.rpm` metadata is in `Cargo.toml`; `pkg/debian/postinst` and `pkg/rpm/post-install.sh` set `cap_net_raw` on install.
- `Formula/mtuspy.rb` is rewritten by the release build; keep its marker comments.

## Release process

```bash
gh workflow run release-pr.yml -f release_type=bugfix    # 0.1.0 -> 0.1.1
gh workflow run release-pr.yml -f release_type=feature   # 0.1.0 -> 0.2.0
gh workflow run release-pr.yml -f release_type=major     # 0.1.0 -> 1.0.0
```

Create release PR rolls `CHANGES.md`, bumps `Cargo.toml` and `Cargo.lock`, builds and tests the release branch, and opens the release pull request with a draft release.
Merging that pull request runs `release-publish.yml`, which tags `vX.Y.Z` and publishes the release.

**Important:** After a release merges, `git pull --rebase` before further work.
