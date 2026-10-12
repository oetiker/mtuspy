# Changelog

## [Unreleased]

### New

### Changed
- The README opens with a recording of mtuspy finding a path MTU, and its install section lists mise beside apt, dnf and Homebrew.
- The man page has AUTHORS, REPORTING BUGS and COPYRIGHT sections, and SEE ALSO names the project home.
- The error messages `Cannot create ICMP socket: insufficient permissions.` and `Even a minimal ICMP packet is too large; ...` and the `--help` text of `--quiet` use a colon, a semicolon or "and" where they had an em dash.

### Fixed
- mtuspy reported `Host ... is not responding to ICMP echo requests` for every host on Linux systems that allow unprivileged ICMP sockets, such as Ubuntu and Fedora, although `ping` reached the host. It now accepts the replies there.

## 0.2.0 - 2026-10-12
### New
- `.deb` and `.rpm` packages for Linux on x86_64 and aarch64, attached to each release and published in the package registry on gitea.oetiker.ch (owner `oposs`). They hold the binary and the man page of the static Linux release archives. On install they grant `cap_net_raw` to `/usr/bin/mtuspy`, so it runs without sudo.
- Homebrew formula: `brew tap oetiker/mtuspy https://github.com/oetiker/mtuspy` and `brew install mtuspy`.
- Man page `mtuspy(1)`, included in the release archives and the packages.

### Changed
- The illumos binary links the system C library instead of a static one.
- Releases are prepared as a release pull request (Actions, Create release PR) instead of the Release workflow. The release is tagged and published when that pull request merges.

### Fixed
- `cargo build --locked` from a source checkout failed because `Cargo.lock` still named mtuspy 0.1.0; each release now updates it together with `Cargo.toml`.

## 0.1.3 - 2026-02-13

### Changed

- Shrink release binaries (~616K, down from 1.2 MB) via strip, LTO, and size optimization

## 0.1.2 - 2026-02-13

### Fixed

- Use `macos-latest` runner for x86_64 macOS builds (`macos-13` unavailable)
- Use PowerShell `Compress-Archive` for Windows release archives (`zip` not available on runner)

## 0.1.1 - 2026-02-13

### Fixed

- Fix `unsafe extern` block required by Rust 2024 edition (Windows build failure)

## 0.1.0 - 2026-02-13

### New

- Path MTU discovery using native ICMP sockets with Don't Fragment bit
- Binary search algorithm (~14 probes for full 0-9000 byte range)
- IPv4 and IPv6 support (`-4`/`-6` flags)
- Cross-platform support: Linux, macOS, Windows, and Illumos
- Unprivileged ICMP socket support with automatic fallback to raw sockets
- Actionable permission error messages with platform-specific fix instructions
- Quiet mode (`--quiet`) for scripting
- Configurable maximum MTU (`--max`) and probe timeout (`--timeout`)
