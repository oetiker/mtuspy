# mtuspy

[![CI](https://github.com/oetiker/mtuspy/actions/workflows/ci.yml/badge.svg)](https://github.com/oetiker/mtuspy/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/oetiker/mtuspy)](https://github.com/oetiker/mtuspy/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A command-line tool to discover the Path MTU (Maximum Transmission Unit) to a network host using native ICMP sockets.

## Overview

When configuring VPN tunnels, network interfaces, or debugging connectivity issues, knowing the actual path MTU between two hosts is essential. `mtuspy` sends ICMP echo requests with the Don't Fragment (DF) bit set and uses binary search to find the largest packet that traverses the path without fragmentation.

Unlike shell-based approaches that call `ping` in a loop, `mtuspy` uses native ICMP sockets and the kernel's Path MTU Discovery mechanism. Once a router reports that a packet is too large (EMSGSIZE), subsequent oversized probes fail immediately without waiting for a timeout.

## Features

- **Native ICMP sockets** - No external `ping` command, proper DF bit handling
- **Binary search** - Finds the exact MTU in ~14 probes for the full 0-9000 byte range
- **IPv4 and IPv6** - Automatic detection or force with `-4`/`-6`
- **Cross-platform** - Linux, macOS, Windows, and Illumos
- **Smart permissions** - Tries unprivileged ICMP first, falls back to raw sockets, gives actionable fix advice on failure
- **Quiet mode** - Machine-readable output for scripting

## Installation

### Building from Source

Requires Rust 1.85 or later.

```bash
git clone https://github.com/oetiker/mtuspy.git
cd mtuspy
make release
```

The binary will be at `target/release/mtuspy`.

### Permissions

`mtuspy` needs ICMP socket access. If you get a permission error, the tool will show you exactly how to fix it with instructions specific to your operating system.

#### Linux

```bash
# Run with sudo (simplest)
sudo mtuspy example.com

# Or grant permanent access (pick one):
sudo chown root:root /usr/local/bin/mtuspy && sudo chmod u+s /usr/local/bin/mtuspy
sudo setcap cap_net_raw+ep /usr/local/bin/mtuspy
sudo sysctl net.ipv4.ping_group_range="0 2147483647"
```

#### macOS

```bash
# Run with sudo
sudo mtuspy example.com

# Or grant permanent access:
sudo chown root:wheel /usr/local/bin/mtuspy && sudo chmod u+s /usr/local/bin/mtuspy
```

#### Windows

Run from an elevated command prompt (right-click Command Prompt or PowerShell and select "Run as administrator").

#### Illumos

```bash
# Run with sudo
sudo mtuspy example.com

# Or grant permanent access (pick one):
sudo usermod -K defaultpriv=basic,net_icmpaccess $USER   # requires re-login
sudo chown root:root /usr/local/bin/mtuspy && sudo chmod u+s /usr/local/bin/mtuspy
```

## Usage

```bash
# Discover path MTU to a host
mtuspy example.com

# Force IPv4 or IPv6
mtuspy -4 example.com
mtuspy -6 example.com

# Just print the MTU number (for scripts)
mtuspy --quiet example.com

# Limit search range (default is 9000 for jumbo frame support)
mtuspy --max 1500 example.com

# Adjust probe timeout (default 2000ms)
mtuspy --timeout 5000 slow-host.example.com
```

### Example Output

```
$ mtuspy 8.8.8.8
mtuspy — Path MTU discovery for 8.8.8.8 (8.8.8.8, IPv4)
Probing with Don't Fragment bit set (max 9000, header 28)...

Checking reachability (IPv4)...
      0 bytes payload -> ok
   4486 bytes payload -> too large
   2243 bytes payload -> too large
   1121 bytes payload -> ok
   1682 bytes payload -> too large
   1401 bytes payload -> ok
   1541 bytes payload -> too large
   1471 bytes payload -> ok
   1506 bytes payload -> too large
   1488 bytes payload -> too large
   1479 bytes payload -> too large
   1475 bytes payload -> too large
   1473 bytes payload -> too large
   1472 bytes payload -> ok

Path MTU: 1500 bytes (1472 payload + 28 header, 14 probes sent)
```

## How It Works

1. **Socket creation** - Creates an ICMP socket (unprivileged `SOCK_DGRAM` first, falls back to `SOCK_RAW`)
2. **DF bit** - Sets the Don't Fragment bit via platform-specific socket options (`IP_MTU_DISCOVER` on Linux, `IP_DONTFRAG` on macOS/Illumos, `IP_DONTFRAGMENT` on Windows)
3. **Reachability check** - Sends a minimal ICMP echo request to verify the host responds
4. **Binary search** - Probes with increasing/decreasing payload sizes, narrowing in on the maximum that gets a reply
5. **Result** - Reports `MTU = max_payload + header_overhead` (28 bytes for IPv4, 48 bytes for IPv6)

When a packet exceeds the path MTU, two things can happen:
- **EMSGSIZE** - The kernel already knows the path MTU (from a previous ICMP error) and rejects the send immediately
- **Timeout** - The packet was sent but dropped by a router along the path

Both cases cause the binary search to try a smaller size.

## Supported Platforms

| Platform | DF Bit Mechanism | Unprivileged ICMP |
|----------|-----------------|-------------------|
| Linux    | `IP_MTU_DISCOVER` | Yes (SOCK_DGRAM) |
| macOS    | `IP_DONTFRAG`   | Yes (SOCK_DGRAM) |
| Windows  | `IP_DONTFRAGMENT` | No (needs Administrator) |
| Illumos  | `IP_DONTFRAG`   | No (needs privileges) |

## Limitations

- Requires the target host to respond to ICMP echo requests
- Hosts that silently drop oversized packets (without sending ICMP errors) cause timeout-based convergence, which is slower but still works

## License

[MIT License](LICENSE)

## Contributing

Before submitting changes:

1. All tests pass: `make test`
2. Code is formatted: `make fmt`
3. No clippy warnings: `make lint`
