---
title: MTUSPY
section: 1
header: mtuspy manual
footer: mtuspy
date: 2026-10-07
---

# NAME

mtuspy - discover the path MTU to a network host

# SYNOPSIS

**mtuspy** \[**-4**|**-6**\] \[**-m** *max*\] \[**-t** *timeout*\] \[**-q**\] *host*

# DESCRIPTION

**mtuspy** finds the largest packet that reaches *host* without fragmentation.
It sends ICMP echo requests with the Don't Fragment bit set and narrows the payload size with a binary search.

*host* is a hostname or a literal IPv4 or IPv6 address.
A hostname resolves to its first address, filtered by **-4** or **-6** when given.

Before the search, **mtuspy** sends one echo request with an empty payload.
When that request gets no reply, it reports the host as unreachable and stops.

A probe counts as too large when the kernel refuses to send it (`EMSGSIZE`) or when no reply arrives within the timeout.
Once a router has reported a smaller MTU, the kernel refuses every larger probe at once, without a timeout.

The reported MTU is the largest payload that got a reply plus the header overhead: 28 bytes for IPv4 (IP and ICMP header), 48 bytes for IPv6.

# OPTIONS

- `-4, --ipv4`: Use IPv4 only.
- `-6, --ipv6`: Use IPv6 only.
- `-m, --max <bytes>`: Largest MTU to test. Default: 9000.
- `-t, --timeout <ms>`: Time to wait for each reply, in milliseconds. Default: 2000.
- `-q, --quiet`: Print only the MTU as a number, followed by a newline.
- `-h, --help`: Print a usage summary and exit.
- `-V, --version`: Print the version and build date and exit.

# EXIT STATUS

- `0`: The path MTU was found.
- `1`: The host did not resolve, was unreachable, or no ICMP socket could be created.
- `2`: The command line was invalid.

# NOTES

**mtuspy** first opens an unprivileged ICMP socket (`SOCK_DGRAM`) and falls back to a raw socket (`SOCK_RAW`).
When neither is allowed, it prints the commands that grant access on the current system and exits with status 1.

On Linux, the unprivileged socket works for users whose group lies in the range of the sysctl `net.ipv4.ping_group_range`.
The raw socket needs root or the capability `cap_net_raw`.
The Debian and RPM packages set `cap_net_raw` on `/usr/bin/mtuspy` when they are installed.

On macOS, the unprivileged socket works for every user.

On Windows, **mtuspy** needs an elevated prompt (Run as administrator).

On Illumos, it needs root or the privilege `net_icmpaccess`.

# CAVEATS

A host that does not answer ICMP echo requests cannot be measured.

A router that drops oversized packets without sending an ICMP error makes every too-large probe wait for the full timeout.
The result is still correct, but the search takes longer.

# EXAMPLES

Find the path MTU to a host:

```sh
mtuspy example.com
```

Use the result in a script:

```sh
mtu=$(mtuspy --quiet example.com)
```

Search only up to the Ethernet MTU, over IPv6, with a longer timeout:

```sh
mtuspy -6 --max 1500 --timeout 5000 example.com
```

# SEE ALSO

**ping**(8), **tracepath**(8), **ip**(8)
