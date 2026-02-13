use std::net::{IpAddr, ToSocketAddrs};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;

mod discover;
mod icmp;

#[derive(Parser)]
#[command(
    name = "mtuspy",
    version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("BUILD_DATE"), ")"),
    about = "Discover the Path MTU to a network host",
    long_about = "mtuspy discovers the Maximum Transmission Unit (MTU) for the network path \
                  to a given host. It sends ICMP echo requests with the Don't Fragment (DF) \
                  bit set and uses binary search to find the largest packet size that can \
                  traverse the path without fragmentation.\n\n\
                  The tool uses the kernel's Path MTU Discovery mechanism for fast, accurate \
                  results: once a router reports that a packet is too large, subsequent \
                  oversized probes fail immediately without waiting for a timeout.\n\n\
                  Requires ICMP socket permissions. Run --help for details if you get a \
                  permission error.",
    arg_required_else_help = true,
)]
struct Cli {
    /// Target hostname or IP address to probe
    host: String,

    /// Force IPv4
    #[arg(short = '4', long, conflicts_with = "ipv6")]
    ipv4: bool,

    /// Force IPv6
    #[arg(short = '6', long, conflicts_with = "ipv4")]
    ipv6: bool,

    /// Maximum MTU to test (bytes)
    #[arg(short, long, default_value_t = 9000)]
    max: u16,

    /// Timeout per probe in milliseconds
    #[arg(short, long, default_value_t = 2000)]
    timeout: u16,

    /// Suppress progress output — print only the final MTU value
    #[arg(short, long)]
    quiet: bool,
}

/// Resolve a hostname to an IP address, optionally filtering by address family.
fn resolve_host(host: &str, force_v4: bool, force_v6: bool) -> Result<IpAddr> {
    // Try parsing as a literal IP address first
    if let Ok(ip) = host.parse::<IpAddr>() {
        if force_v4 && ip.is_ipv6() {
            anyhow::bail!("'{host}' is an IPv6 address but -4 (IPv4 only) was specified");
        }
        if force_v6 && ip.is_ipv4() {
            anyhow::bail!("'{host}' is an IPv4 address but -6 (IPv6 only) was specified");
        }
        return Ok(ip);
    }

    // DNS resolution — ToSocketAddrs requires a port
    let addr_str = format!("{host}:0");
    let addrs: Vec<_> = addr_str
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve hostname '{host}'"))?
        .collect();

    // Filter by requested address family
    let filtered: Vec<_> = addrs
        .iter()
        .filter(|a| {
            if force_v4 {
                a.ip().is_ipv4()
            } else if force_v6 {
                a.ip().is_ipv6()
            } else {
                true
            }
        })
        .collect();

    let family_label = if force_v4 {
        "IPv4"
    } else if force_v6 {
        "IPv6"
    } else {
        "any"
    };

    filtered
        .first()
        .map(|a| a.ip())
        .with_context(|| format!("no {family_label} addresses found for '{host}'"))
}

/// Verbose reporter that prints each probe result to stdout.
struct VerboseReporter;

impl discover::ProbeReporter for VerboseReporter {
    fn reachability_check(&self, addr: &IpAddr) {
        let version = match addr {
            IpAddr::V4(_) => "IPv4",
            IpAddr::V6(_) => "IPv6",
        };
        println!("Checking reachability ({version})...");
    }

    fn probe_result(&self, payload_size: u16, result: &str) {
        println!("  {payload_size:>5} bytes payload -> {result}");
    }
}

/// Quiet reporter that prints nothing during discovery.
struct QuietReporter;

impl discover::ProbeReporter for QuietReporter {
    fn reachability_check(&self, _addr: &IpAddr) {}
    fn probe_result(&self, _payload_size: u16, _result: &str) {}
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let addr = resolve_host(&cli.host, cli.ipv4, cli.ipv6)?;
    let timeout = Duration::from_millis(cli.timeout as u64);
    let header_size = icmp::header_size(&addr);

    if !cli.quiet {
        let version = match addr {
            IpAddr::V4(_) => "IPv4",
            IpAddr::V6(_) => "IPv6",
        };
        println!(
            "mtuspy — Path MTU discovery for {} ({}, {})",
            cli.host, addr, version
        );
        println!(
            "Probing with Don't Fragment bit set (max {}, header {header_size})...",
            cli.max
        );
        println!();
    }

    let reporter: &dyn discover::ProbeReporter = if cli.quiet {
        &QuietReporter
    } else {
        &VerboseReporter
    };

    let result = discover::discover_mtu(addr, cli.max, timeout, reporter)?;

    if cli.quiet {
        println!("{}", result.mtu);
    } else {
        println!();
        println!(
            "Path MTU: {} bytes ({} payload + {} header, {} probes sent)",
            result.mtu, result.max_payload, result.header_overhead, result.probes_sent
        );
    }

    Ok(())
}
