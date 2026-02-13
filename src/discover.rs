use std::net::IpAddr;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::icmp::{self, IcmpSocket, ProbeResult};

/// Result of the MTU discovery process.
pub struct MtuResult {
    /// The discovered path MTU (including IP + ICMP headers).
    pub mtu: u16,
    /// The maximum payload size that fit through the path.
    pub max_payload: u16,
    /// IP + ICMP header overhead.
    pub header_overhead: u16,
    /// Number of probes sent during discovery.
    pub probes_sent: u32,
}

/// Callback for reporting probe progress.
pub trait ProbeReporter {
    fn reachability_check(&self, addr: &IpAddr);
    fn probe_result(&self, payload_size: u16, result: &str);
}

/// Discover the path MTU to the target address.
///
/// Sends ICMP echo requests with the Don't Fragment bit set, using binary search
/// to find the largest payload that gets through. With DF set, oversized packets
/// fail immediately via EMSGSIZE once the kernel learns the path MTU — so the
/// search converges in ~13 probes for the full 0–8972 range.
pub fn discover_mtu(
    addr: IpAddr,
    max_mtu: u16,
    timeout: Duration,
    reporter: &dyn ProbeReporter,
) -> Result<MtuResult> {
    let header_overhead = icmp::header_size(&addr);
    let max_payload = max_mtu.saturating_sub(header_overhead);

    let mut socket = IcmpSocket::new(addr, timeout).context("failed to create ICMP socket")?;

    // Verify reachability with a minimal probe
    reporter.reachability_check(&addr);
    match socket.probe(0)? {
        ProbeResult::Reply => {
            reporter.probe_result(0, "ok");
        }
        ProbeResult::TooLarge => {
            anyhow::bail!(
                "Even a minimal ICMP packet is too large — \
                 this shouldn't happen. Check your network configuration."
            );
        }
        ProbeResult::Timeout => {
            anyhow::bail!(
                "Host {addr} is not responding to ICMP echo requests.\n\
                 The host may be unreachable or may be blocking ICMP."
            );
        }
    }

    let mut probes_sent: u32 = 1;
    let mut low: u16 = 0;
    let mut high = max_payload;

    // Binary search for the largest payload that gets a reply
    while low < high {
        let mid = low + (high - low).div_ceil(2);
        probes_sent += 1;

        match socket.probe(mid as usize)? {
            ProbeResult::Reply => {
                reporter.probe_result(mid, "ok");
                low = mid;
            }
            ProbeResult::TooLarge => {
                reporter.probe_result(mid, "too large");
                high = mid - 1;
            }
            ProbeResult::Timeout => {
                reporter.probe_result(mid, "timeout");
                high = mid - 1;
            }
        }
    }

    let mtu = low + header_overhead;

    Ok(MtuResult {
        mtu,
        max_payload: low,
        header_overhead,
        probes_sent,
    })
}
