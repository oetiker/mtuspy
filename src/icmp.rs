use std::io;
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

/// Header overhead: IPv4 (20) + ICMP (8) = 28, IPv6 (40) + ICMPv6 (8) = 48.
pub fn header_size(addr: &IpAddr) -> u16 {
    match addr {
        IpAddr::V4(_) => 28,
        IpAddr::V6(_) => 48,
    }
}

/// ICMP echo request type values.
fn echo_request_type(addr: &IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => 8,   // ICMP Echo Request
        IpAddr::V6(_) => 128, // ICMPv6 Echo Request
    }
}

/// ICMP echo reply type values.
fn echo_reply_type(addr: &IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => 0,   // ICMP Echo Reply
        IpAddr::V6(_) => 129, // ICMPv6 Echo Reply
    }
}

/// Compute the Internet Checksum (RFC 1071) over a byte slice.
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build an ICMP echo request packet with the given identifier, sequence, and payload size.
pub fn build_echo_request(addr: &IpAddr, id: u16, seq: u16, payload_size: usize) -> Vec<u8> {
    let total = 8 + payload_size; // ICMP header (8 bytes) + payload
    let mut pkt = vec![0u8; total];

    pkt[0] = echo_request_type(addr); // Type
    pkt[1] = 0; // Code
    // Checksum at [2..4] — filled below
    pkt[4..6].copy_from_slice(&id.to_be_bytes());
    pkt[6..8].copy_from_slice(&seq.to_be_bytes());

    // Fill payload with a recognizable pattern
    for i in 0..payload_size {
        pkt[8 + i] = (i & 0xFF) as u8;
    }

    let cksum = checksum(&pkt);
    pkt[2..4].copy_from_slice(&cksum.to_be_bytes());

    pkt
}

/// Check if a received packet is an echo reply matching our identifier and sequence.
fn is_echo_reply(addr: &IpAddr, data: &[u8], expected_id: u16, expected_seq: u16) -> bool {
    if data.len() < 8 {
        return false;
    }
    if data[0] != echo_reply_type(addr) {
        return false;
    }
    let id = u16::from_be_bytes([data[4], data[5]]);
    let seq = u16::from_be_bytes([data[6], data[7]]);
    id == expected_id && seq == expected_seq
}

/// Result of a single probe attempt.
pub enum ProbeResult {
    /// Echo reply received — the packet fit through the path.
    Reply,
    /// Kernel returned EMSGSIZE — path MTU is smaller than the packet.
    TooLarge,
    /// No reply within the timeout.
    Timeout,
}

/// An ICMP socket that can send echo requests and receive replies.
pub struct IcmpSocket {
    socket: Socket,
    addr: IpAddr,
    id: u16,
    seq: u16,
}

impl IcmpSocket {
    /// Create a new ICMP socket connected to `addr`.
    ///
    /// Tries unprivileged ICMP (SOCK_DGRAM) first, falls back to raw (SOCK_RAW).
    /// Sets the Don't Fragment bit via platform-specific socket options.
    pub fn new(addr: IpAddr, timeout: Duration) -> Result<Self> {
        let (domain, protocol) = match addr {
            IpAddr::V4(_) => (Domain::IPV4, Protocol::ICMPV4),
            IpAddr::V6(_) => (Domain::IPV6, Protocol::ICMPV6),
        };

        let socket = try_create_socket(domain, protocol)?;

        socket
            .set_read_timeout(Some(timeout))
            .context("failed to set read timeout")?;

        // Connect so we can use send()/recv()
        let sockaddr = SockAddr::from(SocketAddr::new(addr, 0));
        socket
            .connect(&sockaddr)
            .context("failed to connect ICMP socket")?;

        // Set Don't Fragment bit
        set_df_bit(&socket, &addr)?;

        let id = std::process::id() as u16;

        Ok(Self {
            socket,
            addr,
            id,
            seq: 0,
        })
    }

    /// Send an ICMP echo request with the given payload size and wait for a reply.
    pub fn probe(&mut self, payload_size: usize) -> Result<ProbeResult> {
        self.seq = self.seq.wrapping_add(1);
        let pkt = build_echo_request(&self.addr, self.id, self.seq, payload_size);

        // Send — may fail with EMSGSIZE if kernel knows the path MTU is too small
        match self.socket.send(&pkt) {
            Ok(_) => {}
            Err(e) if is_msg_size_error(&e) => return Ok(ProbeResult::TooLarge),
            Err(e) => return Err(e).context("failed to send ICMP packet"),
        }

        // Wait for echo reply
        let mut buf = vec![MaybeUninit::<u8>::uninit(); 65536];
        loop {
            match self.socket.recv(&mut buf) {
                Ok(n) => {
                    // SAFETY: recv() wrote n bytes into buf, so buf[..n] is initialized.
                    // MaybeUninit<u8> has the same layout as u8.
                    let data: &[u8] =
                        unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), n) };
                    // On RAW sockets for IPv4, the kernel prepends the IP header
                    let icmp_data = strip_ip_header(&self.addr, data);
                    if is_echo_reply(&self.addr, icmp_data, self.id, self.seq) {
                        return Ok(ProbeResult::Reply);
                    }
                    // Not our reply — could be another ICMP message, keep waiting
                }
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    return Ok(ProbeResult::Timeout);
                }
                Err(e) if is_msg_size_error(&e) => return Ok(ProbeResult::TooLarge),
                Err(e) => return Err(e).context("failed to receive ICMP reply"),
            }
        }
    }
}

/// Try SOCK_DGRAM (unprivileged) first, then SOCK_RAW (privileged).
fn try_create_socket(domain: Domain, protocol: Protocol) -> Result<Socket> {
    // Try unprivileged ICMP socket first (Linux, macOS)
    if let Ok(s) = Socket::new(domain, Type::DGRAM, Some(protocol)) {
        return Ok(s);
    }

    // Fall back to raw socket (needs root/admin or CAP_NET_RAW)
    if let Ok(s) = Socket::new(domain, Type::RAW, Some(protocol)) {
        return Ok(s);
    }

    // Both failed — build a helpful error message
    Err(permission_error())
}

// =============================================================================
// Platform-specific: Don't Fragment bit
// =============================================================================

/// Helper for Unix platforms: call setsockopt with an integer value.
#[cfg(unix)]
fn setsockopt_int(
    socket: &Socket,
    level: libc::c_int,
    optname: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    unsafe {
        let rc = libc::setsockopt(
            socket.as_raw_fd(),
            level,
            optname,
            &value as *const _ as *const libc::c_void,
            std::mem::size_of_val(&value) as libc::socklen_t,
        );
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Linux: use IP_MTU_DISCOVER with IP_PMTUDISC_DO.
#[cfg(target_os = "linux")]
fn set_df_bit(socket: &Socket, addr: &IpAddr) -> Result<()> {
    use libc::{
        IP_MTU_DISCOVER, IP_PMTUDISC_DO, IPPROTO_IP, IPPROTO_IPV6, IPV6_MTU_DISCOVER,
        IPV6_PMTUDISC_DO,
    };

    let (level, optname, value) = match addr {
        IpAddr::V4(_) => (IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO),
        IpAddr::V6(_) => (IPPROTO_IPV6, IPV6_MTU_DISCOVER, IPV6_PMTUDISC_DO),
    };

    setsockopt_int(socket, level, optname, value).context("failed to set DF bit (IP_MTU_DISCOVER)")
}

/// macOS: use IP_DONTFRAG / IPV6_DONTFRAG.
#[cfg(target_os = "macos")]
fn set_df_bit(socket: &Socket, addr: &IpAddr) -> Result<()> {
    // darwin-xnu: bsd/netinet/in.h, bsd/netinet6/in6.h
    const IP_DONTFRAG: libc::c_int = 28;
    const IPV6_DONTFRAG: libc::c_int = 62;

    let (level, optname) = match addr {
        IpAddr::V4(_) => (libc::IPPROTO_IP, IP_DONTFRAG),
        IpAddr::V6(_) => (libc::IPPROTO_IPV6, IPV6_DONTFRAG),
    };

    setsockopt_int(socket, level, optname, 1).context("failed to set DF bit (IP_DONTFRAG)")
}

/// Illumos: use IP_DONTFRAG / IPV6_DONTFRAG.
#[cfg(target_os = "illumos")]
fn set_df_bit(socket: &Socket, addr: &IpAddr) -> Result<()> {
    // illumos-gate: usr/src/uts/common/netinet/in.h
    const IP_DONTFRAG: libc::c_int = 27;
    const IPV6_DONTFRAG: libc::c_int = 33;

    let (level, optname) = match addr {
        IpAddr::V4(_) => (libc::IPPROTO_IP, IP_DONTFRAG),
        IpAddr::V6(_) => (libc::IPPROTO_IPV6, IPV6_DONTFRAG),
    };

    setsockopt_int(socket, level, optname, 1).context("failed to set DF bit (IP_DONTFRAG)")
}

/// Windows: use IP_DONTFRAGMENT / IPV6_DONTFRAG via Winsock2.
#[cfg(windows)]
fn set_df_bit(socket: &Socket, addr: &IpAddr) -> Result<()> {
    use std::os::windows::io::AsRawSocket;

    const IPPROTO_IP: i32 = 0;
    const IPPROTO_IPV6: i32 = 41;
    const IP_DONTFRAGMENT: i32 = 14;
    const IPV6_DONTFRAG: i32 = 14;

    #[link(name = "ws2_32")]
    unsafe extern "system" {
        fn setsockopt(
            s: usize,
            level: i32,
            optname: i32,
            optval: *const core::ffi::c_char,
            optlen: i32,
        ) -> i32;
    }

    let (level, optname) = match addr {
        IpAddr::V4(_) => (IPPROTO_IP, IP_DONTFRAGMENT),
        IpAddr::V6(_) => (IPPROTO_IPV6, IPV6_DONTFRAG),
    };

    let value: i32 = 1;
    unsafe {
        let rc = setsockopt(
            socket.as_raw_socket() as usize,
            level,
            optname,
            &value as *const i32 as *const core::ffi::c_char,
            std::mem::size_of::<i32>() as i32,
        );
        if rc != 0 {
            return Err(io::Error::last_os_error())
                .context("failed to set DF bit (IP_DONTFRAGMENT)");
        }
    }
    Ok(())
}

/// Fallback for unsupported platforms.
#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "illumos",
    windows
)))]
fn set_df_bit(_socket: &Socket, _addr: &IpAddr) -> Result<()> {
    anyhow::bail!(
        "Setting the Don't Fragment bit is not supported on this platform.\n\
         mtuspy supports Linux, macOS, Windows, and Illumos."
    )
}

// =============================================================================
// Platform-specific: message size error detection
// =============================================================================

#[cfg(unix)]
const MSG_SIZE_ERROR: i32 = libc::EMSGSIZE;

#[cfg(windows)]
const MSG_SIZE_ERROR: i32 = 10040; // WSAEMSGSIZE

/// Check if an error is EMSGSIZE (message too large).
fn is_msg_size_error(e: &io::Error) -> bool {
    e.raw_os_error() == Some(MSG_SIZE_ERROR)
}

// =============================================================================
// IP header stripping (all platforms)
// =============================================================================

/// On RAW IPv4 sockets, recv() returns the IP header + ICMP data.
/// On DGRAM sockets, it returns just the ICMP data.
/// On IPv6 RAW sockets, the kernel strips the IPv6 header.
fn strip_ip_header<'a>(addr: &IpAddr, data: &'a [u8]) -> &'a [u8] {
    match addr {
        IpAddr::V4(_) => {
            // Check if data starts with an IP header (version 4)
            if data.len() > 20 && (data[0] >> 4) == 4 {
                let ihl = (data[0] & 0x0F) as usize * 4;
                if data.len() > ihl {
                    return &data[ihl..];
                }
            }
            data
        }
        IpAddr::V6(_) => data, // kernel strips IPv6 header
    }
}

// =============================================================================
// Platform-specific: permission error messages
// =============================================================================

#[cfg(target_os = "linux")]
fn permission_error() -> anyhow::Error {
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "mtuspy".into());

    let mut msg = String::from(
        "Cannot create ICMP socket — insufficient permissions.\n\n\
         Fix with any of the following:\n",
    );

    // Option 1: sudo (always works)
    msg.push_str(&format!("\n  1. Run with sudo:\n     sudo {exe} <host>\n"));

    // Option 2: setuid root (always works on any filesystem)
    msg.push_str(&format!(
        "\n  2. Set the binary setuid root (works on any filesystem):\n\
         \x20    sudo chown root:root {exe}\n\
         \x20    sudo chmod u+s {exe}\n"
    ));

    // Option 3: setcap (depends on filesystem)
    if std::path::Path::new("/usr/sbin/setcap").exists()
        || std::path::Path::new("/sbin/setcap").exists()
    {
        msg.push_str(&format!(
            "\n  3. Grant ICMP capability (needs filesystem with xattr support):\n\
             \x20    sudo setcap cap_net_raw+ep {exe}\n"
        ));
    }

    // Option 4: sysctl (Linux-specific)
    if let Ok(range) = std::fs::read_to_string("/proc/sys/net/ipv4/ping_group_range") {
        msg.push_str(&format!(
            "\n  4. Allow unprivileged ICMP for all users (system-wide):\n\
             \x20    sudo sysctl net.ipv4.ping_group_range=\"0 2147483647\"\n\
             \x20    Current setting: {}\n",
            range.trim()
        ));
    }

    anyhow::anyhow!("{msg}")
}

#[cfg(target_os = "macos")]
fn permission_error() -> anyhow::Error {
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "mtuspy".into());

    anyhow::anyhow!(
        "Cannot create ICMP socket — insufficient permissions.\n\n\
         Fix with any of the following:\n\
         \n  1. Run with sudo:\n\
         \x20    sudo {exe} <host>\n\
         \n  2. Set the binary setuid root:\n\
         \x20    sudo chown root:wheel {exe}\n\
         \x20    sudo chmod u+s {exe}\n"
    )
}

#[cfg(target_os = "illumos")]
fn permission_error() -> anyhow::Error {
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "mtuspy".into());

    let user = std::env::var("USER").unwrap_or_else(|_| "<user>".into());

    anyhow::anyhow!(
        "Cannot create ICMP socket — insufficient permissions.\n\n\
         Fix with any of the following:\n\
         \n  1. Run with sudo:\n\
         \x20    sudo {exe} <host>\n\
         \n  2. Grant ICMP access via RBAC (requires re-login):\n\
         \x20    sudo usermod -K defaultpriv=basic,net_icmpaccess {user}\n\
         \n  3. Set the binary setuid root:\n\
         \x20    sudo chown root:root {exe}\n\
         \x20    sudo chmod u+s {exe}\n"
    )
}

#[cfg(windows)]
fn permission_error() -> anyhow::Error {
    anyhow::anyhow!(
        "Cannot create ICMP socket — insufficient permissions.\n\n\
         Fix: Run from an elevated command prompt (Run as Administrator).\n\
         \n  Right-click on Command Prompt or PowerShell and select\n\
         \x20 \"Run as administrator\", then run mtuspy again.\n"
    )
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "illumos",
    windows
)))]
fn permission_error() -> anyhow::Error {
    anyhow::anyhow!(
        "Cannot create ICMP socket — insufficient permissions.\n\n\
         Try running with elevated privileges (e.g. sudo).\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_zeros() {
        let data = vec![0u8; 8];
        assert_eq!(checksum(&data), 0xFFFF);
    }

    #[test]
    fn checksum_known_value() {
        // ICMP echo request: type=8, code=0, id=0x0001, seq=0x0001, no payload
        let mut pkt = vec![0u8; 8];
        pkt[0] = 8; // type
        pkt[4] = 0;
        pkt[5] = 1; // id
        pkt[6] = 0;
        pkt[7] = 1; // seq
        let cksum = checksum(&pkt);
        // Verify: recompute with checksum field set should give 0
        pkt[2..4].copy_from_slice(&cksum.to_be_bytes());
        assert_eq!(checksum(&pkt), 0);
    }

    #[test]
    fn echo_request_packet_structure() {
        let addr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let pkt = build_echo_request(&addr, 0x1234, 0x0001, 4);
        assert_eq!(pkt.len(), 12); // 8 header + 4 payload
        assert_eq!(pkt[0], 8); // type = echo request
        assert_eq!(pkt[1], 0); // code = 0
        assert_eq!(&pkt[4..6], &0x1234u16.to_be_bytes());
        assert_eq!(&pkt[6..8], &0x0001u16.to_be_bytes());
        // Verify checksum
        assert_eq!(checksum(&pkt), 0);
    }

    #[test]
    fn echo_reply_detection() {
        let addr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let mut reply = vec![0u8; 8];
        reply[0] = 0; // type = echo reply
        reply[4..6].copy_from_slice(&42u16.to_be_bytes());
        reply[6..8].copy_from_slice(&7u16.to_be_bytes());
        assert!(is_echo_reply(&addr, &reply, 42, 7));
        assert!(!is_echo_reply(&addr, &reply, 99, 7));
        assert!(!is_echo_reply(&addr, &reply, 42, 8)); // wrong seq
    }
}
