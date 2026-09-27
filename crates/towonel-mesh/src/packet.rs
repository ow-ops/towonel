//! Just enough IP parsing for routing, anti-spoofing and connection
//! tracking, plus the ICMP message that makes TCP shrink oversized packets.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_ICMPV6: u8 = 58;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketInfo {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: u8,
    /// TCP/UDP ports, or the ICMP echo identifier in both; 0 otherwise.
    pub src_port: u16,
    pub dst_port: u16,
}

#[must_use]
pub fn parse(packet: &[u8]) -> Option<PacketInfo> {
    match packet.first()? >> 4 {
        4 => parse_v4(packet),
        6 => parse_v6(packet),
        _ => None,
    }
}

fn parse_v4(p: &[u8]) -> Option<PacketInfo> {
    let header_len = usize::from(p.first()? & 0x0f) * 4;
    if header_len < 20 || p.len() < header_len {
        return None;
    }
    let src = Ipv4Addr::from(<[u8; 4]>::try_from(p.get(12..16)?).ok()?);
    let dst = Ipv4Addr::from(<[u8; 4]>::try_from(p.get(16..20)?).ok()?);
    let proto = *p.get(9)?;
    // Only the first fragment carries the transport header.
    let fragment_offset = u16::from_be_bytes([*p.get(6)?, *p.get(7)?]) & 0x1fff;
    let (src_port, dst_port) = if fragment_offset == 0 {
        ports(proto, p.get(header_len..)?)
    } else {
        (0, 0)
    };
    Some(PacketInfo {
        src: src.into(),
        dst: dst.into(),
        proto,
        src_port,
        dst_port,
    })
}

fn parse_v6(p: &[u8]) -> Option<PacketInfo> {
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(p.get(8..24)?).ok()?);
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(p.get(24..40)?).ok()?);
    // Extension headers aren't walked: those flows track without ports.
    let proto = *p.get(6)?;
    let (src_port, dst_port) = ports(proto, p.get(40..)?);
    Some(PacketInfo {
        src: src.into(),
        dst: dst.into(),
        proto,
        src_port,
        dst_port,
    })
}

fn ports(proto: u8, l4: &[u8]) -> (u16, u16) {
    let be = |i: usize| {
        l4.get(i..i + 2)
            .and_then(|b| <[u8; 2]>::try_from(b).ok())
            .map(u16::from_be_bytes)
    };
    match proto {
        PROTO_TCP | PROTO_UDP => (be(0).unwrap_or(0), be(2).unwrap_or(0)),
        PROTO_ICMP | PROTO_ICMPV6 => {
            let id = be(4).unwrap_or(0);
            (id, id)
        }
        _ => (0, 0),
    }
}

/// `ICMPv4` "fragmentation needed" for `original`, to hand back to the host so
/// its TCP lowers the segment size to fit `mtu`.
#[must_use]
pub fn icmpv4_frag_needed(original: &[u8], mtu: u16) -> Option<Vec<u8>> {
    let [hi, lo] = mtu.to_be_bytes();
    icmpv4_error(original, 4, [0, 0, hi, lo])
}

/// "Port unreachable" for `original`, so the sender's connect fails at once
/// instead of timing out. `None` for ICMP, which never gets an error back.
#[must_use]
pub fn port_unreachable(original: &[u8]) -> Option<Vec<u8>> {
    match parse(original)?.proto {
        PROTO_ICMP | PROTO_ICMPV6 => None,
        _ if original.first()? >> 4 == 4 => icmpv4_error(original, 3, [0; 4]),
        _ => icmpv6_port_unreachable(original),
    }
}

/// The packet an ICMP error quotes, so it can be matched to the flow it's
/// about.
#[must_use]
pub fn icmp_error_quote(packet: &[u8]) -> Option<PacketInfo> {
    let info = parse(packet)?;
    let body = match (packet.first()? >> 4, info.proto) {
        (4, PROTO_ICMP) => {
            let header_len = usize::from(packet.first()? & 0x0f) * 4;
            // Destination unreachable, time exceeded.
            matches!(packet.get(header_len)?, 3 | 11).then_some(header_len + 8)?
        }
        (6, PROTO_ICMPV6) => matches!(packet.get(40)?, 1..=4).then_some(48)?,
        _ => return None,
    };
    parse(packet.get(body..)?)
}

/// Destination-unreachable (type 3) with `code`, sent "from" the original
/// destination back to its sender.
fn icmpv4_error(original: &[u8], code: u8, rest: [u8; 4]) -> Option<Vec<u8>> {
    let info = parse(original)?;
    let (IpAddr::V4(src), IpAddr::V4(dst)) = (info.src, info.dst) else {
        return None;
    };
    let header_len = usize::from(original.first()? & 0x0f) * 4;
    let quoted = original.get(..(header_len + 8).min(original.len()))?;

    let mut icmp = vec![3, code, 0, 0];
    icmp.extend_from_slice(&rest);
    icmp.extend_from_slice(quoted);
    let sum = checksum(&icmp).to_be_bytes();
    icmp.get_mut(2..4)?.copy_from_slice(&sum);

    let total = u16::try_from(20 + icmp.len()).ok()?.to_be_bytes();
    let mut ip = vec![
        0x45, 0, total[0], total[1], 0, 0, 0x40, 0, 64, PROTO_ICMP, 0, 0,
    ];
    ip.extend_from_slice(&dst.octets());
    ip.extend_from_slice(&src.octets());
    let sum = checksum(&ip).to_be_bytes();
    ip.get_mut(10..12)?.copy_from_slice(&sum);
    ip.extend_from_slice(&icmp);
    Some(ip)
}

fn icmpv6_port_unreachable(original: &[u8]) -> Option<Vec<u8>> {
    let info = parse(original)?;
    let (IpAddr::V6(src), IpAddr::V6(dst)) = (info.src, info.dst) else {
        return None;
    };
    // The reply must fit the IPv6 minimum MTU.
    let quoted = original.get(..original.len().min(1280 - 40 - 8))?;
    let mut icmp = vec![1, 4, 0, 0, 0, 0, 0, 0];
    icmp.extend_from_slice(quoted);
    let len = u32::try_from(icmp.len()).ok()?;

    let mut pseudo = Vec::with_capacity(40 + icmp.len());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&len.to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, PROTO_ICMPV6]);
    pseudo.extend_from_slice(&icmp);
    let sum = checksum(&pseudo).to_be_bytes();
    icmp.get_mut(2..4)?.copy_from_slice(&sum);

    let payload = u16::try_from(icmp.len()).ok()?.to_be_bytes();
    let mut ip = vec![0x60, 0, 0, 0, payload[0], payload[1], PROTO_ICMPV6, 64];
    ip.extend_from_slice(&dst.octets());
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&icmp);
    Some(ip)
}

pub(crate) fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = data
        .chunks(2)
        .map(|c| {
            let hi = c.first().copied().unwrap_or(0);
            let lo = c.get(1).copied().unwrap_or(0);
            u32::from(u16::from_be_bytes([hi, lo]))
        })
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    #[expect(clippy::cast_possible_truncation, reason = "folded to 16 bits above")]
    let folded = sum as u16;
    !folded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_unreachable_answers_tcp_and_udp_but_not_icmp() {
        let syn = ipv4_tcp([100, 64, 0, 1], [100, 64, 0, 2], 40000, 5432, 0);
        let icmp = port_unreachable(&syn).unwrap();
        let info = parse(&icmp).unwrap();
        assert_eq!(
            (info.src, info.dst),
            (IpAddr::from([100, 64, 0, 2]), IpAddr::from([100, 64, 0, 1]))
        );
        assert_eq!((icmp[9], icmp[20], icmp[21]), (PROTO_ICMP, 3, 3));
        assert_eq!(checksum(&icmp[..20]), 0);
        assert_eq!(checksum(&icmp[20..]), 0);
        assert!(port_unreachable(&icmp).is_none(), "no error about an error");
        let quoted = icmp_error_quote(&icmp).unwrap();
        assert_eq!((quoted.src_port, quoted.dst_port), (40000, 5432));
        assert!(icmp_error_quote(&syn).is_none());

        let (a, b): (Ipv6Addr, Ipv6Addr) = ("fd00::1".parse().unwrap(), "fd00::2".parse().unwrap());
        let reply = port_unreachable(&ipv6_udp(a, b, 40000, 53)).unwrap();
        let info = parse(&reply).unwrap();
        assert_eq!(
            (info.src, info.dst, info.proto),
            (b.into(), a.into(), PROTO_ICMPV6)
        );
        assert_eq!((reply[40], reply[41]), (1, 4));
        assert_eq!(icmp_error_quote(&reply).unwrap().dst_port, 53);
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&b.octets());
        pseudo.extend_from_slice(&a.octets());
        pseudo.extend_from_slice(&u32::try_from(reply.len() - 40).unwrap().to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, PROTO_ICMPV6]);
        pseudo.extend_from_slice(&reply[40..]);
        assert_eq!(checksum(&pseudo), 0);
    }

    fn ipv4_tcp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: usize) -> Vec<u8> {
        let total = u16::try_from(40 + payload).unwrap().to_be_bytes();
        let mut p = vec![
            0x45, 0, total[0], total[1], 0, 0, 0x40, 0, 64, PROTO_TCP, 0, 0,
        ];
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p.extend_from_slice(&sport.to_be_bytes());
        p.extend_from_slice(&dport.to_be_bytes());
        p.extend_from_slice(&[0; 16]);
        p.resize(40 + payload, 0xaa);
        p
    }

    fn ipv6_udp(src: Ipv6Addr, dst: Ipv6Addr, sport: u16, dport: u16) -> Vec<u8> {
        let mut p = vec![0x60, 0, 0, 0, 0, 8, PROTO_UDP, 64];
        p.extend_from_slice(&src.octets());
        p.extend_from_slice(&dst.octets());
        p.extend_from_slice(&sport.to_be_bytes());
        p.extend_from_slice(&dport.to_be_bytes());
        p.extend_from_slice(&[0, 8, 0, 0]);
        p
    }

    #[test]
    fn parses_ipv4_tcp() {
        let info = parse(&ipv4_tcp([100, 64, 0, 1], [100, 64, 0, 2], 40000, 22, 0)).unwrap();
        assert_eq!(info.src, IpAddr::from([100, 64, 0, 1]));
        assert_eq!(info.dst, IpAddr::from([100, 64, 0, 2]));
        assert_eq!(
            (info.proto, info.src_port, info.dst_port),
            (PROTO_TCP, 40000, 22)
        );
    }

    #[test]
    fn parses_ipv6_udp() {
        let a: Ipv6Addr = "fd00::1".parse().unwrap();
        let b: Ipv6Addr = "fd00::2".parse().unwrap();
        let info = parse(&ipv6_udp(a, b, 5353, 53)).unwrap();
        assert_eq!((info.src, info.dst), (a.into(), b.into()));
        assert_eq!(
            (info.proto, info.src_port, info.dst_port),
            (PROTO_UDP, 5353, 53)
        );
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse(&[]).is_none());
        assert!(parse(&[0x45, 0, 0]).is_none());
        assert!(parse(&[0x20; 40]).is_none());
        assert!(parse(&[0x60; 20]).is_none());
    }

    /// Peers and the host control these bytes: nothing may panic on them.
    #[test]
    fn arbitrary_bytes_never_panic() {
        let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..20_000 {
            let len = usize::try_from(next() % 80).unwrap();
            let mut bytes: Vec<u8> = (0..len).map(|_| next().to_le_bytes()[0]).collect();
            // Bias towards plausible IPv4/IPv6 headers so the deep paths run.
            if let Some(first) = bytes.first_mut() {
                *first = match next() % 3 {
                    0 => 0x45,
                    1 => 0x60,
                    _ => *first,
                };
            }
            assert!(parse(&bytes).is_none_or(|p| p.src.is_ipv4() == p.dst.is_ipv4()));
            drop(icmpv4_frag_needed(&bytes, 1200));
        }
    }

    #[test]
    fn frag_needed_is_well_formed() {
        let original = ipv4_tcp([100, 64, 0, 1], [100, 64, 0, 2], 40000, 22, 1300);
        let icmp = icmpv4_frag_needed(&original, 1200).unwrap();
        let info = parse(&icmp).unwrap();
        assert_eq!(info.proto, PROTO_ICMP);
        assert_eq!(info.src, IpAddr::from([100, 64, 0, 2]));
        assert_eq!(info.dst, IpAddr::from([100, 64, 0, 1]));
        // Valid checksums sum to zero.
        assert_eq!(checksum(&icmp[..20]), 0);
        assert_eq!(checksum(&icmp[20..]), 0);
        assert_eq!(&icmp[20..22], &[3, 4]);
        assert_eq!(u16::from_be_bytes([icmp[26], icmp[27]]), 1200);
        assert_eq!(&icmp[28..48], &original[..20]);
    }
}
