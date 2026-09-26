//! Resolver for mesh names, answered inside the node: queries to
//! [`RESOLVER`] arrive as packets on the TUN and never reach a socket.
//!
//! The OS only sends the mesh domain here (split DNS), so anything else is
//! refused rather than forwarded.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::packet::{self, PROTO_UDP};

/// Inside `100.64.0.0/10`, so the TUN route already covers it.
pub const RESOLVER: Ipv4Addr = Ipv4Addr::new(100, 100, 100, 100);
const TTL_SECS: u32 = 60;
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;
const RCODE_NXDOMAIN: u16 = 3;
const RCODE_REFUSED: u16 = 5;
const RCODE_FORMERR: u16 = 1;

#[must_use]
pub fn is_query(info: &packet::PacketInfo) -> bool {
    info.dst == RESOLVER && info.proto == PROTO_UDP && info.dst_port == 53
}

/// The reply to a DNS query packet addressed to [`RESOLVER`], or `None` if
/// it isn't one. `lookup` maps a device name to its overlay addresses.
#[must_use]
pub fn answer(
    packet: &[u8],
    domain: &str,
    lookup: impl Fn(&str) -> Option<(Ipv4Addr, Ipv6Addr)>,
) -> Option<Vec<u8>> {
    let info = packet::parse(packet)?;
    let std::net::IpAddr::V4(client) = info.src else {
        return None;
    };
    if !is_query(&info) {
        return None;
    }
    let header_len = usize::from(packet.first()? & 0x0f) * 4;
    let query = packet.get(header_len + 8..)?;
    let reply = reply(query, domain, lookup)?;
    Some(udp_packet(client, info.src_port, &reply))
}

fn reply(
    query: &[u8],
    domain: &str,
    lookup: impl Fn(&str) -> Option<(Ipv4Addr, Ipv6Addr)>,
) -> Option<Vec<u8>> {
    let header: [u8; 12] = query.get(..12)?.try_into().ok()?;
    let flags = u16::from_be_bytes([header[2], header[3]]);
    if flags & 0x8000 != 0 {
        return None;
    }
    let questions = u16::from_be_bytes([header[4], header[5]]);
    let parsed = (questions == 1)
        .then(|| question(query.get(12..)?))
        .flatten();
    let Some((name, qtype, qclass, question_len)) = parsed else {
        return Some(header_only(&header, flags, RCODE_FORMERR));
    };

    let mut out = header.to_vec();
    let question = query.get(12..12 + question_len)?;
    let (rcode, record) = match resolve(&name, domain, &lookup) {
        Resolved::Refused => (RCODE_REFUSED, None),
        Resolved::NxDomain => (RCODE_NXDOMAIN, None),
        Resolved::Found(v4, v6) => {
            let record = match (qtype, qclass) {
                (TYPE_A, CLASS_IN) => Some((TYPE_A, v4.octets().to_vec())),
                (TYPE_AAAA, CLASS_IN) => Some((TYPE_AAAA, v6.octets().to_vec())),
                // The name exists, just not with this type: empty NOERROR.
                _ => None,
            };
            (0, record)
        }
    };
    // QR, opcode and RD from the query, AA set, RA clear.
    let flags = 0x8000 | (flags & 0x7900) | 0x0400 | rcode;
    out.get_mut(2..4)?.copy_from_slice(&flags.to_be_bytes());
    let answers = u16::from(record.is_some());
    out.get_mut(4..12)?
        .copy_from_slice(&[0, 1, 0, u8::try_from(answers).ok()?, 0, 0, 0, 0]);
    out.extend_from_slice(question);
    if let Some((rtype, data)) = record {
        // Name as a pointer to the question at offset 12.
        out.extend_from_slice(&[0xc0, 0x0c]);
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&TTL_SECS.to_be_bytes());
        out.extend_from_slice(&u16::try_from(data.len()).ok()?.to_be_bytes());
        out.extend_from_slice(&data);
    }
    Some(out)
}

enum Resolved {
    Found(Ipv4Addr, Ipv6Addr),
    NxDomain,
    Refused,
}

fn resolve(
    name: &str,
    domain: &str,
    lookup: &impl Fn(&str) -> Option<(Ipv4Addr, Ipv6Addr)>,
) -> Resolved {
    let device = if name.contains('.') {
        match name.strip_suffix(domain).and_then(|n| n.strip_suffix('.')) {
            Some(device) if !device.contains('.') => device,
            _ if name == domain || name.ends_with(&format!(".{domain}")) => {
                return Resolved::NxDomain;
            }
            _ => return Resolved::Refused,
        }
    } else {
        name
    };
    lookup(device).map_or(Resolved::NxDomain, |(v4, v6)| Resolved::Found(v4, v6))
}

/// `(lowercased name, qtype, qclass, bytes consumed)`.
fn question(bytes: &[u8]) -> Option<(String, u16, u16, usize)> {
    let mut name = String::new();
    let mut pos = 0;
    loop {
        let len = usize::from(*bytes.get(pos)?);
        pos += 1;
        if len == 0 {
            break;
        }
        // Compression pointers never appear in a query's question.
        if len > 63 || name.len() + len > 253 {
            return None;
        }
        let label = std::str::from_utf8(bytes.get(pos..pos + len)?).ok()?;
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&label.to_ascii_lowercase());
        pos += len;
    }
    let qtype = u16::from_be_bytes(bytes.get(pos..pos + 2)?.try_into().ok()?);
    let qclass = u16::from_be_bytes(bytes.get(pos + 2..pos + 4)?.try_into().ok()?);
    Some((name, qtype, qclass, pos + 4))
}

fn header_only(header: &[u8], flags: u16, rcode: u16) -> Vec<u8> {
    let mut out = header.to_vec();
    let flags = 0x8000 | (flags & 0x7900) | rcode;
    if let Some(f) = out.get_mut(2..4) {
        f.copy_from_slice(&flags.to_be_bytes());
    }
    if let Some(counts) = out.get_mut(4..12) {
        counts.fill(0);
    }
    out
}

/// IPv4/UDP from the resolver to the client; the UDP checksum is optional
/// over IPv4 and left at zero.
fn udp_packet(client: Ipv4Addr, client_port: u16, payload: &[u8]) -> Vec<u8> {
    let udp_len = u16::try_from(8 + payload.len()).unwrap_or(u16::MAX);
    let total = udp_len.saturating_add(20).to_be_bytes();
    let mut p = vec![
        0x45, 0, total[0], total[1], 0, 0, 0x40, 0, 64, PROTO_UDP, 0, 0,
    ];
    p.extend_from_slice(&RESOLVER.octets());
    p.extend_from_slice(&client.octets());
    let sum = packet::checksum(&p).to_be_bytes();
    if let Some(c) = p.get_mut(10..12) {
        c.copy_from_slice(&sum);
    }
    p.extend_from_slice(&53u16.to_be_bytes());
    p.extend_from_slice(&client_port.to_be_bytes());
    p.extend_from_slice(&udp_len.to_be_bytes());
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(payload);
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOMAIN: &str = "towonel.internal";
    const CLIENT: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 2);

    fn lookup(name: &str) -> Option<(Ipv4Addr, Ipv6Addr)> {
        (name == "nas").then(|| (Ipv4Addr::new(100, 64, 0, 1), "fd00::1".parse().unwrap()))
    }

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut dns = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            dns.push(u8::try_from(label.len()).unwrap());
            dns.extend_from_slice(label.as_bytes());
        }
        dns.push(0);
        dns.extend_from_slice(&qtype.to_be_bytes());
        dns.extend_from_slice(&CLASS_IN.to_be_bytes());
        let udp_len = u16::try_from(8 + dns.len()).unwrap();
        let total = (udp_len + 20).to_be_bytes();
        let mut p = vec![
            0x45, 0, total[0], total[1], 0, 0, 0x40, 0, 64, PROTO_UDP, 0, 0,
        ];
        p.extend_from_slice(&CLIENT.octets());
        p.extend_from_slice(&RESOLVER.octets());
        p.extend_from_slice(&40000u16.to_be_bytes());
        p.extend_from_slice(&53u16.to_be_bytes());
        p.extend_from_slice(&udp_len.to_be_bytes());
        p.extend_from_slice(&[0, 0]);
        p.extend_from_slice(&dns);
        p
    }

    /// `(rcode, answer rdata)` of a reply packet.
    fn decode(reply: &[u8]) -> (u16, Option<Vec<u8>>) {
        let info = packet::parse(reply).unwrap();
        assert_eq!(info.src, RESOLVER);
        assert_eq!(info.dst, CLIENT);
        assert_eq!((info.src_port, info.dst_port), (53, 40000));
        assert_eq!(packet::checksum(&reply[..20]), 0);
        let dns = &reply[28..];
        assert_eq!(&dns[..2], &[0x12, 0x34], "id echoed");
        let flags = u16::from_be_bytes([dns[2], dns[3]]);
        assert_ne!(flags & 0x8000, 0, "QR set");
        let answers = u16::from_be_bytes([dns[6], dns[7]]);
        let rdata = (answers == 1).then(|| {
            let (_, _, _, question_len) = question(&dns[12..]).unwrap();
            // Answer: pointer (2), type (2), class (2), ttl (4), rdlength (2), rdata.
            let rr = &dns[12 + question_len..];
            let rdlen = usize::from(u16::from_be_bytes([rr[10], rr[11]]));
            rr[12..12 + rdlen].to_vec()
        });
        (flags & 0x000f, rdata)
    }

    #[test]
    fn answers_a_and_aaaa_for_short_and_full_names() {
        for name in ["nas", "nas.towonel.internal", "NAS.Towonel.Internal"] {
            let (rcode, data) = decode(&answer(&query(name, TYPE_A), DOMAIN, lookup).unwrap());
            assert_eq!(rcode, 0, "{name}");
            assert_eq!(data, Some(vec![100, 64, 0, 1]), "{name}");
        }
        let (rcode, data) = decode(&answer(&query("nas", TYPE_AAAA), DOMAIN, lookup).unwrap());
        assert_eq!(rcode, 0);
        let v6: Ipv6Addr = "fd00::1".parse().unwrap();
        assert_eq!(data, Some(v6.octets().to_vec()));
    }

    #[test]
    fn unknown_names_and_types() {
        let (rcode, data) =
            decode(&answer(&query("ghost.towonel.internal", TYPE_A), DOMAIN, lookup).unwrap());
        assert_eq!((rcode, data), (RCODE_NXDOMAIN, None));
        let (rcode, _) =
            decode(&answer(&query("a.b.towonel.internal", TYPE_A), DOMAIN, lookup).unwrap());
        assert_eq!(rcode, RCODE_NXDOMAIN);
        let (rcode, _) = decode(&answer(&query("example.com", TYPE_A), DOMAIN, lookup).unwrap());
        assert_eq!(rcode, RCODE_REFUSED);
        // MX for an existing name: NOERROR, no answer.
        let (rcode, data) = decode(&answer(&query("nas", 15), DOMAIN, lookup).unwrap());
        assert_eq!((rcode, data), (0, None));
    }

    #[test]
    fn ignores_non_queries_and_survives_garbage() {
        let mut not_dns = query("nas", TYPE_A);
        not_dns[23] = 54; // destination port 54
        assert!(answer(&not_dns, DOMAIN, lookup).is_none());

        let mut truncated = query("nas", TYPE_A);
        // Header intact, question cut short.
        truncated.truncate(44);
        let reply = answer(&truncated, DOMAIN, lookup).unwrap();
        assert_eq!(decode(&reply).0, RCODE_FORMERR);

        for cut in 0..query("nas.towonel.internal", TYPE_A).len() {
            let mut q = query("nas.towonel.internal", TYPE_A);
            q.truncate(cut);
            drop(answer(&q, DOMAIN, lookup));
        }
    }
}
