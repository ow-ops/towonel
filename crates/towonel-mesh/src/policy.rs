//! Tenant access policy: who may open connections to whom.
//!
//! Evaluated by the receiving device on the first packet of a flow; replies
//! to flows a device started always pass. The hub validates a policy (and
//! runs its tests) before storing it.

use anyhow::{Context, bail, ensure};
use serde::{Deserialize, Serialize};
use towonel_common::mesh::MeshCred;

use crate::packet::{PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP};

const MAX_RULES: usize = 256;
const MAX_TESTS: usize = 256;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default)]
    pub rules: Vec<Rule>,
    /// Checked on save against the tenant's devices; a failing test rejects
    /// the policy.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tests: Vec<PolicyTest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub from: Vec<String>,
    pub to: Vec<String>,
    /// `"22"`, `"8000-8999"` or `"*"`. Ignored for ICMP.
    #[serde(default = "any_port")]
    pub ports: Vec<String>,
    /// `tcp`, `udp`, `icmp` or `any`.
    #[serde(default = "any_proto")]
    pub proto: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyTest {
    /// Device names; `to` may also be `internet`.
    pub from: String,
    pub to: String,
    #[serde(default = "tcp")]
    pub proto: String,
    #[serde(default)]
    pub port: u16,
    pub allow: bool,
}

fn any_port() -> Vec<String> {
    vec!["*".into()]
}

fn any_proto() -> String {
    "any".into()
}

fn tcp() -> String {
    "tcp".into()
}

enum Selector<'a> {
    Any,
    Tag(&'a str),
    User(&'a str),
    /// Untagged devices enrolled without a user.
    Tenant,
    /// Only in `to`: devices owned by the sender's user.
    SameOwner,
    /// Only in `to`: public addresses reached through an exit node.
    Internet,
}

/// A device, or the internet via an exit node.
#[derive(Clone, Copy)]
enum Target<'a> {
    Device(&'a MeshCred),
    Internet,
}

fn selector(s: &str) -> anyhow::Result<Selector<'_>> {
    Ok(match s {
        "*" => Selector::Any,
        "tenant" => Selector::Tenant,
        "self" => Selector::SameOwner,
        "internet" => Selector::Internet,
        _ if s.starts_with("tag:") && s.len() > 4 => Selector::Tag(s),
        _ => match s.strip_prefix("user:") {
            Some(id) if !id.is_empty() => Selector::User(id),
            _ => bail!(
                "unknown selector {s:?}: expected *, tag:<name>, user:<id>, tenant, self or internet"
            ),
        },
    })
}

fn matches(sel: &Selector<'_>, device: &MeshCred, sender: &MeshCred) -> bool {
    match sel {
        Selector::Any => true,
        Selector::Tag(t) => device.tags.iter().any(|x| x == t),
        Selector::User(u) => device.owner.as_deref() == Some(*u),
        Selector::Tenant => device.owner.is_none() && device.tags.is_empty(),
        Selector::SameOwner => device.owner.is_some() && device.owner == sender.owner,
        Selector::Internet => false,
    }
}

fn parse_proto(s: &str) -> anyhow::Result<Option<u8>> {
    Ok(match s {
        "any" => None,
        "tcp" => Some(PROTO_TCP),
        "udp" => Some(PROTO_UDP),
        "icmp" => Some(PROTO_ICMP),
        _ => bail!("unknown proto {s:?}: expected tcp, udp, icmp or any"),
    })
}

fn parse_ports(s: &str) -> anyhow::Result<(u16, u16)> {
    if s == "*" {
        return Ok((0, u16::MAX));
    }
    let (lo, hi) = s.split_once('-').unwrap_or((s, s));
    let lo: u16 = lo.parse().with_context(|| format!("bad port {s:?}"))?;
    let hi: u16 = hi.parse().with_context(|| format!("bad port {s:?}"))?;
    ensure!(lo <= hi, "port range {s:?} is backwards");
    Ok((lo, hi))
}

impl Rule {
    fn allows(&self, src: &MeshCred, dst: Target<'_>, proto: u8, port: u16) -> bool {
        let proto_ok = match parse_proto(&self.proto) {
            Ok(None) => true,
            Ok(Some(PROTO_ICMP)) => proto == PROTO_ICMP || proto == PROTO_ICMPV6,
            Ok(Some(p)) => p == proto,
            Err(_) => false,
        };
        let is_icmp = proto == PROTO_ICMP || proto == PROTO_ICMPV6;
        let port_ok = is_icmp
            || self
                .ports
                .iter()
                .filter_map(|p| parse_ports(p).ok())
                .any(|(lo, hi)| (lo..=hi).contains(&port));
        let from_ok = self
            .from
            .iter()
            .filter_map(|s| selector(s).ok())
            .any(|s| !matches!(s, Selector::SameOwner) && matches(&s, src, src));
        let to_ok = self
            .to
            .iter()
            .filter_map(|s| selector(s).ok())
            .any(|s| match dst {
                Target::Device(d) => matches(&s, d, src),
                Target::Internet => matches!(s, Selector::Internet),
            });
        proto_ok && port_ok && from_ok && to_ok
    }
}

impl Policy {
    #[must_use]
    pub fn allows(&self, src: &MeshCred, dst: &MeshCred, proto: u8, port: u16) -> bool {
        self.rules
            .iter()
            .any(|r| r.allows(src, Target::Device(dst), proto, port))
    }

    #[must_use]
    pub fn allows_internet(&self, src: &MeshCred, proto: u8, port: u16) -> bool {
        self.rules
            .iter()
            .any(|r| r.allows(src, Target::Internet, proto, port))
    }

    /// Syntax only; [`Policy::run_tests`] checks behaviour.
    pub fn validate(&self) -> anyhow::Result<()> {
        ensure!(self.rules.len() <= MAX_RULES, "at most {MAX_RULES} rules");
        ensure!(self.tests.len() <= MAX_TESTS, "at most {MAX_TESTS} tests");
        for (i, rule) in self.rules.iter().enumerate() {
            let at = || format!("rule {}", i + 1);
            ensure!(
                !rule.from.is_empty() && !rule.to.is_empty(),
                "{}: from and to are required",
                at()
            );
            for s in &rule.from {
                match selector(s).with_context(at)? {
                    Selector::SameOwner | Selector::Internet => {
                        bail!("{}: {s:?} only makes sense in `to`", at());
                    }
                    _ => {}
                }
            }
            for s in &rule.to {
                selector(s).with_context(at)?;
            }
            for p in &rule.ports {
                parse_ports(p).with_context(at)?;
            }
            parse_proto(&rule.proto).with_context(at)?;
        }
        for test in &self.tests {
            parse_proto(&test.proto)
                .with_context(|| format!("test {} -> {}", test.from, test.to))?;
        }
        Ok(())
    }

    /// Run the embedded tests; `lookup` resolves a device name.
    pub fn run_tests(&self, lookup: impl Fn(&str) -> Option<MeshCred>) -> anyhow::Result<()> {
        for t in &self.tests {
            let name = format!("{} -> {}:{}/{}", t.from, t.to, t.port, t.proto);
            let src =
                lookup(&t.from).with_context(|| format!("test {name}: no device {:?}", t.from))?;
            let proto = parse_proto(&t.proto)?.unwrap_or(PROTO_TCP);
            let got = if t.to == "internet" {
                self.allows_internet(&src, proto, t.port)
            } else {
                let dst =
                    lookup(&t.to).with_context(|| format!("test {name}: no device {:?}", t.to))?;
                self.allows(&src, &dst, proto, t.port)
            };
            ensure!(
                got == t.allow,
                "test {name}: expected {}, the policy {}",
                if t.allow { "allow" } else { "deny" },
                if got { "allows it" } else { "denies it" }
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use towonel_common::mesh::MESH_CRED_VERSION;

    fn device(owner: Option<&str>, tags: &[&str]) -> MeshCred {
        MeshCred {
            version: MESH_CRED_VERSION,
            kid: 1,
            device_id: [1; 32],
            tenant_id: towonel_common::identity::TenantKeypair::generate().id(),
            ipv4: "100.64.0.1".parse().unwrap(),
            ipv6: "fd00::1".parse().unwrap(),
            tags: tags.iter().map(|t| (*t).to_string()).collect(),
            owner: owner.map(str::to_string),
            not_after_ms: u64::MAX,
        }
    }

    fn policy(json: &str) -> Policy {
        let p: Policy = serde_json::from_str(json).unwrap();
        p.validate().unwrap();
        p
    }

    #[test]
    fn rules_match_selectors_ports_and_proto() {
        let p = policy(
            r#"{"rules": [
                {"from": ["user:alice"], "to": ["tag:db"], "ports": ["5432"], "proto": "tcp"},
                {"from": ["*"], "to": ["self"]},
                {"from": ["tag:ci"], "to": ["tag:web"], "ports": ["8000-8100"]}
            ]}"#,
        );
        let alice = device(Some("alice"), &[]);
        let alice2 = device(Some("alice"), &[]);
        let bob = device(Some("bob"), &[]);
        let db = device(None, &["tag:db"]);
        let ci = device(None, &["tag:ci"]);
        let web = device(None, &["tag:web"]);

        assert!(p.allows(&alice, &db, PROTO_TCP, 5432));
        assert!(!p.allows(&alice, &db, PROTO_TCP, 22));
        assert!(!p.allows(&alice, &db, PROTO_UDP, 5432));
        assert!(!p.allows(&bob, &db, PROTO_TCP, 5432));
        assert!(p.allows(&alice, &alice2, PROTO_UDP, 9));
        assert!(!p.allows(&alice, &bob, PROTO_TCP, 22));
        assert!(
            !p.allows(&db, &db, PROTO_TCP, 22),
            "tagged devices own nothing"
        );
        assert!(p.allows(&ci, &web, PROTO_UDP, 8050));
        assert!(!p.allows(&ci, &web, PROTO_UDP, 8101));
        assert!(!p.allows(&web, &ci, PROTO_UDP, 8050));
    }

    #[test]
    fn icmp_ignores_ports() {
        let p = policy(
            r#"{"rules": [{"from": ["*"], "to": ["*"], "ports": ["22"], "proto": "icmp"}]}"#,
        );
        let a = device(Some("a"), &[]);
        assert!(p.allows(&a, &a, PROTO_ICMP, 0));
        assert!(p.allows(&a, &a, PROTO_ICMPV6, 0));
        assert!(!p.allows(&a, &a, PROTO_TCP, 22));
    }

    #[test]
    fn internet_is_only_matched_by_its_selector() {
        let p = policy(
            r#"{"rules": [
                {"from": ["*"], "to": ["*"]},
                {"from": ["user:alice"], "to": ["internet"], "ports": ["443"], "proto": "tcp"}
            ]}"#,
        );
        let alice = device(Some("alice"), &[]);
        let bob = device(Some("bob"), &[]);
        assert!(p.allows_internet(&alice, PROTO_TCP, 443));
        assert!(!p.allows_internet(&alice, PROTO_TCP, 80));
        assert!(
            !p.allows_internet(&bob, PROTO_TCP, 443),
            "`*` is devices only"
        );
        assert!(p.allows(&bob, &alice, PROTO_TCP, 443));
    }

    #[test]
    fn empty_policy_denies_everything() {
        let a = device(Some("a"), &[]);
        assert!(!Policy::default().allows(&a, &a, PROTO_TCP, 22));
    }

    #[test]
    fn validation_rejects_bad_rules() {
        for (json, want) in [
            (
                r#"{"rules": [{"from": ["group:x"], "to": ["*"]}]}"#,
                "unknown selector",
            ),
            (
                r#"{"rules": [{"from": ["self"], "to": ["*"]}]}"#,
                "only makes sense",
            ),
            (
                r#"{"rules": [{"from": ["internet"], "to": ["*"]}]}"#,
                "only makes sense",
            ),
            (
                r#"{"rules": [{"from": ["*"], "to": ["*"], "ports": ["90-80"]}]}"#,
                "backwards",
            ),
            (
                r#"{"rules": [{"from": ["*"], "to": ["*"], "ports": ["http"]}]}"#,
                "bad port",
            ),
            (
                r#"{"rules": [{"from": ["*"], "to": ["*"], "proto": "sctp"}]}"#,
                "unknown proto",
            ),
            (r#"{"rules": [{"from": [], "to": ["*"]}]}"#, "required"),
        ] {
            let p: Policy = serde_json::from_str(json).unwrap();
            let err = format!("{:#}", p.validate().unwrap_err());
            assert!(err.contains(want), "{json}: {err}");
        }
        serde_json::from_str::<Policy>(r#"{"rules": [], "acls": []}"#).unwrap_err();
    }

    #[test]
    fn tests_catch_policy_mistakes() {
        let p = policy(
            r#"{"rules": [{"from": ["*"], "to": ["tag:nas"], "ports": ["22"]}],
                "tests": [
                    {"from": "laptop", "to": "nas", "port": 22, "allow": true},
                    {"from": "laptop", "to": "internet", "port": 443, "allow": false},
                    {"from": "laptop", "to": "nas", "port": 80, "allow": true}
                ]}"#,
        );
        let lookup = |name: &str| match name {
            "laptop" => Some(device(Some("alice"), &[])),
            "nas" => Some(device(None, &["tag:nas"])),
            _ => None,
        };
        let err = p.run_tests(lookup).unwrap_err().to_string();
        assert!(
            err.contains("laptop -> nas:80/tcp: expected allow, the policy denies it"),
            "{err}"
        );

        let missing = policy(r#"{"tests": [{"from": "ghost", "to": "nas", "allow": false}]}"#);
        assert!(
            missing
                .run_tests(lookup)
                .unwrap_err()
                .to_string()
                .contains("no device")
        );
    }
}
