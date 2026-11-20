use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::config_entry::{ConfigOp, ConfigPayload};
use crate::hostname::{ascii_lowercase_cow, wildcard_lookup_ascii_lower};
use crate::identity::{AgentId, TenantId};
use crate::ownership::OwnershipPolicy;
use crate::tls_policy::{TlsMode, TlsPolicyTable};
use crate::tunnel::{CONTROL_PREFIX, HTTP_ROUTE_PREFIX, TCP_ROUTE_PREFIX, UDP_ROUTE_PREFIX};

/// Whether `hostname` begins with a route-key prefix the agent dispatches on.
///
/// (`tcp:`/`udp:`/`http:`/`ctrl:`) — the edge rejects such SNI/Host values so a
/// client can't flip hostname routing into a raw service-map lookup.
#[must_use]
pub fn is_reserved_route_key(hostname: &str) -> bool {
    [
        TCP_ROUTE_PREFIX,
        UDP_ROUTE_PREFIX,
        HTTP_ROUTE_PREFIX,
        CONTROL_PREFIX,
    ]
    .iter()
    .any(|p| hostname.starts_with(p))
}

/// A materialized routing table: hostname -> set of agent IDs that serve it,
/// plus a parallel TLS policy table so edges can look up termination mode
/// on the hot path.
///
/// Serializes as canonical CBOR on the hub's `/v1/routes/subscribe` SSE
/// stream, so an edge-only node can apply snapshots pushed by a remote hub.
/// `tls_policies` is `#[serde(default)]` for wire compatibility with older
/// hubs/edges that predate per-hostname TLS config.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RouteTable {
    routes: HashMap<String, HashSet<AgentId>>,
    #[serde(default, skip_serializing_if = "TlsPolicyTable::is_empty")]
    tls_policies: TlsPolicyTable,
    /// `#[serde(default)]` keeps the wire format compatible with edges and
    /// hubs that predate TCP/UDP service forwarding.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    tcp_routes: HashMap<TcpRouteKey, HashSet<AgentId>>,
    /// `BTreeMap` so the edge reconciler iterates in deterministic port order.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    tcp_listeners: BTreeMap<u16, TcpListenerBinding>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    udp_routes: HashMap<UdpRouteKey, HashSet<AgentId>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    udp_listeners: BTreeMap<u16, UdpListenerBinding>,
    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    signed_agents: HashSet<AgentId>,
}

/// Struct rather than a `(TenantId, String)` tuple so the CBOR wire form has
/// stable named fields.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TcpRouteKey {
    pub tenant: TenantId,
    pub service: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpListenerBinding {
    pub tenant: TenantId,
    pub service: String,
}

/// UDP routing reuses the TCP *key* shape (`{tenant, service}`); the protocol
/// is implicit in which map the entry lives in.
pub type UdpRouteKey = TcpRouteKey;

/// UDP listener binding. Unlike TCP it carries an optional per-service idle
/// timeout the edge uses to size its session-reap window.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdpListenerBinding {
    pub tenant: TenantId,
    pub service: String,
    /// Edge idle-reap timeout in seconds. `None` → edge default (60s).
    /// `#[serde(default)]` keeps the wire form compatible with edges that
    /// predate this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_timeout_secs: Option<u32>,
}

impl RouteTable {
    /// Materialize a route table from already-replayed config. The `policy`
    /// is applied here rather than during replay, so a [`ConfigState`] kept
    /// across policy changes still yields what a fresh replay would.
    #[must_use]
    pub fn from_state(
        state: &ConfigState,
        policy: &OwnershipPolicy,
        live_agents: Option<&HashSet<(TenantId, AgentId)>>,
    ) -> Self {
        // Sort tenants so cross-tenant port collisions resolve deterministically
        // (lowest `tenant_id` wins). HashMap iteration is randomized.
        let mut sorted_tenants: Vec<(&TenantId, &TenantState)> = state
            .tenants
            .iter()
            .filter(|(tenant_id, _)| policy.pq_public_key(tenant_id).is_some())
            .collect();
        sorted_tenants.sort_by_key(|(t, _)| *t.as_bytes());

        let mut routes: HashMap<String, HashSet<AgentId>> = HashMap::new();
        let mut tls_policies = TlsPolicyTable::new();
        let mut tcp_routes: HashMap<TcpRouteKey, HashSet<AgentId>> = HashMap::new();
        let mut tcp_listeners: BTreeMap<u16, TcpListenerBinding> = BTreeMap::new();
        let mut udp_routes: HashMap<UdpRouteKey, HashSet<AgentId>> = HashMap::new();
        let mut udp_listeners: BTreeMap<u16, UdpListenerBinding> = BTreeMap::new();
        // Not liveness-filtered: a fresh agent must pass the edge's
        // `is_known_agent` gate to establish the session that bumps its own
        // liveness. Per-hostname route sets below keep the liveness filter.
        let signed_agents: HashSet<AgentId> = sorted_tenants
            .iter()
            .flat_map(|(_, s)| s.agents.iter().cloned())
            .collect();

        for (tenant_id, tenant) in sorted_tenants {
            materialize_tenant(
                tenant_id,
                tenant,
                policy,
                live_agents,
                &mut routes,
                &mut tls_policies,
                &mut tcp_routes,
                &mut tcp_listeners,
                &mut udp_routes,
                &mut udp_listeners,
            );
        }

        Self {
            routes,
            tls_policies,
            tcp_routes,
            tcp_listeners,
            udp_routes,
            udp_listeners,
            signed_agents,
        }
    }

    /// Look up which agents serve a hostname.
    ///
    /// Tries exact match first, then a single-level wildcard: `*.example.eu`
    /// matches `app.example.eu` but **not** `deep.app.example.eu`. Only the
    /// first label (before the first dot) is replaced by `*`.
    #[must_use]
    pub fn lookup(&self, hostname: &str) -> Option<&HashSet<AgentId>> {
        crate::hostname::wildcard_lookup(hostname, |key| {
            self.routes.get(key).filter(|a| !a.is_empty())
        })
    }

    /// Combined `lookup` + TLS-mode resolution that shares a single
    /// ASCII-lowercase allocation across both hot-path probes. Preserves the
    /// independent wildcard semantics (each table is probed with its own
    /// exact-then-wildcard order).
    #[must_use]
    pub fn lookup_with_tls(&self, hostname: &str) -> Option<(&HashSet<AgentId>, TlsMode)> {
        let lower = ascii_lowercase_cow(hostname);
        let agents = wildcard_lookup_ascii_lower(&lower, |key| {
            self.routes.get(key).filter(|a| !a.is_empty())
        })?;
        let tls = self.tls_policies.lookup_ascii_lower(&lower);
        Some((agents, tls))
    }

    /// Build a route table from a pre-computed map (e.g. from TOML config).
    ///
    /// Use this when you already have the final hostname->agents mapping and
    /// don't need to replay signed config entries. Ownership is already
    /// enforced by the TOML structure itself.
    #[must_use]
    pub fn from_raw(routes: HashMap<String, HashSet<AgentId>>) -> Self {
        let signed_agents: HashSet<AgentId> = routes.values().flatten().cloned().collect();
        Self {
            routes,
            tls_policies: TlsPolicyTable::new(),
            tcp_routes: HashMap::new(),
            tcp_listeners: BTreeMap::new(),
            udp_routes: HashMap::new(),
            udp_listeners: BTreeMap::new(),
            signed_agents,
        }
    }

    /// Every agent ID a tenant has signed an `UpsertAgent` for, regardless
    /// of liveness. Used by edges to authorize inbound iroh connections.
    #[must_use]
    pub const fn signed_agents(&self) -> &HashSet<AgentId> {
        &self.signed_agents
    }

    /// Service names are exact-match — no wildcards (unlike `lookup`).
    #[must_use]
    pub fn lookup_tcp_service(
        &self,
        tenant: &TenantId,
        service: &str,
    ) -> Option<&HashSet<AgentId>> {
        let key = TcpRouteKey {
            tenant: *tenant,
            service: service.to_string(),
        };
        self.tcp_routes.get(&key).filter(|a| !a.is_empty())
    }

    #[must_use]
    pub const fn tcp_listeners(&self) -> &BTreeMap<u16, TcpListenerBinding> {
        &self.tcp_listeners
    }

    #[must_use]
    pub fn lookup_udp_service(
        &self,
        tenant: &TenantId,
        service: &str,
    ) -> Option<&HashSet<AgentId>> {
        let key = UdpRouteKey {
            tenant: *tenant,
            service: service.to_string(),
        };
        self.udp_routes.get(&key).filter(|a| !a.is_empty())
    }

    #[must_use]
    pub const fn udp_listeners(&self) -> &BTreeMap<u16, UdpListenerBinding> {
        &self.udp_listeners
    }

    /// Check if the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Number of hostname entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// All hostnames with at least one agent.
    #[must_use]
    pub fn hostnames(&self) -> HashSet<String> {
        self.routes
            .iter()
            .filter(|(_, agents)| !agents.is_empty())
            .map(|(h, _)| h.clone())
            .collect()
    }

    /// Remove TCP listeners whose port does not satisfy `f`.
    pub fn retain_tcp_listeners(&mut self, f: impl FnMut(&u16, &mut TcpListenerBinding) -> bool) {
        self.tcp_listeners.retain(f);
    }

    /// Remove UDP listeners whose port does not satisfy `f`.
    pub fn retain_udp_listeners(&mut self, f: impl FnMut(&u16, &mut UdpListenerBinding) -> bool) {
        self.udp_listeners.retain(f);
    }

    /// Every unique agent that serves at least one hostname or TCP/UDP service.
    #[must_use]
    pub fn unique_agents(&self) -> HashSet<&AgentId> {
        self.routes
            .values()
            .flatten()
            .chain(self.tcp_routes.values().flatten())
            .chain(self.udp_routes.values().flatten())
            .collect()
    }
}

/// Fold one signed-op into the per-tenant accumulator. Ownership-policy
/// gates are applied at materialization (see [`materialize_tenant`]).
fn apply_op(state: &mut TenantState, op: &ConfigOp, tenant_id: &TenantId) {
    match op {
        ConfigOp::UpsertHostname { hostname } => {
            state.hostnames.insert(hostname.to_lowercase());
        }
        ConfigOp::DeleteHostname { hostname } => {
            let key = hostname.to_lowercase();
            state.hostnames.remove(&key);
            state.tls.remove(&key);
        }
        ConfigOp::UpsertAgent { agent_id } => {
            state.agents.insert(agent_id.clone());
        }
        ConfigOp::RevokeAgent { agent_id } => {
            state.agents.remove(agent_id);
        }
        ConfigOp::SetHostnameTls { hostname, mode } => {
            state.tls.insert(hostname.to_lowercase(), *mode);
        }
        ConfigOp::UpsertTcpService {
            service,
            listen_port,
        } => {
            state.tcp_services.insert(service.clone(), *listen_port);
        }
        ConfigOp::DeleteTcpService { service } => {
            state.tcp_services.remove(service);
        }
        ConfigOp::UpsertUdpService {
            service,
            listen_port,
            idle_timeout_secs,
        } => {
            state.udp_services.insert(
                service.clone(),
                UdpServiceSpec {
                    listen_port: *listen_port,
                    port_count: 1,
                    idle_timeout_secs: *idle_timeout_secs,
                },
            );
        }
        ConfigOp::UpsertUdpServiceRange {
            service,
            port_start,
            port_end,
            idle_timeout_secs,
        } => {
            // `port_end < port_start` should never reach here (the hub rejects
            // it at ingress); skip defensively rather than underflow.
            let Some(count) = port_end
                .checked_sub(*port_start)
                .map(|d| d.saturating_add(1))
            else {
                tracing::warn!(
                    tenant = %tenant_id,
                    %service,
                    port_start,
                    port_end,
                    "skipping udp range with port_end < port_start"
                );
                return;
            };
            state.udp_services.insert(
                service.clone(),
                UdpServiceSpec {
                    listen_port: *port_start,
                    port_count: count,
                    idle_timeout_secs: *idle_timeout_secs,
                },
            );
        }
        ConfigOp::DeleteUdpService { service } => {
            state.udp_services.remove(service);
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "materializing every route surface for one tenant is naturally wide; \
              wrapping these into a struct just shifts the noise without simplifying"
)]
fn materialize_tenant(
    tenant_id: &TenantId,
    state: &TenantState,
    policy: &OwnershipPolicy,
    live_agents: Option<&HashSet<(TenantId, AgentId)>>,
    routes: &mut HashMap<String, HashSet<AgentId>>,
    tls_policies: &mut TlsPolicyTable,
    tcp_routes: &mut HashMap<TcpRouteKey, HashSet<AgentId>>,
    tcp_listeners: &mut BTreeMap<u16, TcpListenerBinding>,
    udp_routes: &mut HashMap<UdpRouteKey, HashSet<AgentId>>,
    udp_listeners: &mut BTreeMap<u16, UdpListenerBinding>,
) {
    // Only allocate a new set when filtering; the `None` path reuses the
    // existing set by reference. `agents_ref` points at whichever.
    let filtered: Option<HashSet<AgentId>> = live_agents.map(|live| {
        state
            .agents
            .iter()
            .filter(|a| live.contains(&(*tenant_id, (*a).clone())))
            .cloned()
            .collect()
    });
    let agents_ref: &HashSet<AgentId> = filtered.as_ref().unwrap_or(&state.agents);

    if agents_ref.is_empty() {
        return;
    }
    for hostname in &state.hostnames {
        if !policy.is_hostname_allowed(tenant_id, hostname) {
            tracing::warn!(
                tenant = %tenant_id,
                %hostname,
                "skipping unauthorized hostname claim"
            );
            continue;
        }
        // A key already present means another (lower) tenant_id claimed this
        // hostname. Keep the first claimant (matches the listener tie-break)
        // rather than silently overwriting it.
        if routes.contains_key(hostname) {
            tracing::warn!(
                tenant = %tenant_id,
                hostname = %hostname,
                "cross-tenant hostname collision; keeping earlier claimant"
            );
            continue;
        }
        routes.insert(hostname.clone(), agents_ref.clone());
        if let Some(mode) = state.tls.get(hostname) {
            tls_policies.insert(hostname.clone(), *mode);
        }
    }
    for (service, listen_port) in &state.tcp_services {
        tcp_routes.insert(
            TcpRouteKey {
                tenant: *tenant_id,
                service: service.clone(),
            },
            agents_ref.clone(),
        );
        // First-claim-wins is a backstop: the hub already enforces port
        // uniqueness at insert time.
        tcp_listeners
            .entry(*listen_port)
            .or_insert_with(|| TcpListenerBinding {
                tenant: *tenant_id,
                service: service.clone(),
            });
    }
    for (service, spec) in &state.udp_services {
        udp_routes.insert(
            UdpRouteKey {
                tenant: *tenant_id,
                service: service.clone(),
            },
            agents_ref.clone(),
        );
        // One listener per port in the range (`port_count` is bounded by the
        // hub's cap). First-claim-wins backstops the hub's insert-time check.
        for offset in 0..spec.port_count {
            let Some(port) = spec.listen_port.checked_add(offset) else {
                break;
            };
            udp_listeners
                .entry(port)
                .or_insert_with(|| UdpListenerBinding {
                    tenant: *tenant_id,
                    service: service.clone(),
                    idle_timeout_secs: spec.idle_timeout_secs,
                });
        }
    }
}

/// Config replayed from signed entries, per tenant.
///
/// Independent of the ownership policy and of agent liveness, so the hub can
/// keep one across rebuilds and fold new entries in with [`Self::apply`]
/// instead of replaying the whole log.
#[derive(Debug, Default)]
pub struct ConfigState {
    tenants: HashMap<TenantId, TenantState>,
}

impl ConfigState {
    /// Fold one entry in. Entries must be applied in sequence order per tenant.
    pub fn apply(&mut self, payload: &ConfigPayload) {
        let tenant = self.tenants.entry(payload.tenant_id).or_default();
        tenant.last_sequence = Some(payload.sequence);
        apply_op(tenant, &payload.op, &payload.tenant_id);
    }

    /// Sequence of the tenant's newest entry.
    #[must_use]
    pub fn last_sequence(&self, tenant_id: &TenantId) -> Option<u64> {
        self.tenants.get(tenant_id).and_then(|t| t.last_sequence)
    }

    /// Whether the tenant has an `UpsertAgent` for `agent_id` that was not
    /// revoked since.
    #[must_use]
    pub fn is_agent_signed(&self, tenant_id: &TenantId, agent_id: &AgentId) -> bool {
        self.tenants
            .get(tenant_id)
            .is_some_and(|t| t.agents.contains(agent_id))
    }

    /// `(has_tcp, has_udp)`: whether the tenant has any TCP / UDP service.
    #[must_use]
    pub fn service_bindings(&self, tenant_id: &TenantId) -> (bool, bool) {
        self.tenants.get(tenant_id).map_or((false, false), |t| {
            (!t.tcp_services.is_empty(), !t.udp_services.is_empty())
        })
    }

    /// Every TCP service as `(tenant, service, listen_port)`.
    pub fn tcp_services(&self) -> impl Iterator<Item = (&TenantId, &str, u16)> {
        self.tenants.iter().flat_map(|(tenant, t)| {
            t.tcp_services
                .iter()
                .map(move |(service, port)| (tenant, service.as_str(), *port))
        })
    }

    /// Every UDP service as `(tenant, service, port_start, port_end)`, the
    /// range inclusive.
    pub fn udp_services(&self) -> impl Iterator<Item = (&TenantId, &str, u16, u16)> {
        self.tenants.iter().flat_map(|(tenant, t)| {
            t.udp_services.iter().map(move |(service, spec)| {
                let end = spec
                    .listen_port
                    .saturating_add(spec.port_count.saturating_sub(1));
                (tenant, service.as_str(), spec.listen_port, end)
            })
        })
    }
}

/// Per-tenant state accumulated while replaying config entries.
#[derive(Debug, Default)]
struct TenantState {
    hostnames: HashSet<String>,
    agents: HashSet<AgentId>,
    #[expect(
        clippy::zero_sized_map_values,
        reason = "TlsMode is single-variant today; future variants would re-expand the table"
    )]
    tls: HashMap<String, TlsMode>,
    /// `service_name -> listen_port`, last-write-wins per service.
    tcp_services: HashMap<String, u16>,
    /// `service_name -> spec`, last-write-wins per service.
    udp_services: HashMap<String, UdpServiceSpec>,
    last_sequence: Option<u64>,
}

/// Accumulated UDP service binding for one tenant while replaying entries.
/// A single-port service has `port_count == 1`; a range spans
/// `listen_port ..= listen_port + port_count - 1`.
#[derive(Clone, Debug)]
struct UdpServiceSpec {
    listen_port: u16,
    port_count: u16,
    idle_timeout_secs: Option<u32>,
}

#[cfg(test)]
#[path = "routing_tests.rs"]
mod tests;
