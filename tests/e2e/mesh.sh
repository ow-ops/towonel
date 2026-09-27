#!/usr/bin/env bash
# Mesh data plane with real TUN devices: a hub and two `towonel mesh up`
# daemons in containers, then IPv4/IPv6 ping, TCP, an exit node and
# revocation across the overlay.
#
# Uses the host-built binary inside archlinux:latest, so the host's glibc
# must not be newer than the image's.
set -euo pipefail

BIN=${BIN:-$(pwd)/target/release/towonel}
NET=towonel-mesh-e2e
# Stands in for the internet: only alpha, the exit node, is attached. Public
# addresses, since exits refuse to forward to private ranges.
WAN=towonel-mesh-e2e-wan
WAN_SUBNET=11.10.0.0/24
WEB_IP=11.10.0.10
IMAGE=archlinux:latest

cleanup() {
	docker rm -f mesh-hub mesh-alpha mesh-beta mesh-gamma mesh-web >/dev/null 2>&1 || true
	docker network rm "$NET" "$WAN" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

fail() {
	echo "FAIL: $*" >&2
	for c in mesh-alpha mesh-beta mesh-gamma; do docker logs "$c" >&2 || true; done
	exit 1
}

docker network create "$NET" >/dev/null
docker network create --subnet "$WAN_SUBNET" "$WAN" >/dev/null
docker run -d --name mesh-hub --network "$NET" -v "$BIN:/usr/local/bin/towonel:ro" \
	-e TOWONEL_DATA_DIR=/data -e TOWONEL_HUB_ENABLED=true -e TOWONEL_EDGE_ENABLED=false \
	-e TOWONEL_HUB_DB_DRIVER=sqlite -e TOWONEL_HUB_DB_DSN=/data/hub.sqlite \
	-e TOWONEL_HUB_LISTEN_ADDR=0.0.0.0:18443 -e TOWONEL_HUB_PUBLIC_URL=https://hub.mesh.test \
	-e TOWONEL_HUB_MESH_EXIT_NODES_ENABLED=true \
	"$IMAGE" sh -c 'mkdir -p /data && exec towonel serve' >/dev/null

hub() { docker exec mesh-hub "$@"; }
for _ in $(seq 30); do hub curl -sf http://127.0.0.1:18443/v1/health >/dev/null && break; sleep 1; done
op=$(hub cat /data/operator.key)
api() { hub curl -sf -H "Authorization: Bearer $op" -H 'content-type: application/json' "$@"; }

hub env TOWONEL_HUB_URL=http://127.0.0.1:18443 TOWONEL_OPERATOR_KEY="$op" \
	towonel invite create --name mesh --hostnames app.mesh.test >/dev/null
tenant=$(api http://127.0.0.1:18443/v1/invites | grep -o '"tenant_id":"[0-9a-f]*"' | head -1 | cut -d'"' -f4)
key=$(api -X POST -d '{"reusable":true}' "http://127.0.0.1:18443/v1/tenants/$tenant/mesh/auth-keys" |
	grep -o '"token":"[^"]*"' | cut -d'"' -f4)

mesh_up() {
	local d=$1
	shift
	docker run -d --name "mesh-$d" --network "$NET" --cap-add NET_ADMIN --device /dev/net/tun \
		--sysctl net.ipv4.ip_forward=1 --sysctl net.ipv6.conf.all.forwarding=1 \
		-v "$BIN:/usr/local/bin/towonel:ro" -e RUST_BACKTRACE=0 "$IMAGE" \
		sh -c 'pacman -Sy --noconfirm --needed nftables >/dev/null 2>&1; exec "$@"' sh \
		towonel mesh up --hub-url http://mesh-hub:18443 --auth-key "$key" --name "$d" --state-dir /state "$@" >/dev/null
}
mesh_up alpha --advertise-exit-node
mesh_up beta
docker network connect "$WAN" mesh-alpha
docker run -d --name mesh-web --network "$WAN" --ip "$WEB_IP" -v "$BIN:/usr/local/bin/towonel:ro" \
	-e TOWONEL_DATA_DIR=/data -e TOWONEL_HUB_ENABLED=true -e TOWONEL_EDGE_ENABLED=false \
	-e TOWONEL_HUB_DB_DRIVER=sqlite -e TOWONEL_HUB_DB_DSN=/data/hub.sqlite \
	-e TOWONEL_HUB_LISTEN_ADDR=0.0.0.0:18443 -e TOWONEL_HUB_PUBLIC_URL=https://web.test \
	"$IMAGE" sh -c 'mkdir -p /data && exec towonel serve' >/dev/null
# alpha also serves something to reach over TCP.
docker exec -d mesh-alpha sh -c 'mkdir -p /d2 && TOWONEL_DATA_DIR=/d2 TOWONEL_HUB_ENABLED=true \
	TOWONEL_EDGE_ENABLED=false TOWONEL_HUB_DB_DRIVER=sqlite TOWONEL_HUB_DB_DSN=/d2/hub.sqlite \
	TOWONEL_HUB_LISTEN_ADDR=0.0.0.0:28443 TOWONEL_HUB_PUBLIC_URL=https://x.test towonel serve > /d2/log 2>&1'

for _ in $(seq 30); do
	docker exec mesh-beta ip -brief addr show towonel0 >/dev/null 2>&1 &&
		docker exec mesh-alpha ip -brief addr show towonel0 >/dev/null 2>&1 && break
	sleep 1
done
alpha6=$(docker exec mesh-alpha ip -6 -brief addr show towonel0 | awk '{print $3}' | cut -d/ -f1)
[ -n "$alpha6" ] || fail "alpha has no towonel0 IPv6 address"

docker exec mesh-beta ping -c 3 -W 5 100.64.0.1 >/dev/null || fail "IPv4 ping over the mesh"
echo "ok: IPv4 ping"
docker exec mesh-beta ping -6 -c 3 -W 5 "$alpha6" >/dev/null || fail "IPv6 ping over the mesh"
echo "ok: IPv6 ping"
for _ in $(seq 20); do
	docker exec mesh-beta curl -sf -m 5 http://100.64.0.1:28443/v1/health >/dev/null && break
	sleep 1
done
docker exec mesh-beta curl -sf -m 5 http://100.64.0.1:28443/v1/health >/dev/null || fail "TCP over the mesh"
echo "ok: TCP"

alpha_id=$(docker exec mesh-alpha cat /state/enrollment.json | grep -o '"device_id": *"[0-9a-f]*"' | grep -o '[0-9a-f]\{64\}')

docker exec mesh-beta curl -sf -m 3 "http://$WEB_IP:18443/v1/health" >/dev/null 2>&1 &&
	fail "the WAN is reachable without the exit node"
api -X PUT -d '{"approved":true}' "http://127.0.0.1:18443/v1/tenants/$tenant/mesh/devices/$alpha_id/exit-node" >/dev/null
mesh_up gamma --exit-node alpha
for _ in $(seq 60); do
	docker exec mesh-gamma curl -sf -m 5 "http://$WEB_IP:18443/v1/health" >/dev/null 2>&1 && break
	sleep 1
done
docker exec mesh-gamma curl -sf -m 5 "http://$WEB_IP:18443/v1/health" >/dev/null || fail "internet through the exit node"
docker exec mesh-gamma ip route get "$WEB_IP" | grep -q towonel0 || fail "internet not routed into the mesh"
docker exec mesh-gamma ping -c 2 -W 5 100.64.0.2 >/dev/null || fail "mesh traffic next to an exit node"
echo "ok: exit node"
api -X DELETE "http://127.0.0.1:18443/v1/tenants/$tenant/mesh/devices/$alpha_id" >/dev/null
sleep 3
docker exec mesh-beta ping -c 2 -W 2 100.64.0.1 >/dev/null 2>&1 && fail "revoked device still reachable"
[ "$(docker inspect -f '{{.State.Running}}' mesh-alpha)" = false ] || fail "revoked daemon kept running"
docker logs mesh-alpha 2>&1 | grep -q "removed from the mesh" || fail "revoked daemon gave no reason"
echo "ok: revocation"
echo "mesh e2e passed"
