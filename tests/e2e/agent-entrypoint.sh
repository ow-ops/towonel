#!/bin/sh
set -eu

BROKER_URL="${BROKER_URL:-http://test-runner:7777/token}"
MAX_WAIT_SECS="${BROKER_MAX_WAIT_SECS:-60}"

# e2e: the hub serves a cert issued by the local Pebble CA. Install Pebble's
# issuing root (and intermediate) so the agent's TLS verification of the hub
# succeeds. Pebble generates these at startup, so fetch them at runtime.
if [ -n "${PEBBLE_URL:-}" ]; then
    waited=0
    until curl -fsSk "$PEBBLE_URL/roots/0" -o /usr/local/share/ca-certificates/pebble-root.crt; do
        waited=$((waited + 1))
        if [ "$waited" -ge 30 ]; then
            echo "agent-entrypoint: no Pebble roots from $PEBBLE_URL after 30s" >&2
            exit 1
        fi
        sleep 1
    done
    curl -fsSk "$PEBBLE_URL/intermediates/0" \
        -o /usr/local/share/ca-certificates/pebble-intermediate.crt || true
    update-ca-certificates >/dev/null 2>&1
fi

# e2e-tls: drop outbound UDP to the edge's QUIC port so the agent has to use the
# TLS fallback. Only that port, because the container resolver is UDP too.
if [ -n "${E2E_BLOCK_UDP_PORT:-}" ]; then
    iptables -A OUTPUT -p udp --dport "$E2E_BLOCK_UDP_PORT" -j DROP
    ip6tables -A OUTPUT -p udp --dport "$E2E_BLOCK_UDP_PORT" -j DROP || true
fi

waited=0
while :; do
    token=$(curl --fail --silent --max-time 2 "$BROKER_URL" 2>/dev/null || true)
    if [ -n "$token" ]; then
        break
    fi
    waited=$((waited + 1))
    if [ "$waited" -ge "$MAX_WAIT_SECS" ]; then
        echo "agent-entrypoint: no token from $BROKER_URL after ${MAX_WAIT_SECS}s" >&2
        exit 1
    fi
    sleep 1
done

export TOWONEL_INVITE_TOKEN="$token"
exec /usr/local/bin/towonel-agent
