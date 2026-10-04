#!/usr/bin/env bash
# QUIC against TLS/TCP under the same emulated WAN, one run per loss rate.
#   LOSSES="0 0.5 2" DELAY=20ms RATE=100mbit BULK_STREAMS=4 bash tests/transport-compare.sh
set -euo pipefail

cd "$(dirname "$0")/.."
cargo test --release --offline --locked --test transport_compare --no-run

for loss in ${LOSSES:-0 0.5 2}; do
    # All shaping is confined to this process's new network namespace.
    unshare --user --map-root-user --net \
        env LOSS="$loss" DELAY="${DELAY:-20ms}" RATE="${RATE:-100mbit}" \
        BULK_STREAMS="${BULK_STREAMS:-4}" bash -s <<'SH'
set -euo pipefail
ip link set lo up
# Loopback's 64 KiB MTU would hand TCP super-segments that netem queues as single
# packets; a real path carries 1500-byte ones, as QUIC's datagrams already are.
ip link set lo mtu 1500
tc qdisc add dev lo root netem limit 2000 delay "$DELAY" rate "$RATE" \
    loss random "$LOSS" seed 12345
export TOWONEL_DISABLE_UDP_GSO=true
cargo test --release --offline --locked --test transport_compare -- --ignored --nocapture \
    --test-threads=1 2>&1 | grep -E "RESULT|FAILED|panicked|Error"
SH
done
