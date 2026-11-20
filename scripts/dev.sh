#!/usr/bin/env bash
# Run a staging gateway on this machine: the simulator at http://127.0.0.1:8700/test, plus a Unix socket at
# $XDG_RUNTIME_DIR/aha-gateway.sock that a local aha computer can use without the gateway listening on the LAN.
set -euo pipefail
cd "$(dirname "$0")/.."
export AHA_GW_SIGNING_KEY_FILE="${AHA_GW_SIGNING_KEY_FILE:-$HOME/.local/share/aha-gateway-dev/gateway.key}"
export AHA_GW_UNIX_SOCKET="${AHA_GW_UNIX_SOCKET:-${XDG_RUNTIME_DIR:-/tmp}/aha-gateway.sock}"
export AHA_GW_PUBLIC_URL="${AHA_GW_PUBLIC_URL:-http://127.0.0.1:8700}"
rm -f "$AHA_GW_UNIX_SOCKET"
exec uv run python -m aha_gateway
