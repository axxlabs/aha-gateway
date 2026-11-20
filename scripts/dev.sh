#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Axxlabs Limited
# Run a development gateway on this machine (SPEC §7.6): TCP on 127.0.0.1:8700, plus a Unix socket at
# $XDG_RUNTIME_DIR/aha-gateway/gateway.sock that a local aha computer uses. The app runs from aha-app's own
# dev server (npm run dev, http://127.0.0.1:5173). AHA_GW_HOST=0.0.0.0 listens on the LAN too.
set -euo pipefail
umask 077  # the socket and the keys are for this user only
cd "$(dirname "$0")/.."
DATA="${AHA_GW_DEV_DATA:-$HOME/.local/share/aha-gateway-dev}"
export AHA_GW_SIGNING_KEY_FILE="${AHA_GW_SIGNING_KEY_FILE:-$DATA/gateway.key}"
export AHA_GW_VAPID_KEY_FILE="${AHA_GW_VAPID_KEY_FILE:-$DATA/vapid.pem}"
export AHA_GW_UNIX_SOCKET="${AHA_GW_UNIX_SOCKET:-${XDG_RUNTIME_DIR:-/tmp}/aha-gateway/gateway.sock}"
mkdir -p "$(dirname "$AHA_GW_UNIX_SOCKET")"
chmod 700 "$(dirname "$AHA_GW_UNIX_SOCKET")"  # uvicorn makes the socket itself 0666
export AHA_GW_PUBLIC_URL="${AHA_GW_PUBLIC_URL:-http://127.0.0.1:8700}"
rm -f "$AHA_GW_UNIX_SOCKET"
exec uv run python -m aha_gateway
