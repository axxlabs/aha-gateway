# aha-gateway

The relay between chat apps (WhatsApp, Telegram, and a chat simulator in staging) and aha computers.
It carries each message to the computer that holds the address and forgets it: no database, no message logs.

The full specification is `SPEC.md` in aha-root (§6 protocol, §7 gateway, §8 hosted gateway).

## Run it locally (staging build, with the simulator)

```sh
uv sync
AHA_GW_SIGNING_KEY_FILE=./.dev/gateway.key uv run python -m aha_gateway
# open http://127.0.0.1:8700/test
```

The signing key is created on first start. Computers pin its public key (`/.well-known/aha-gateway.json`),
so keep it: a new key means re-running `aha init` on every computer.

## Self-host

See `deploy/compose.yaml` (gateway + Caddy for TLS). Production images are built without the simulator:
`podman build -f deploy/Containerfile -t aha-gateway .`

## Environment

| Variable | Default | |
|---|---|---|
| `AHA_GW_SIGNING_KEY_FILE` | `/run/secrets/aha-gateway-key` | Ed25519 key, created if missing (mode 0600) |
| `AHA_GW_PUBLIC_URL` | `http://127.0.0.1:8700` | Advertised in `/.well-known/aha-gateway.json` |
| `AHA_GW_HOST` / `AHA_GW_PORT` | `127.0.0.1` / `8700` | Listen address |
| `AHA_GW_BILLING` | `off` | `stripe` is milestone M3 |
| `AHA_GW_STAGING_ACCESS` | `local` | `local` (loopback only) or `proxy` (with `AHA_GW_TRUSTED_PROXY`) |

## Tests

`uv run pytest` — real sockets: a gateway on a free port, a fake computer and the simulator as a browser.

Licence: AGPL-3.0-or-later.
