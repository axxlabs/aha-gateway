# aha-gateway

The relay between SHA apps and the aha computers they belong to (**SHA, a self-hosted assistant**). Messages are
end-to-end encrypted between each device and its computer; the gateway only routes ciphertext, relays
encrypted push notifications, and keeps nothing: no database, no message logs, no identifiers in its logs. It
serves no web pages or scripts, so taking it over gives no way to change the app.

The computer side is [aha-local-llm](https://github.com/axxlabs/aha-local-llm); the app is
[aha-app](https://github.com/axxlabs/aha-app). Website: https://axxlabs.ai/aha/

## What it does

- `/v1/tunnel`: computers connect out to it; both sides prove their keys (the computer pins the gateway's key).
- `/v1/device`: apps connect with a binding certificate and a signature; or join a pairing with a rendezvous
  code (the pairing itself is end-to-end and needs a secret the gateway never sees).
- Signs binding certificates on a computer's request. They only route frames; they never make a computer
  trust a device.
- Relays Web Push payloads (already encrypted and authenticated by the computer) to the known push services,
  signed with its VAPID key.
- Passes on problem reports the person chose to send to a private issue tracker, and keeps nothing (below).
- `/.well-known/aha-gateway.json` (public keys, version, source) and `/healthz`.

## Run it locally (development)

```sh
uv sync
scripts/dev.sh        # 127.0.0.1:8700 and a Unix socket for a computer on this machine
```

The signing key and VAPID key are created on first start (mode 0600). Computers pin the signing key, so keep
it: a new key means pairing every device and re-running `aha init` on every computer.

## Self-host

See `deploy/compose.yaml` (gateway + Caddy for TLS). Serve the app (aha-app's `dist/`) from a static host of
your own, separate from the gateway, and list its origin in `AHA_GW_APP_ORIGINS`.

`deploy/hetzner/create.sh` sets up a server on Hetzner Cloud the way the hosted gateway runs: a cloud firewall
(SSH, 80, 443 only), an admin user with your SSH key, no root or password login, automatic security updates,
then the same compose file. Until your DNS name resolves, the gateway is also served as `<ip>.sslip.io`.

### Problem reports

Computers can pass on a problem report the person previewed and chose to send. The gateway opens it as an issue
(label `report`) in a private GitHub repository, keeps nothing itself, and once an hour deletes closed report
issues and open ones older than 90 days. Set `AHA_GW_REPORTS_REPO` and put a token in the file named by
`AHA_GW_GITHUB_TOKEN_FILE` (issues read/write on that repository; its account must be an admin of it to delete
issues). Without them, reports are off and the app says so.

## Environment

| Variable | Default | |
|---|---|---|
| `AHA_GW_SIGNING_KEY_FILE` | `/run/secrets/aha-gateway-key` | Ed25519 key, created if missing (mode 0600) |
| `AHA_GW_VAPID_KEY_FILE` | `/run/secrets/aha-gateway-vapid.pem` | P-256 key for Web Push (VAPID), created if missing |
| `AHA_GW_VAPID_SUBJECT` | `https://axxlabs.ai/aha/` | Contact URL sent to push services |
| `AHA_GW_PUBLIC_URL` | `http://127.0.0.1:8700` | Advertised in `/.well-known/aha-gateway.json` |
| `AHA_GW_APP_ORIGINS` | the official app and `localhost:5173` | Browser origins allowed to open `/v1/device` |
| `AHA_GW_HOST` / `AHA_GW_PORT` | `127.0.0.1` / `8700` | Listen address |
| `AHA_GW_UNIX_SOCKET` | unset | Also listen on this Unix socket (a computer on the same machine) |
| `AHA_GW_BILLING` | `off` | `stripe` is a later milestone |
| `AHA_GW_REPORTS_REPO` | unset | `owner/repo` of the private repository problem reports go to |
| `AHA_GW_GITHUB_TOKEN_FILE` | unset | File holding the GitHub token for that repository |
| `AHA_GW_SOURCE_URL` | upstream repo | Where this gateway's source is, shown to its users (AGPL §13). Point it at your own source if you run a modified gateway |

## Tests

`uv run pytest`: real sockets (a gateway on a free port, a fake computer and fake devices), certificate and
pairing rules, push allowlist, origin checks, fuzzed frames, and a test that relaying writes no file and logs
no identifiers.

## Security

See `SECURITY.md` for how to report a vulnerability.

## Licence

Copyright (C) 2026 Axxlabs Limited. Licensed under the GNU Affero General Public License, version 3 or (at your
option) any later version: see `LICENSE`. If you run a modified version for other people, including over a
network, you must offer them its source (AGPL §13; set `AHA_GW_SOURCE_URL`).
