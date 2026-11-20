# Instructions for coding agents

`SPEC.md` in the parent folder (aha-root) is the single source of truth. Read §6 (protocol), §7 (gateway)
and §9 (security) before changing anything here.

Rules:
- The gateway stores nothing (SPEC §6.5): no database, no files, no logs with addresses, names, message text
  or certificate contents. `tests/test_tunnel.py::test_nothing_is_written_and_nothing_personal_is_logged`
  must keep passing; extend its canaries when you add a code path that handles content.
- `aha_gateway/protocol.py` and `aha_gateway/certs.py` are identical copies of the files in aha-local-llm.
  Change both repos together.
- The simulator (`aha_gateway/staging/`) never ships in production builds; keep
  `test_production_wheel_has_no_staging_code` green.
- All texts the gateway sends to people live in `aha_gateway/messages.py`.
- Follow the milestones in SPEC §12; don't build what's marked later (WhatsApp, Telegram, Stripe) without
  being asked.
- `uv run ruff check . && uv run ruff format --check . && uv run pytest` before every commit.
