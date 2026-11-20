# Instructions for coding agents

Design notes: Axxlabs keeps the design specification privately. Code comments still cite its sections
("SPEC §5.2"); you don't need it, because the rules that matter are written here and enforced by the tests.
For a change in behaviour, say what changes and why (in the PR description, or to the user) before writing
code, then make the code and its tests match.

Rules:
- The gateway stores nothing: no database, no files, no logs with addresses, names, message text
  or certificate contents. `tests/test_tunnel.py::test_nothing_is_written_and_nothing_personal_is_logged`
  must keep passing; extend its canaries when you add a code path that handles content.
- `aha_gateway/protocol.py` and `aha_gateway/certs.py` are identical copies of the files in aha-local-llm.
  Change both repos together.
- The simulator (`aha_gateway/staging/`) never ships in production builds; keep
  `test_production_wheel_has_no_staging_code` green.
- All texts the gateway sends to people live in `aha_gateway/messages.py`.
- WhatsApp and Telegram connectors and Stripe billing are planned for later; don't build them without being
  asked.
- `uv run ruff check . && uv run ruff format --check . && uv run pytest` before every commit.

