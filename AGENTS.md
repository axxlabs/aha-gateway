# Instructions for coding agents

Design notes: Axxlabs keeps the design specification privately. Code comments still cite its sections
("SPEC §5.2"); you don't need it, because the rules that matter are written here and enforced by the tests.
For a change in behaviour, say what changes and why (in the PR description, or to the user) before writing
code, then make the code and its tests match.

Rules:
- The gateway stores nothing and reads nothing: no database, no files, no logs with device ids, tags,
  certificates or frame contents, and it never parses an end-to-end box.
  `tests/test_tunnel.py::test_nothing_is_written_and_nothing_identifying_is_logged` must keep passing; extend
  its canaries when you add a code path.
- It serves no web pages or scripts (only `/v1/*`, `/.well-known` and `/healthz`): the app is hosted elsewhere.
- Certificates only route. Never add a path where the gateway's word makes a computer trust a device.
- Push relay: only HTTPS endpoints of the known push services, no redirects (`aha_gateway/push.py`).
- `aha_gateway/protocol.py` and `aha_gateway/certs.py` are identical copies of the files in aha-local-llm.
  Change both repos together.
- Stripe billing is planned for later; don't build it without being asked.
- `uv run ruff check . && uv run ruff format --check . && uv run pytest` before every commit.

