# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Axxlabs Limited
"""Problem reports (SPEC §7.7, §11.10): fenced, @-free, rate-limited, off without a repository, swept."""

import datetime as dt
import json

import httpx

from aha_gateway.protocol import Report
from aha_gateway.reports import GitHubIssues, Reports, clean_title, fenced


class FakeIssues:
    def __init__(self) -> None:
        self.opened: list[tuple[str, str]] = []

    async def open(self, title: str, body: str) -> bool:
        self.opened.append((title, body))
        return True

    async def sweep(self) -> int:
        return 0


def test_body_is_fenced_longer_than_any_backticks_inside():
    body = "look: ```` @someone **bold**"
    out = fenced(body)
    assert out.startswith("`````text\n") and out.endswith("\n`````")
    assert body in out


def test_titles_lose_at_signs_and_newlines():
    assert clean_title("@octocat broke\nit") == "octocat broke it"
    assert clean_title("   ") == "Problem report"
    assert len(clean_title("x" * 500)) == 100


async def test_reports_are_off_without_a_repository(gateway, computer):
    await computer.connect()
    await computer.send(Report(id="r1", title="t", body="b"))
    res = await computer.recv()
    assert (res.t, res.id, res.ok, res.code) == ("report_result", "r1", False, "reports_off")


async def test_reports_are_passed_on_then_rate_limited(gateway, computer):
    fake = FakeIssues()
    gateway.app.state.reports.issues = fake
    await computer.connect()
    for i in range(5):
        await computer.send(Report(id=f"r{i}", title="Problem: page", body=f"body {i}"))
        res = await computer.recv()
        assert res.ok, res
    await computer.send(Report(id="r9", title="again", body="b"))
    res = await computer.recv()
    assert (res.ok, res.code) == (False, "rate_limited")
    assert [b for _, b in fake.opened] == [f"body {i}" for i in range(5)]


async def test_github_issue_and_sweep():
    now = dt.datetime.now(dt.UTC)
    old = (now - dt.timedelta(days=91)).isoformat().replace("+00:00", "Z")
    new = now.isoformat().replace("+00:00", "Z")
    calls: list[tuple[str, str, dict]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else {}
        calls.append((request.method, request.url.path, body))
        assert request.headers["authorization"] == "Bearer tok"
        if request.method == "POST" and request.url.path.endswith("/issues"):
            return httpx.Response(201, json={"number": 1})
        if request.url.path.endswith("/issues"):
            if request.url.params["state"] == "closed":
                return httpx.Response(200, json=[{"node_id": "closed1", "created_at": new}])
            return httpx.Response(
                200,
                json=[
                    {"node_id": "old1", "created_at": old},
                    {"node_id": "new1", "created_at": new},
                    {"node_id": "pr", "created_at": old, "pull_request": {}},
                ],
            )
        if request.url.path == "/graphql":
            return httpx.Response(200, json={"data": {}})
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        gh = GitHubIssues("axxlabs/aha-reports", "tok", http)
        assert await Reports(gh).send(Report(id="x", title="@a hi", body="```x")) == ""
        posted = calls[0][2]
        assert posted["title"] == "a hi" and posted["labels"] == ["report"]
        assert posted["body"] == "````text\n```x\n````"
        assert await gh.sweep() == 2
    deleted = [c[2]["variables"]["id"] for c in calls if c[1] == "/graphql"]
    assert deleted == ["closed1", "old1"]
