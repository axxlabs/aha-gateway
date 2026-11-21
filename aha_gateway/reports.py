# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Axxlabs Limited
"""Problem reports (SPEC §7.7): passed on to a private GitHub repository as issues, never kept here.

The computer builds the text and the person sees exactly that before sending. The gateway only frames it so
nothing in it is read as Markdown or mentions anyone, opens the issue, and once an hour deletes closed report
issues and open ones older than 90 days.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import logging
import re
from pathlib import Path
from typing import Protocol

import httpx

from .protocol import Report

log = logging.getLogger("aha.gateway")

API = "https://api.github.com"
LABEL = "report"
KEEP_DAYS = 90
SWEEP_EVERY = 3600
DELETE_ISSUE = "mutation($id: ID!) { deleteIssue(input: {issueId: $id}) { clientMutationId } }"


def fenced(body: str) -> str:
    """The whole body in one code block, fenced with more backticks than any run inside it."""
    longest = max((len(m) for m in re.findall(r"`+", body)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}text\n{body}\n{fence}"


def clean_title(title: str) -> str:
    title = " ".join(title.replace("@", "").split())
    return (title or "Problem report")[:100]


class Issues(Protocol):
    async def open(self, title: str, body: str) -> bool: ...
    async def sweep(self) -> int: ...


class GitHubIssues:
    def __init__(self, repo: str, token: str, http: httpx.AsyncClient) -> None:
        self.repo = repo
        self.http = http
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "aha-gateway",
        }

    async def open(self, title: str, body: str) -> bool:
        payload = {"title": clean_title(title), "body": fenced(body), "labels": [LABEL]}
        try:
            r = await self.http.post(f"{API}/repos/{self.repo}/issues", json=payload, headers=self.headers)
        except httpx.HTTPError as e:
            log.warning("report not sent: %s", type(e).__name__)
            return False
        if r.status_code != 201:
            log.warning("report not sent: GitHub answered %d", r.status_code)
        return r.status_code == 201

    async def _list(self, state: str) -> list[dict]:
        params = {"state": state, "labels": LABEL, "per_page": "100", "sort": "created", "direction": "asc"}
        r = await self.http.get(f"{API}/repos/{self.repo}/issues", params=params, headers=self.headers)
        r.raise_for_status()
        return [i for i in r.json() if "pull_request" not in i]

    async def _delete(self, node_id: str) -> bool:
        payload = {"query": DELETE_ISSUE, "variables": {"id": node_id}}
        r = await self.http.post(f"{API}/graphql", json=payload, headers=self.headers)
        return r.status_code == 200 and not r.json().get("errors")

    async def sweep(self) -> int:
        """Delete closed report issues, and open ones older than KEEP_DAYS. Returns how many were deleted."""
        cutoff = dt.datetime.now(dt.UTC) - dt.timedelta(days=KEEP_DAYS)
        doomed = list(await self._list("closed"))
        for issue in await self._list("open"):
            created = dt.datetime.fromisoformat(issue["created_at"].replace("Z", "+00:00"))
            if created < cutoff:
                doomed.append(issue)
        deleted = 0
        for issue in doomed:
            if await self._delete(issue["node_id"]):
                deleted += 1
        return deleted


class Reports:
    """The relay. `issues` is None when this gateway has no reports repository (SPEC §7.2)."""

    def __init__(self, issues: Issues | None) -> None:
        self.issues = issues

    @classmethod
    def from_settings(cls, repo: str, token_file: Path | None, http: httpx.AsyncClient) -> Reports:
        if not repo or token_file is None or not token_file.exists():
            return cls(None)
        token = token_file.read_text().strip()
        return cls(GitHubIssues(repo, token, http) if token else None)

    async def send(self, report: Report) -> str:
        """'' when the issue was opened, else the error code for report_result."""
        if self.issues is None:
            return "reports_off"
        return "" if await self.issues.open(report.title, report.body) else "send_failed"

    async def sweep_forever(self) -> None:
        if self.issues is None:
            return
        while True:
            try:
                n = await self.issues.sweep()
                if n:
                    log.info("deleted %d dealt-with or expired report(s)", n)
            except (httpx.HTTPError, ValueError, KeyError) as e:
                log.warning("report sweep failed: %s", type(e).__name__)
            await asyncio.sleep(SWEEP_EVERY)
