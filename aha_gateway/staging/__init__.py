# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Axxlabs Limited
"""Chat simulator: /test (SPEC §7.4). Present only in a staging build.

Copied from amb-v2's developer console (its spec §15) and adapted to a gateway that stores nothing: the
transcript lives in the browser (localStorage), and replies arrive live over Server-Sent Events. A reply sent
while no browser is listening for that number is dropped, like any message to a phone that's switched off.

Two gates, as in amb-v2: the package is left out of production builds, and every request must come from
loopback with no forwarding header (`local`), from the local network or Tailscale with no forwarding header
(`network`), or from the trusted proxy with a signed-in user (`proxy`).
Anything else gets a plain 404.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import secrets
import time
from collections import defaultdict
from pathlib import Path

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader
from pydantic import BaseModel, Field

from ..config import Settings
from ..connectors.base import InboundMessage, OutboundMessage
from ..protocol import ID_PATTERN, MAX_TEXT_CHARS, normalise_phone
from ..relay import Relay
from .formatting import whatsapp

log = logging.getLogger("aha.gateway.staging")

TEMPLATES = Jinja2Templates(
    env=Environment(loader=FileSystemLoader(Path(__file__).parent / "templates"), autoescape=True)
)
FORWARDING_HEADERS = ("x-forwarded-for", "forwarded", "x-real-ip")
USER_HEADER = "x-auth-request-user"
TOKEN_COOKIE = "sim_token"
TOKEN_HEADER = "x-sim-token"
MAX_STREAM_ADDRESSES = 50
QUEUE_SIZE = 100
KEEPALIVE_SECONDS = 15
# `network` access: the LAN (RFC 1918, IPv6 unique-local) and Tailscale (CGNAT range and its IPv6 prefix).
LOCAL_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7", "fd7a:115c:a1e0::/48")
)


def viewer(request: Request, settings: Settings) -> str:
    """Gate 2. Returns the signed-in login with `proxy` access, "" with `local`/`network`; otherwise 404."""
    host = request.client.host if request.client else ""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        raise HTTPException(status_code=404) from None
    if settings.staging_access == "proxy":
        login = request.headers.get(USER_HEADER, "").strip()
        network = ipaddress.ip_network(settings.trusted_proxy, strict=False)
        if address not in network or not login:
            raise HTTPException(status_code=404)
        return login
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    allowed = address.is_loopback or (
        settings.staging_access == "network" and any(address in n for n in LOCAL_NETWORKS)
    )
    if not allowed or any(h in request.headers for h in FORWARDING_HEADERS):
        raise HTTPException(status_code=404)
    return ""


class SimulatorConnector:
    """Delivers outbound messages for `sim:` addresses to the browsers listening for them."""

    prefix = "sim"

    def __init__(self) -> None:
        self._listeners: dict[str, set[asyncio.Queue]] = defaultdict(set)

    def listen(self, addresses: list[str]) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=QUEUE_SIZE)
        for a in addresses:
            self._listeners[a].add(queue)
        return queue

    def stop(self, addresses: list[str], queue: asyncio.Queue) -> None:
        for a in addresses:
            self._listeners[a].discard(queue)
            if not self._listeners[a]:
                del self._listeners[a]

    async def send(self, message: OutboundMessage) -> None:
        event = {
            "type": "message",
            "to": message.to.removeprefix("sim:"),
            "html": str(whatsapp(message.text)),
            "buttons": [b.model_dump() for b in message.buttons],
            "image": f"data:{message.image.mime};base64,{message.image.b64}" if message.image else None,
            "time": time.strftime("%H:%M"),
        }
        if not self._publish(message.to, event):
            log.info("simulated reply dropped: no browser listening")

    async def typing(self, address: str, on: bool) -> None:
        self._publish(address, {"type": "typing", "to": address.removeprefix("sim:"), "on": on})

    def _publish(self, address: str, event: dict) -> bool:
        queues = self._listeners.get(address, set())
        for q in list(queues):
            if q.full():
                q.get_nowait()
            q.put_nowait(event)
        return bool(queues)


class SendForm(BaseModel):
    number: str = Field(max_length=32)
    text: str = Field(default="", max_length=MAX_TEXT_CHARS)
    button: str | None = Field(default=None, pattern=ID_PATTERN)


def mount(app: FastAPI, relay: Relay, settings: Settings) -> None:
    connector = SimulatorConnector()
    relay.add_connector(connector)

    def gate(request: Request) -> None:
        request.state.viewer = viewer(request, settings)

    def check_token(request: Request) -> None:
        cookie = request.cookies.get(TOKEN_COOKIE, "")
        header = request.headers.get(TOKEN_HEADER, "")
        if not cookie or not secrets.compare_digest(cookie, header):
            raise HTTPException(status_code=403, detail="Missing or wrong token")

    router = APIRouter(prefix="/test", dependencies=[Depends(gate)])

    @router.get("", response_class=HTMLResponse)
    def page(request: Request) -> HTMLResponse:
        token = request.cookies.get(TOKEN_COOKIE) or secrets.token_urlsafe(32)
        response = TEMPLATES.TemplateResponse(
            request,
            "test.html",
            {
                "token": token,
                "viewer": request.state.viewer,
                "open_registration": settings.open_registration,
                "source_url": settings.source_url,
            },
        )
        response.set_cookie(TOKEN_COOKIE, token, httponly=True, samesite="strict")
        response.headers["Cache-Control"] = "no-store"  # always the current page script
        return response

    @router.post("/send", dependencies=[Depends(check_token)])
    async def send(form: SendForm) -> JSONResponse:
        number = normalise_phone(form.number)
        if number is None:
            raise HTTPException(status_code=422, detail="Use an international number, e.g. +44 7900 000001")
        if not form.text.strip() and form.button is None:
            raise HTTPException(status_code=422, detail="Empty message")
        await relay.inbound(InboundMessage(sender=f"sim:{number}", text=form.text, button=form.button))
        return JSONResponse({"number": number, "html": str(whatsapp(form.text)), "time": time.strftime("%H:%M")})

    @router.get("/events")
    async def events(request: Request, n: list[str] = Query(default=[])) -> StreamingResponse:
        numbers = [p for p in (normalise_phone(x) for x in n[:MAX_STREAM_ADDRESSES]) if p]
        addresses = [f"sim:{p}" for p in numbers]
        queue = connector.listen(addresses)

        async def stream():
            try:
                yield ": connected\n\n"
                while not await request.is_disconnected():
                    try:
                        event = await asyncio.wait_for(queue.get(), timeout=KEEPALIVE_SECONDS)
                    except TimeoutError:
                        yield ": keepalive\n\n"
                        continue
                    yield f"data: {json.dumps(event)}\n\n"
            finally:
                connector.stop(addresses, queue)

        return StreamingResponse(
            stream(), media_type="text/event-stream", headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"}
        )

    app.include_router(router)
