# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Axxlabs Limited
"""The gateway app (SPEC §7). It serves no web pages or scripts: only the two WebSocket endpoints, the
public key information and a health check (§7.1, §9.1)."""

from __future__ import annotations

import contextlib
import logging

import httpx
from fastapi import FastAPI, WebSocket
from fastapi.responses import JSONResponse

from . import __version__
from .billing import Billing, make_billing
from .certs import load_or_create_key, public_b64
from .config import Settings
from .device import serve_device
from .hub import Hub
from .protocol import PROTOCOL_VERSION
from .push import Vapid
from .tunnel import serve_tunnel

log = logging.getLogger("aha.gateway")


def create_app(settings: Settings, billing: Billing | None = None) -> FastAPI:
    key = load_or_create_key(settings.signing_key_file)
    vapid = Vapid.load_or_create(settings.vapid_key_file, settings.vapid_subject)
    hub = Hub()
    billing = billing or make_billing(settings.billing)
    http = httpx.AsyncClient(timeout=10, follow_redirects=False, headers={"User-Agent": "aha-gateway"})

    @contextlib.asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        await http.aclose()

    app = FastAPI(
        title="aha gateway", version=__version__, docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan
    )
    app.state.hub = hub

    @app.websocket("/v1/tunnel")
    async def tunnel(ws: WebSocket) -> None:
        await serve_tunnel(ws, hub, key, billing, vapid, http)

    @app.websocket("/v1/device")
    async def device(ws: WebSocket) -> None:
        await serve_device(ws, hub, key, settings, vapid.public_b64url)

    @app.get("/.well-known/aha-gateway.json")
    def well_known() -> JSONResponse:
        ws_base = settings.public_url.rstrip("/").replace("http", "ws", 1)
        return JSONResponse(
            {
                "gateway": public_b64(key),
                "vapid": vapid.public_b64url,
                "version": __version__,
                "protocol": PROTOCOL_VERSION,
                "source": settings.source_url,
                "licence": "AGPL-3.0-or-later",
                "tunnel": ws_base + "/v1/tunnel",
                "device": ws_base + "/v1/device",
            },
            headers={"Access-Control-Allow-Origin": "*"},
        )

    @app.get("/healthz")
    def healthz() -> JSONResponse:
        return JSONResponse({"ok": True, **hub.counts()})

    return app
