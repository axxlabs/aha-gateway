"""The gateway app (SPEC §7)."""

from __future__ import annotations

import importlib
import logging

from fastapi import FastAPI, WebSocket
from fastapi.responses import JSONResponse

from . import __version__
from .billing import Billing, make_billing
from .certs import load_or_create_key, public_b64
from .config import Settings
from .pairing import PairingCodes
from .relay import Relay
from .router import Router
from .tunnel import serve_tunnel

log = logging.getLogger("aha.gateway")


def staging_available() -> bool:
    """The simulator is mounted only when its package is present, i.e. in a staging build (SPEC §7.4)."""
    try:
        importlib.import_module("aha_gateway.staging")
    except ImportError:
        return False
    return True


def create_app(settings: Settings, billing: Billing | None = None, staging: bool | None = None) -> FastAPI:
    key = load_or_create_key(settings.signing_key_file)
    relay = Relay(key, Router(), PairingCodes())
    billing = billing or make_billing(settings.billing)
    app = FastAPI(title="aha gateway", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.relay = relay

    @app.websocket("/v1/tunnel")
    async def tunnel(ws: WebSocket) -> None:
        await serve_tunnel(ws, relay, billing)

    @app.get("/.well-known/aha-gateway.json")
    def well_known() -> JSONResponse:
        return JSONResponse(
            {
                "gateway": public_b64(key),
                "version": __version__,
                "protocol": 1,
                "tunnel": settings.public_url.rstrip("/").replace("http", "ws", 1) + "/v1/tunnel",
            }
        )

    @app.get("/healthz")
    def healthz() -> JSONResponse:
        return JSONResponse({"ok": True, **relay.router.counts()})

    if staging if staging is not None else staging_available():
        from .staging import mount

        mount(app, relay, settings)
        log.warning("staging build: chat simulator mounted at /test")
    return app
