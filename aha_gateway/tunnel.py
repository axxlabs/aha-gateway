"""The computer's tunnel: handshake with mutual key authentication, then frames (SPEC §6.2, §6.3)."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os

from fastapi import WebSocket, WebSocketDisconnect
from pydantic import ValidationError

from .billing import Billing
from .certs import cert_valid, handshake_message, issue_cert, public_b64, sign, verify
from .protocol import (
    AUTH,
    TO_GATEWAY,
    Hello,
    Notice,
    Out,
    PairCode,
    PairStart,
    Ping,
    Pong,
    Ready,
    Renew,
    Renewed,
    Unpair,
    b64,
    frame_too_big,
)
from .relay import Relay

log = logging.getLogger("aha.gateway")

AUTH_TIMEOUT = 10
FRAME_RATE = 50  # frames per second per computer, burst 100


class Tunnel:
    def __init__(self, ws: WebSocket, instance: str, name: str) -> None:
        self.ws = ws
        self.instance = instance
        self.name = name
        self._send_lock = asyncio.Lock()

    async def send_frame(self, frame) -> None:
        async with self._send_lock:
            await self.ws.send_text(frame.model_dump_json(exclude_none=True))

    async def close(self, code: int = 1000) -> None:
        with contextlib.suppress(RuntimeError):
            await self.ws.close(code=code)


async def serve_tunnel(ws: WebSocket, relay: Relay, billing: Billing) -> None:
    await ws.accept()
    gateway_public = public_b64(relay.signing_key)
    nonce = b64(os.urandom(32))
    await ws.send_text(Hello(gateway=gateway_public, nonce=nonce).model_dump_json())

    try:
        raw = await asyncio.wait_for(ws.receive_text(), timeout=AUTH_TIMEOUT)
        auth = AUTH.validate_json(raw)
    except (TimeoutError, ValidationError, WebSocketDisconnect, RuntimeError):
        await _close(ws, 4401)
        return
    if not verify(auth.instance, handshake_message(nonce, auth.instance), auth.sig):
        log.info("tunnel rejected: bad signature")
        await _close(ws, 4401)
        return
    if not await billing.active(auth.instance):
        await ws.send_text(Notice(code="not_subscribed", detail="subscription not active").model_dump_json())
        await _close(ws, 4402)
        return

    tunnel = Tunnel(ws, auth.instance, auth.name)
    replaced = relay.router.attach(tunnel)
    if replaced is not None:
        await replaced.close(4409)
    routes, rejected = [], []
    for cert in auth.certs:
        if cert_valid(cert, gateway_public, auth.instance) and relay.router.add_route(
            cert.address, tunnel, cert.issued
        ):
            routes.append(cert.address)
        else:
            rejected.append(cert.address)
    await tunnel.send_frame(
        Ready(sig=sign(relay.signing_key, handshake_message(auth.nonce)), routes=routes, rejected=rejected)
    )
    log.info("computer connected (%d routes, %d rejected)", len(routes), len(rejected))

    try:
        await _frames(tunnel, relay, gateway_public)
    finally:
        relay.router.detach(tunnel)
        log.info("computer disconnected")


async def _frames(tunnel: Tunnel, relay: Relay, gateway_public: str) -> None:
    allowance, last = 100.0, asyncio.get_running_loop().time()
    while True:
        try:
            raw = await tunnel.ws.receive_text()
        except (WebSocketDisconnect, RuntimeError):
            return
        now = asyncio.get_running_loop().time()
        allowance = min(100.0, allowance + (now - last) * FRAME_RATE)
        last = now
        if allowance < 1:
            await tunnel.close(4429)
            return
        allowance -= 1
        if frame_too_big(raw):
            await tunnel.close(4413)
            return
        try:
            frame = TO_GATEWAY.validate_json(raw)
        except ValidationError:
            log.info("tunnel closed: invalid frame")
            await tunnel.close(4400)
            return
        await _dispatch(tunnel, relay, gateway_public, frame)


async def _dispatch(tunnel: Tunnel, relay: Relay, gateway_public: str, frame) -> None:
    match frame:
        case Out():
            await relay.outbound(tunnel, frame)
        case PairStart():
            try:
                code = relay.pairing.create(tunnel.instance)
            except RuntimeError:
                await tunnel.send_frame(Notice(code="pairing_busy", detail="try again later"))
                return
            await tunnel.send_frame(PairCode(code=code, expires_in=600))
        case Unpair():
            relay.router.remove_route(frame.address, tunnel)
        case Renew():
            if cert_valid(frame.cert, gateway_public, tunnel.instance) and relay.router.owns(
                frame.cert.address, tunnel
            ):
                cert = issue_cert(relay.signing_key, frame.cert.address, tunnel.instance)
                relay.router.add_route(cert.address, tunnel, cert.issued)
                await tunnel.send_frame(Renewed(cert=cert))
            else:
                await tunnel.send_frame(Notice(code="renew_refused", detail="certificate not renewable"))
        case Ping():
            await tunnel.send_frame(Pong())
        case Pong():
            pass


async def _close(ws: WebSocket, code: int) -> None:
    with contextlib.suppress(RuntimeError):
        await ws.close(code=code)
