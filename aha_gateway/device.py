# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Axxlabs Limited
"""Devices' connections: certificate + signature authentication, or joining a pairing (SPEC §6.3, §6.4)."""

from __future__ import annotations

import asyncio
import logging
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import WebSocket, WebSocketDisconnect
from pydantic import ValidationError

from .certs import cert_valid, device_message, gateway_proof_message, public_b64, sign, verify
from .config import Settings
from .hub import Hub
from .protocol import (
    E2E,
    FROM_DEVICE,
    GATEWAY_FEATURES,
    MAX_FRAME_BYTES,
    ComputerStatus,
    DevAuth,
    DevE2E,
    DeviceReady,
    DevPair,
    Hello,
    Notice,
    Pair,
    PairHello,
    Ping,
    Pong,
    b64,
)
from .tunnel import WsConn

log = logging.getLogger("aha.gateway")

AUTH_TIMEOUT = 10


def origin_allowed(origin: str | None, settings: Settings) -> bool:
    """Browsers must come from the app's origin (no cross-site WebSocket use); non-browser clients send none."""
    return origin is None or origin in settings.app_origins


async def serve_device(ws: WebSocket, hub: Hub, key: Ed25519PrivateKey, settings: Settings, vapid_public: str) -> None:
    client_ip = ws.client.host if ws.client else ""
    if not origin_allowed(ws.headers.get("origin"), settings) or not hub.conns_per_ip.allow(("ip", client_ip)):
        await ws.close(code=4403)
        return
    await ws.accept()
    conn = WsConn(ws)
    gateway_public = public_b64(key)
    nonce = b64(os.urandom(32))
    await conn.send_frame(
        Hello(gateway=gateway_public, nonce=nonce, vapid=vapid_public, features=list(GATEWAY_FEATURES))
    )
    try:
        raw = await asyncio.wait_for(ws.receive_text(), timeout=AUTH_TIMEOUT)
        first = FROM_DEVICE.validate_json(raw)
    except (TimeoutError, ValidationError, WebSocketDisconnect, RuntimeError):
        await conn.close(4401)
        return
    match first:
        case DevAuth():
            await _authenticated(conn, hub, key, gateway_public, nonce, first)
        case PairHello():
            await _pairing(conn, hub, key, client_ip, first)
        case _:
            await conn.close(4401)


def _proof(key: Ed25519PrivateKey, device_nonce: str | None) -> str | None:
    """The gateway proves it holds the key the device pinned (SPEC §6.3)."""
    return sign(key, gateway_proof_message(device_nonce)) if device_nonce else None


async def _authenticated(
    conn: WsConn, hub: Hub, key: Ed25519PrivateKey, gateway_public: str, nonce: str, auth: DevAuth
) -> None:
    dev = auth.cert.device
    if not cert_valid(auth.cert, gateway_public) or not verify(dev, device_message(nonce, dev), auth.sig):
        log.info("device rejected: bad authentication")
        await conn.close(4401)
        return
    instance = auth.cert.instance
    online = await hub.attach_device(conn, dev, instance)
    if online is None:  # the computer is connected and doesn't list this device: revoked
        await conn.close(4403)
        return
    await conn.send_frame(DeviceReady(online=online, sig=_proof(key, auth.nonce)))
    try:
        while True:
            try:
                raw = await conn.ws.receive_text()
            except (WebSocketDisconnect, RuntimeError):
                return
            if not hub.device_frames.allow(conn) or len(raw) > MAX_FRAME_BYTES:
                await conn.close(4429)
                return
            try:
                frame = FROM_DEVICE.validate_json(raw)
            except ValidationError:
                await conn.close(4400)
                return
            match frame:
                case DevE2E():
                    comp = hub.computer(instance)
                    if comp is None or dev not in comp.devices:
                        await conn.send_frame(ComputerStatus(online=False))
                    else:
                        await comp.conn.send_frame(E2E(dev=dev, box=frame.box))
                case Ping():
                    await conn.send_frame(Pong())
                case Pong() | None:  # None: a frame type this version doesn't know (SPEC §6.5)
                    pass
                case _:
                    await conn.close(4400)
                    return
    finally:
        await hub.detach_device(conn, dev)


async def _pairing(conn: WsConn, hub: Hub, key: Ed25519PrivateKey, client_ip: str, hello: PairHello) -> None:
    code = hello.code
    if not hub.pair_attempts.allow(("pair", client_ip)) or not hub.pair_attempts_global.allow("pair"):
        await conn.send_frame(Notice(code="pair_rate_limited"))
        await conn.close(4429)
        return
    instance = hub.pairing.join(code, conn)
    comp = hub.computer(instance) if instance else None
    if comp is None:
        await conn.send_frame(Notice(code="pair_unknown"))
        await conn.close(4404)
        return
    if hello.nonce:
        await conn.send_frame(DeviceReady(online=True, sig=_proof(key, hello.nonce)))
    await comp.conn.send_frame(Pair(code=code, body={"t": "hello"}))
    try:
        while True:
            try:
                raw = await asyncio.wait_for(conn.ws.receive_text(), timeout=600)
            except (TimeoutError, WebSocketDisconnect, RuntimeError):
                return
            if not hub.device_frames.allow(conn) or len(raw) > 64_000:
                await conn.close(4429)
                return
            try:
                frame = FROM_DEVICE.validate_json(raw)
            except ValidationError:
                await conn.close(4400)
                return
            match frame:
                case DevPair():
                    comp = hub.computer(instance)
                    if comp is None:
                        await conn.send_frame(Notice(code="pair_unknown"))
                        return
                    await comp.conn.send_frame(Pair(code=code, body=frame.body))
                case Ping():
                    await conn.send_frame(Pong())
                case None:
                    pass
                case _:
                    await conn.close(4400)
                    return
    finally:
        hub.pairing.drop(code)
