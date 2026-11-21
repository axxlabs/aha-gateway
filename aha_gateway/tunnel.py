# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Axxlabs Limited
"""Computers' tunnels: mutual key authentication, then routing of opaque frames (SPEC §6.2, §6.5)."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import WebSocket, WebSocketDisconnect
from pydantic import ValidationError

from . import push as push_relay
from .billing import Billing
from .certs import cert_valid, handshake_message, issue_cert, public_b64, sign, verify
from .hub import Hub
from .protocol import (
    E2E,
    FROM_COMPUTER,
    GATEWAY_FEATURES,
    MAX_FRAME_BYTES,
    CertIssued,
    CertRequest,
    DevE2E,
    DeviceStatus,
    DevPair,
    Hello,
    Notice,
    Pair,
    PairCode,
    PairStart,
    Ping,
    Pong,
    Push,
    Ready,
    Report,
    ReportResult,
    Revoke,
    b64,
)
from .reports import Reports

log = logging.getLogger("aha.gateway")

AUTH_TIMEOUT = 10


class WsConn:
    """One WebSocket, with serialised sends."""

    def __init__(self, ws: WebSocket) -> None:
        self.ws = ws
        self._lock = asyncio.Lock()

    async def send_frame(self, frame) -> None:
        async with self._lock:
            await self.ws.send_text(frame.model_dump_json(exclude_none=True))

    async def close(self, code: int = 1000) -> None:
        with contextlib.suppress(RuntimeError):
            await self.ws.close(code=code)


async def serve_tunnel(
    ws: WebSocket,
    hub: Hub,
    key: Ed25519PrivateKey,
    billing: Billing,
    vapid: push_relay.Vapid,
    http: httpx.AsyncClient,
    reports: Reports | None = None,
) -> None:
    await ws.accept()
    conn = WsConn(ws)
    gateway_public = public_b64(key)
    nonce = b64(os.urandom(32))
    await conn.send_frame(Hello(gateway=gateway_public, nonce=nonce, features=list(GATEWAY_FEATURES)))
    try:
        raw = await asyncio.wait_for(ws.receive_text(), timeout=AUTH_TIMEOUT)
        auth = FROM_COMPUTER.validate_json(raw)
    except (TimeoutError, ValidationError, WebSocketDisconnect, RuntimeError):
        await conn.close(4401)
        return
    if auth is None or auth.t != "auth" or not verify(auth.instance, handshake_message(nonce, auth.instance), auth.sig):
        log.info("tunnel rejected: bad authentication")
        await conn.close(4401)
        return
    if not await billing.active(auth.instance):
        await conn.send_frame(Notice(code="not_subscribed", detail="subscription not active"))
        await conn.close(4402)
        return
    instance = auth.instance
    routes = [c.device for c in auth.certs if cert_valid(c, gateway_public, instance)]
    rejected = [c.device for c in auth.certs if c.device not in routes]
    await conn.send_frame(Ready(sig=sign(key, handshake_message(auth.nonce)), routes=routes, rejected=rejected))
    await hub.attach_computer(conn, instance, set(routes))  # after Ready: it may send device statuses
    log.info("computer connected (%d devices, %d rejected)", len(routes), len(rejected))
    try:
        await _frames(conn, hub, key, instance, vapid, http, reports or Reports(None))
    finally:
        await hub.detach_computer(conn, instance)
        log.info("computer disconnected")


async def _frames(
    conn: WsConn,
    hub: Hub,
    key: Ed25519PrivateKey,
    instance: str,
    vapid: push_relay.Vapid,
    http: httpx.AsyncClient,
    reports: Reports,
) -> None:
    pending: set[asyncio.Task] = set()
    while True:
        try:
            raw = await conn.ws.receive_text()
        except (WebSocketDisconnect, RuntimeError):
            return
        if not hub.computer_frames.allow(instance):
            await conn.close(4429)
            return
        if len(raw) > MAX_FRAME_BYTES:
            await conn.close(4413)
            return
        try:
            frame = FROM_COMPUTER.validate_json(raw)
        except ValidationError:
            log.info("tunnel closed: invalid frame")
            await conn.close(4400)
            return
        comp = hub.computer(instance)
        if comp is None or comp.conn is not conn:
            return  # replaced by a newer connection
        match frame:
            case E2E():
                dconn = hub.device_conn(frame.dev, instance) if frame.dev in comp.devices else None
                if dconn is None:
                    await conn.send_frame(DeviceStatus(dev=frame.dev, online=False))
                else:
                    try:
                        await dconn.send_frame(DevE2E(box=frame.box))
                    except Exception:
                        await conn.send_frame(DeviceStatus(dev=frame.dev, online=False))
            case PairStart():
                try:
                    code = hub.pairing.create(instance)
                except RuntimeError:
                    await conn.send_frame(Notice(code="pairing_busy", detail="try again later"))
                    continue
                await conn.send_frame(PairCode(code=code, expires_in=600))
            case Pair():
                dconn = hub.pairing.device_for(frame.code, instance)
                if dconn is None:
                    await conn.send_frame(Notice(code="pair_gone", detail=frame.code))
                else:
                    await dconn.send_frame(DevPair(body=frame.body))
            case CertRequest():
                if not hub.cert_requests.allow(instance):
                    await conn.send_frame(Notice(code="cert_rate_limited", detail=frame.id))
                    continue
                # Only what there's a reason to sign: a device that joined this computer's live code (once), or
                # a renewal of a device already routed to it (SPEC §6.4).
                renewal = frame.device in comp.devices
                if not renewal and not (frame.code and hub.pairing.claim_cert(frame.code, instance)):
                    await conn.send_frame(Notice(code="cert_refused", detail=frame.id))
                    continue
                cert = issue_cert(key, frame.device, instance, frame.tag)
                comp.devices.add(frame.device)
                await conn.send_frame(CertIssued(id=frame.id, cert=cert))
            case Push():
                if not hub.pushes.allow(instance) or not push_relay.endpoint_allowed(frame.endpoint):
                    await conn.send_frame(Notice(code="push_refused"))
                    continue
                task = asyncio.create_task(push_relay.deliver(http, vapid, frame))
                pending.add(task)
                task.add_done_callback(pending.discard)
            case Revoke():
                await hub.revoke(frame.dev, instance)
            case Report():
                if reports.issues is None:
                    await conn.send_frame(ReportResult(id=frame.id, ok=False, code="reports_off"))
                elif not hub.reports.allow(instance) or not hub.reports_global.allow("all"):
                    await conn.send_frame(ReportResult(id=frame.id, ok=False, code="rate_limited"))
                else:
                    task = asyncio.create_task(_report(conn, reports, frame))
                    pending.add(task)
                    task.add_done_callback(pending.discard)
            case Ping():
                await conn.send_frame(Pong())
            case Pong() | None:  # None: a frame type this version doesn't know (SPEC §6.5)
                pass
            case _:
                await conn.close(4400)
                return


async def _report(conn: WsConn, reports: Reports, frame: Report) -> None:
    code = await reports.send(frame)
    with contextlib.suppress(Exception):
        await conn.send_frame(ReportResult(id=frame.id, ok=not code, code=code))
    log.info("problem report %s", "passed on" if not code else f"not sent ({code})")
