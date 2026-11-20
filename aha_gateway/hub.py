# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Axxlabs Limited
"""The gateway's whole state: who is connected, and which device routes to which computer. Memory only.

Nothing here is ever written to disk or logged with identifiers (SPEC §6.7). Routes come from the binding
certificates computers present when they connect; certificates only route, they never grant trust (§6.4).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from dataclasses import dataclass, field
from typing import Protocol

from .pairing import PairingCodes

log = logging.getLogger("aha.gateway")


class Conn(Protocol):
    async def send_frame(self, frame) -> None: ...
    async def close(self, code: int = 1000) -> None: ...


class RateLimiter:
    """Token buckets keyed by anything (a connection, an IP, a computer), in memory."""

    def __init__(self, rate: float, burst: float) -> None:
        self.rate, self.burst = rate, burst
        self._buckets: dict[object, tuple[float, float]] = {}

    def allow(self, key: object, cost: float = 1, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        if len(self._buckets) > 50_000:
            self._buckets = {k: v for k, v in self._buckets.items() if now - v[1] < 300}
        tokens, last = self._buckets.get(key, (self.burst, now))
        tokens = min(self.burst, tokens + (now - last) * self.rate)
        if tokens < cost:
            self._buckets[key] = (tokens, now)
            return False
        self._buckets[key] = (tokens - cost, now)
        return True


@dataclass
class Computer:
    conn: Conn
    instance: str
    devices: set[str] = field(default_factory=set)  # device keys whose certificates it presented or was issued


class Hub:
    def __init__(self) -> None:
        self.computers: dict[str, Computer] = {}  # instance → computer
        self.devices: dict[str, tuple[Conn, str]] = {}  # device key → (connection, instance)
        self.pairing = PairingCodes()
        self.device_frames = RateLimiter(rate=10, burst=40)  # per device connection
        self.computer_frames = RateLimiter(rate=200, burst=400)  # per computer
        self.pair_attempts = RateLimiter(rate=5 / 60, burst=5)  # per client IP
        self.pair_attempts_global = RateLimiter(rate=100 / 60, burst=100)
        self.cert_requests = RateLimiter(rate=30 / 60, burst=30)  # per computer
        self.pushes = RateLimiter(rate=2, burst=60)  # per computer
        self.conns_per_ip = RateLimiter(rate=1, burst=30)

    # -- computers

    async def attach_computer(self, conn: Conn, instance: str, devices: set[str]) -> None:
        old = self.computers.get(instance)
        self.computers[instance] = Computer(conn, instance, set(devices))
        if old is not None:
            with contextlib.suppress(Exception):
                await old.conn.close(4409)
        # Devices already connected for this instance: tell them, and drop any the computer no longer lists.
        for dev, (dconn, inst) in list(self.devices.items()):
            if inst != instance:
                continue
            if dev in devices:
                await _safe_send(dconn, _computer_status(True))
                await _safe_send(conn, _device_status(dev, True))
            else:
                await _safe_close(dconn, 4403)

    async def detach_computer(self, conn: Conn, instance: str) -> None:
        current = self.computers.get(instance)
        if current is None or current.conn is not conn:
            return
        del self.computers[instance]
        for _dev, (dconn, inst) in list(self.devices.items()):
            if inst == instance:
                await _safe_send(dconn, _computer_status(False))

    def computer(self, instance: str) -> Computer | None:
        return self.computers.get(instance)

    # -- devices

    async def attach_device(self, conn: Conn, dev: str, instance: str) -> bool | None:
        """Returns whether the computer is online; None if the computer is online and doesn't list the device."""
        comp = self.computers.get(instance)
        if comp is not None and dev not in comp.devices:
            return None
        old = self.devices.get(dev)
        self.devices[dev] = (conn, instance)
        if old is not None and old[0] is not conn:
            await _safe_close(old[0], 4409)
        if comp is not None:
            await _safe_send(comp.conn, _device_status(dev, True))
        return comp is not None

    async def detach_device(self, conn: Conn, dev: str) -> None:
        current = self.devices.get(dev)
        if current is None or current[0] is not conn:
            return
        del self.devices[dev]
        comp = self.computers.get(current[1])
        if comp is not None:
            await _safe_send(comp.conn, _device_status(dev, False))

    def device_conn(self, dev: str, instance: str) -> Conn | None:
        entry = self.devices.get(dev)
        if entry is None or entry[1] != instance:
            return None
        return entry[0]

    async def revoke(self, dev: str, instance: str) -> None:
        comp = self.computers.get(instance)
        if comp is not None:
            comp.devices.discard(dev)
        conn = self.device_conn(dev, instance)
        if conn is not None:
            await _safe_close(conn, 4403)

    def counts(self) -> dict[str, int]:
        return {"computers": len(self.computers), "devices": len(self.devices)}


def _computer_status(online: bool):
    from .protocol import ComputerStatus

    return ComputerStatus(online=online)


def _device_status(dev: str, online: bool):
    from .protocol import DeviceStatus

    return DeviceStatus(dev=dev, online=online)


async def _safe_send(conn: Conn, frame) -> None:
    with contextlib.suppress(Exception):
        await asyncio.wait_for(conn.send_frame(frame), timeout=5)


async def _safe_close(conn: Conn, code: int) -> None:
    with contextlib.suppress(Exception):
        await conn.close(code)
