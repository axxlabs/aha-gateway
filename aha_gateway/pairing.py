# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Axxlabs Limited
"""Rendezvous codes for QR pairing, in memory for at most 10 minutes (SPEC §6.4).

A code connects one pairing device to the computer that asked for it; the gateway only matches codes and
forwards the (public-key and MAC) messages of the pairing handshake. It can't complete a pairing itself: the
secret is in the QR code, which never reaches the gateway.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from typing import Any

ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no I, O, 0, 1
LIFETIME = 600
MAX_PENDING = 10_000


@dataclass
class Pending:
    instance: str
    expires: float
    device: Any = None  # the pairing device's connection, once it has joined
    created: float = field(default_factory=time.monotonic)


class PairingCodes:
    def __init__(self) -> None:
        self._codes: dict[str, Pending] = {}

    def create(self, instance: str, now: float | None = None) -> str:
        now = time.monotonic() if now is None else now
        self._sweep(now)
        if len(self._codes) >= MAX_PENDING:
            raise RuntimeError("too many pending pairing codes")
        # One live code per computer: a new request replaces the old one.
        self._codes = {c: p for c, p in self._codes.items() if p.instance != instance}
        while True:
            raw = "".join(secrets.choice(ALPHABET) for _ in range(6))
            code = f"{raw[:3]}-{raw[3:]}"
            if code not in self._codes:
                break
        self._codes[code] = Pending(instance, now + LIFETIME)
        return code

    def join(self, code: str, device: Any, now: float | None = None) -> str | None:
        """A device joins with a code: returns the instance, or None (unknown, expired or already taken)."""
        now = time.monotonic() if now is None else now
        self._sweep(now)
        pending = self._codes.get(code)
        if pending is None or pending.device is not None:
            return None
        pending.device = device
        return pending.instance

    def device_for(self, code: str, instance: str) -> Any:
        pending = self._codes.get(code)
        if pending is None or pending.instance != instance or pending.expires <= time.monotonic():
            return None
        return pending.device

    def drop(self, code: str) -> None:
        self._codes.pop(code, None)

    def drop_device(self, device: Any) -> None:
        self._codes = {c: p for c, p in self._codes.items() if p.device is not device}

    def _sweep(self, now: float) -> None:
        self._codes = {c: p for c, p in self._codes.items() if p.expires > now}
