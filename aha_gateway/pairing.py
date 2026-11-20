# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Axxlabs Limited
"""Pairing codes, held in memory for at most 10 minutes (SPEC §6.4)."""

from __future__ import annotations

import re
import secrets
import time
from dataclasses import dataclass

ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no I, O, 0, 1
LIFETIME = 600
MAX_PENDING = 10_000
PAIR_PATTERN = re.compile(r"^\s*pair\s+([A-Za-z2-9]{3})-?([A-Za-z2-9]{3})\s*$", re.I)


@dataclass
class Pending:
    instance: str
    expires: float


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

    def redeem(self, code: str, now: float | None = None) -> str | None:
        """Single use: returns the instance the code was issued to, or None."""
        now = time.monotonic() if now is None else now
        self._sweep(now)
        pending = self._codes.pop(code.upper(), None)
        return pending.instance if pending else None

    def _sweep(self, now: float) -> None:
        self._codes = {c: p for c, p in self._codes.items() if p.expires > now}


def parse_pair_message(text: str) -> str | None:
    """'PAIR 7K3-QF9' (any case, dash optional) → '7K3-QF9'."""
    m = PAIR_PATTERN.match(text or "")
    return f"{m.group(1)}-{m.group(2)}".upper() if m else None
