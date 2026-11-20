# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Axxlabs Limited
"""Push relay (SPEC §6.6, §7.1): POST an already-encrypted Web Push payload, signed with our VAPID key.

The computer encrypts the payload to the device (RFC 8291) and authenticates its content with the push key
(AHA-PQ), so the gateway can't read or forge what the notification says. The gateway only adds VAPID
(RFC 8292) and talks to the push service, which keeps the computer's address private. Only the known push
services are reachable, over HTTPS, without redirects (no request forgery towards anything else).
"""

from __future__ import annotations

import base64
import json
import logging
import os
import time
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from .protocol import Push, unb64

log = logging.getLogger("aha.gateway")

PUSH_HOSTS = ("fcm.googleapis.com", "updates.push.services.mozilla.com", "web.push.apple.com")
PUSH_SUFFIXES = (".push.apple.com", ".notify.windows.com", ".push.services.mozilla.com")


def endpoint_allowed(endpoint: str) -> bool:
    try:
        parts = urlsplit(endpoint)
    except ValueError:
        return False
    host = (parts.hostname or "").lower()
    return (
        parts.scheme == "https"
        and not parts.username
        and not parts.password
        and parts.port in (None, 443)
        and (host in PUSH_HOSTS or host.endswith(PUSH_SUFFIXES))
    )


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class Vapid:
    def __init__(self, key: ec.EllipticCurvePrivateKey, subject: str) -> None:
        self.key = key
        self.subject = subject
        point = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        self.public_b64url = _b64url(point)

    @classmethod
    def load_or_create(cls, path: Path, subject: str) -> Vapid:
        if path.exists():
            key = serialization.load_pem_private_key(path.read_bytes(), password=None)
            if not isinstance(key, ec.EllipticCurvePrivateKey):
                raise SystemExit("VAPID key must be a P-256 private key")
        else:
            key = ec.generate_private_key(ec.SECP256R1())
            path.parent.mkdir(parents=True, exist_ok=True)
            pem = key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(pem)
        return cls(key, subject)

    def authorization(self, endpoint: str, now: int | None = None) -> str:
        parts = urlsplit(endpoint)
        now = int(time.time()) if now is None else now
        header = _b64url(json.dumps({"typ": "JWT", "alg": "ES256"}, separators=(",", ":")).encode())
        claims = _b64url(
            json.dumps(
                {"aud": f"{parts.scheme}://{parts.netloc}", "exp": now + 12 * 3600, "sub": self.subject},
                separators=(",", ":"),
            ).encode()
        )
        signing_input = f"{header}.{claims}".encode()
        r, s = decode_dss_signature(self.key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return f"vapid t={header}.{claims}.{_b64url(sig)}, k={self.public_b64url}"


async def deliver(client: httpx.AsyncClient, vapid: Vapid, push: Push) -> int:
    """POST one push. Returns the HTTP status (0 when not attempted or on a network error)."""
    if not endpoint_allowed(push.endpoint):
        return 0
    headers = {
        "Authorization": vapid.authorization(push.endpoint),
        "Content-Encoding": "aes128gcm",
        "Content-Type": "application/octet-stream",
        "TTL": str(push.ttl),
        "Urgency": push.urgency,
    }
    try:
        r = await client.post(push.endpoint, content=unb64(push.body), headers=headers)
    except httpx.HTTPError:
        return 0
    return r.status_code
