# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Axxlabs Limited
"""Certificates, rendezvous codes, rate limits, push rules and frame strictness (SPEC §6, §7)."""

import base64
import contextlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from pydantic import ValidationError

from aha_gateway.certs import cert_valid, issue_cert, needs_renewal, new_key, public_b64
from aha_gateway.config import Settings
from aha_gateway.device import origin_allowed
from aha_gateway.hub import RateLimiter
from aha_gateway.pairing import PairingCodes
from aha_gateway.protocol import FROM_COMPUTER, FROM_DEVICE, b64
from aha_gateway.push import Vapid, endpoint_allowed

ROOT = Path(__file__).resolve().parents[1]
TAG = b64(b"\x01" * 16)


def test_certificate_binds_device_instance_and_tag():
    gw, inst, dev = new_key(), public_b64(new_key()), public_b64(new_key())
    cert = issue_cert(gw, dev, inst, TAG, now=1000)
    assert cert_valid(cert, public_b64(gw), inst, now=2000)
    assert cert_valid(cert, public_b64(gw), None, now=2000)
    assert not cert_valid(cert, public_b64(gw), public_b64(new_key()), now=2000)  # other instance
    assert not cert_valid(cert, public_b64(new_key()), inst, now=2000)  # other gateway
    assert not cert_valid(cert, public_b64(gw), inst, now=cert.expires)  # expired
    forged = cert.model_copy(update={"tag": b64(b"\x02" * 16)})
    assert not cert_valid(forged, public_b64(gw), inst, now=2000)
    assert needs_renewal(cert, now=cert.expires - 10)


def test_rendezvous_codes_join_once_and_expire():
    codes = PairingCodes()
    code = codes.create("A", now=0)
    assert codes.join(code, "dev1", now=10) == "A"
    assert codes.join(code, "dev2", now=11) is None  # already taken
    code2 = codes.create("B", now=0)
    assert codes.join(code2, "dev", now=700) is None  # expired
    assert codes.join("ZZZ-ZZZ", "dev", now=1) is None


def test_new_code_replaces_the_old_one_for_the_same_computer():
    codes = PairingCodes()
    first = codes.create("A", now=0)
    codes.create("A", now=1)
    assert codes.join(first, "dev", now=2) is None


def test_rate_limit():
    rl = RateLimiter(rate=1, burst=2)
    assert rl.allow("k", now=0) and rl.allow("k", now=0)
    assert not rl.allow("k", now=0)
    assert rl.allow("k", now=1.5)


def test_push_endpoints_are_only_known_services_over_https():
    assert endpoint_allowed("https://fcm.googleapis.com/fcm/send/abc")
    assert endpoint_allowed("https://web.push.apple.com/QGuQyavXutnMH")
    assert endpoint_allowed("https://updates.push.services.mozilla.com/wpush/v2/x")
    for bad in (
        "http://fcm.googleapis.com/x",
        "https://evil.example/x",
        "https://fcm.googleapis.com.evil.example/x",
        "https://user:pw@fcm.googleapis.com/x",
        "https://fcm.googleapis.com:8443/x",
        "https://127.0.0.1/x",
        "https://169.254.169.254/latest/meta-data",
    ):
        assert not endpoint_allowed(bad), bad


def test_vapid_header_verifies(tmp_path):
    vapid = Vapid.load_or_create(tmp_path / "v.pem", "https://axxlabs.ai/aha/")
    auth = vapid.authorization("https://fcm.googleapis.com/fcm/send/x", now=1000)
    token = auth.split("t=")[1].split(",")[0]
    header, claims, sig = token.split(".")
    pad = lambda s: s + "=" * (-len(s) % 4)  # noqa: E731
    raw = base64.urlsafe_b64decode(pad(sig))
    der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    vapid.key.public_key().verify(der, f"{header}.{claims}".encode(), ec.ECDSA(hashes.SHA256()))
    assert json.loads(base64.urlsafe_b64decode(pad(claims)))["aud"] == "https://fcm.googleapis.com"
    assert (tmp_path / "v.pem").stat().st_mode & 0o777 == 0o600


def test_origin_check():
    s = Settings(signing_key_file=Path("/x"), public_url="http://x")
    assert origin_allowed(None, s)
    assert origin_allowed("http://127.0.0.1:5173", s)
    assert not origin_allowed("https://evil.example", s)


def test_frames_are_strict():
    with pytest.raises(ValidationError):
        FROM_DEVICE.validate_json('{"t":"e2e","box":"AAAA","dev":"x"}')  # devices can't name a target
    with pytest.raises(ValidationError):
        FROM_DEVICE.validate_json('{"t":"e2e","box":"not base64!"}')
    with pytest.raises(ValidationError):
        FROM_COMPUTER.validate_json('{"t":"push","endpoint":"http://x/","body":"AAAA"}')
    with pytest.raises(ValidationError):
        FROM_COMPUTER.validate_json('{"t":"pair","code":"AAA-AAA","body":{"BAD KEY":"x"}}')
    assert FROM_DEVICE.validate_json('{"t":"pair_hello","code":"7K3-QF9"}').code == "7K3-QF9"


def test_protocol_and_certs_are_shared_with_aha_local_llm():
    other = ROOT.parent / "aha-local-llm" / "aha_local"
    if not other.exists():
        pytest.skip("aha-local-llm not checked out next to aha-gateway")
    for name in ("protocol.py", "certs.py"):
        assert (ROOT / "aha_gateway" / name).read_text() == (other / name).read_text(), name


def test_random_frames_never_crash_the_parsers():
    import os
    import random

    rng = random.Random(7)
    seeds = [
        '{"t":"dev_auth","cert":{"v":2},"sig":"AAAA"}',
        '{"t":"e2e","box":"AAAA"}',
        '{"t":"pair_hello","code":"ABC-DEF"}',
        '{"t":"push","endpoint":"https://fcm.googleapis.com/x","body":"AAAA"}',
        '{"t":"cert_request","id":"1","device":"' + "A" * 43 + '=","tag":"' + "A" * 22 + '=="}',
    ]
    for _ in range(500):
        raw = bytearray(rng.choice(seeds).encode())
        for _ in range(rng.randint(1, 6)):
            i = rng.randrange(len(raw))
            raw[i : i + rng.randint(0, 5)] = os.urandom(rng.randint(0, 5))
        text = raw.decode("utf-8", "replace")
        for adapter in (FROM_DEVICE, FROM_COMPUTER):
            with contextlib.suppress(ValidationError):
                adapter.validate_json(text)


def test_outgoing_request_urls_are_not_logged(tmp_path):
    """Push endpoint URLs identify devices; httpx would log them at INFO (SPEC §6.7)."""
    import logging

    from aha_gateway.app import create_app
    from aha_gateway.config import Settings

    create_app(Settings(signing_key_file=tmp_path / "k", vapid_key_file=tmp_path / "v.pem", public_url="http://x"))
    assert logging.getLogger("httpx").getEffectiveLevel() >= logging.WARNING
    assert logging.getLogger("httpcore").getEffectiveLevel() >= logging.WARNING
