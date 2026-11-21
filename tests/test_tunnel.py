# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Axxlabs Limited
"""The gateway end to end: tunnels, devices, pairing rendezvous, routing, revocation, and that it keeps and
logs nothing (SPEC §6, §7, §11.6)."""

import asyncio
import logging

import httpx
import pytest
import websockets

from aha_gateway.certs import device_message, gateway_proof_message, new_key, public_b64, sign, verify
from aha_gateway.protocol import (
    E2E,
    CertIssued,
    CertRequest,
    ComputerStatus,
    DevAuth,
    DevE2E,
    DeviceReady,
    DevPair,
    Notice,
    Pair,
    PairHello,
    PairStart,
    Ping,
    Push,
    Revoke,
    b64,
)

from .conftest import Computer, Device

TAG = b64(b"\x07" * 16)
NONCE = b64(b"\x09" * 32)
BOX = b64(b"CANARY-BOX-" + b"x" * 64)


async def paired_device(gateway, computer: Computer) -> tuple[Device, object]:
    """A device paired through the rendezvous, with a certificate from the gateway."""
    await computer.send(PairStart())
    code = (await computer.recv()).code
    dev = Device(gateway)
    await dev.open()
    await dev.send(PairHello(code=code, nonce=NONCE))
    ready = await dev.recv()
    assert isinstance(ready, DeviceReady) and verify(dev.hello.gateway, gateway_proof_message(NONCE), ready.sig)
    hello = await computer.recv()
    assert isinstance(hello, Pair) and hello.code == code and hello.body == {"t": "hello"}
    await computer.send(Pair(code=code, body={"t": "bundle", "ikc": "AAAA"}))
    assert (await dev.recv()) == DevPair(body={"t": "bundle", "ikc": "AAAA"})
    await dev.send(DevPair(body={"t": "finish", "mac": "BBBB"}))
    assert (await computer.recv()).body == {"t": "finish", "mac": "BBBB"}
    await computer.send(CertRequest(id="r1", device=dev.dev, tag=TAG, code=code))
    issued = await computer.recv()
    assert (
        isinstance(issued, CertIssued) and issued.cert.device == dev.dev and issued.cert.instance == computer.instance
    )
    await dev.ws.close()
    computer.certs.append(issued.cert)
    return dev, issued.cert


async def test_computer_handshake_and_tampered_signature(gateway, computer):
    ready = await computer.connect()
    assert ready.routes == []
    other = Computer(gateway)
    with pytest.raises(websockets.ConnectionClosed) as e:
        await other.connect(tamper=True)
    assert e.value.rcvd.code == 4401


async def test_pairing_rendezvous_then_encrypted_frames_both_ways(gateway, computer):
    await computer.connect()
    dev, cert = await paired_device(gateway, computer)
    phone = Device(gateway)
    phone.key, phone.dev = dev.key, dev.dev
    ready = await phone.auth(cert)
    assert ready == DeviceReady(online=True)
    status = await computer.recv(skip_status=False)
    assert status.t == "device" and status.dev == phone.dev and status.online
    await phone.send(DevE2E(box=BOX))
    got = await computer.recv()
    assert got == E2E(dev=phone.dev, box=BOX)
    await computer.send(E2E(dev=phone.dev, box=BOX))
    assert (await phone.recv()) == DevE2E(box=BOX)


async def test_a_code_works_once_and_unknown_codes_are_refused(gateway, computer):
    await computer.connect()
    await computer.send(PairStart())
    code = (await computer.recv()).code
    first, second = Device(gateway), Device(gateway)
    await first.open()
    await first.send(PairHello(code=code))
    await computer.recv()
    await second.open()
    await second.send(PairHello(code=code))
    assert (await second.recv()) == Notice(code="pair_unknown")
    assert await second.closed_with() == 4404
    third = Device(gateway)
    await third.open()
    await third.send(PairHello(code="ZZZ-ZZZ"))
    assert (await third.recv()).code == "pair_unknown"


async def test_bad_device_signature_and_foreign_certificates_are_refused(gateway, computer):
    await computer.connect()
    _, cert = await paired_device(gateway, computer)
    thief = Device(gateway)  # has the certificate but not the key
    await thief.open()
    from aha_gateway.certs import device_message, sign
    from aha_gateway.protocol import DevAuth

    await thief.send(DevAuth(cert=cert, sig=sign(thief.key, device_message(thief.hello.nonce, cert.device))))
    assert await thief.closed_with() == 4401


async def test_revocation_closes_the_device_and_keeps_it_out(gateway, computer):
    await computer.connect()
    dev, cert = await paired_device(gateway, computer)
    phone = Device(gateway)
    phone.key, phone.dev = dev.key, dev.dev
    await phone.auth(cert)
    await computer.send(Revoke(dev=phone.dev))
    assert await phone.closed_with() == 4403
    # After a reconnect without that certificate the computer no longer lists it, so it can't come back.
    await computer.close()
    computer.certs = []
    await computer.connect()
    again = Device(gateway)
    again.key, again.dev = dev.key, dev.dev
    await again.open()
    from aha_gateway.certs import device_message, sign
    from aha_gateway.protocol import DevAuth

    await again.send(DevAuth(cert=cert, sig=sign(again.key, device_message(again.hello.nonce, again.dev))))
    assert await again.closed_with() == 4403


async def test_offline_computer_and_status_changes(gateway, computer):
    await computer.connect()
    dev, cert = await paired_device(gateway, computer)
    await computer.close()
    await asyncio.sleep(0.1)
    phone = Device(gateway)
    phone.key, phone.dev = dev.key, dev.dev
    assert (await phone.auth(cert)) == DeviceReady(online=False)
    await phone.send(DevE2E(box=BOX))
    assert (await phone.recv()) == ComputerStatus(online=False)
    await computer.connect()
    assert (await phone.recv()) == ComputerStatus(online=True)


async def test_frames_to_absent_or_foreign_devices_are_not_delivered(gateway, computer):
    await computer.connect()
    dev, _ = await paired_device(gateway, computer)
    await computer.send(E2E(dev=dev.dev, box=BOX))  # paired but not connected
    status = await computer.recv(skip_status=False)
    assert status.t == "device" and status.dev == dev.dev and not status.online
    other = Computer(gateway, "Other")
    await other.connect()
    await other.send(E2E(dev=dev.dev, box=BOX))  # not its device
    status = await other.recv(skip_status=False)
    assert status.t == "device" and not status.online


async def test_browsers_from_other_sites_are_refused(gateway):
    evil = Device(gateway)
    with pytest.raises((websockets.InvalidStatus, websockets.ConnectionClosed)):
        await evil.open(origin="https://evil.example")
    ok = Device(gateway)
    assert (await ok.open(origin="http://127.0.0.1:5173")).vapid


async def test_pushes_only_to_known_services(gateway, computer):
    await computer.connect()
    await computer.send(Push(endpoint="https://evil.example/x", body="AAAA"))
    assert (await computer.recv()) == Notice(code="push_refused")


async def test_the_gateway_serves_no_pages(gateway):
    async with httpx.AsyncClient(base_url=gateway.url) as http:
        info = (await http.get("/.well-known/aha-gateway.json")).json()
        assert info["protocol"] == 2 and info["vapid"] and info["source"].startswith("https://")
        for path in ("/", "/test", "/index.html", "/app"):
            assert (await http.get(path)).status_code == 404


async def test_nothing_is_written_and_nothing_identifying_is_logged(gateway, computer, tmp_path, caplog):
    """SPEC §6.7, §11.6: relaying writes no file and logs no device ids, tags, certificates or boxes."""
    caplog.set_level(logging.DEBUG)
    await computer.connect()
    before = {p: p.stat().st_mtime for p in tmp_path.rglob("*")}
    dev, cert = await paired_device(gateway, computer)
    phone = Device(gateway)
    phone.key, phone.dev = dev.key, dev.dev
    await phone.auth(cert)
    await phone.send(DevE2E(box=BOX))
    await computer.recv()
    await computer.send(E2E(dev=phone.dev, box=BOX))
    await phone.recv()
    after = {p: p.stat().st_mtime for p in tmp_path.rglob("*")}
    assert after == before
    logged = "\n".join(
        r.getMessage() for r in caplog.records if r.name.startswith(("aha.gateway", "uvicorn", "fastapi", "starlette"))
    )
    assert "connected" in logged
    for secret in ("CANARY", phone.dev, TAG, cert.sig, computer.instance):
        assert secret not in logged


async def test_a_device_must_authenticate_before_anything_else(gateway, computer):
    await computer.connect()
    dev = Device(gateway)
    await dev.open()
    await dev.send(DevE2E(box=BOX))  # no dev_auth first
    assert await dev.closed_with() == 4401


async def test_the_gateway_proves_its_key_to_devices(gateway, computer):
    """A device's nonce comes back signed with the pinned key (SPEC §6.3, §9.2)."""
    await computer.connect()
    dev, cert = await paired_device(gateway, computer)
    computer2 = Computer(gateway)
    computer2.key, computer2.instance, computer2.certs = computer.key, computer.instance, [cert]
    await computer.close()
    await computer2.connect()
    again = Device(gateway)
    again.key, again.dev = dev.key, dev.dev
    hello = await again.open()
    await again.send(DevAuth(cert=cert, sig=sign(again.key, device_message(hello.nonce, again.dev)), nonce=NONCE))
    ready = await again.recv()
    assert ready.online and verify(hello.gateway, gateway_proof_message(NONCE), ready.sig)
    assert not verify(hello.gateway, gateway_proof_message(b64(b"\x01" * 32)), ready.sig)


async def test_certificates_only_for_a_joined_code_or_a_renewal(gateway, computer):
    await computer.connect()
    stranger = new_key()
    await computer.send(CertRequest(id="x1", device=public_b64(stranger), tag=TAG))
    refused = await computer.recv()
    assert refused.t == "notice" and refused.code == "cert_refused"
    await computer.send(PairStart())
    code = (await computer.recv()).code
    await computer.send(CertRequest(id="x2", device=public_b64(stranger), tag=TAG, code=code))
    assert (await computer.recv()).code == "cert_refused"  # nobody joined the code yet
    dev, _ = await paired_device(gateway, computer)  # one certificate for its code...
    await computer.send(CertRequest(id="x3", device=public_b64(stranger), tag=TAG, code=code))
    assert (await computer.recv()).code == "cert_refused"  # ...an old code gives nothing
    await computer.send(CertRequest(id="x4", device=dev.dev, tag=TAG))  # renewal of a routed device
    renewed = await computer.recv()
    assert isinstance(renewed, CertIssued) and renewed.cert.device == dev.dev


async def test_unknown_frame_types_are_ignored_not_fatal(gateway, computer):
    """Newer and older versions can talk to each other (SPEC §6.5)."""
    await computer.connect()
    await computer.ws.send('{"t": "from_the_future", "x": 1}')
    await computer.send(Ping())
    assert (await computer.recv()).t == "pong"
    await computer.ws.send('{"t": "e2e", "dev": "not a key", "box": "AAAA"}')  # a known type, malformed: closes
    with pytest.raises(websockets.ConnectionClosed):
        await computer.recv()


async def test_healthz_says_nothing_about_who_is_connected(gateway, computer):
    await computer.connect()
    async with httpx.AsyncClient() as c:
        assert (await c.get(f"{gateway.url}/healthz")).json() == {"ok": True}
