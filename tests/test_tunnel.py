"""Tunnel handshake, pairing and relaying, end to end over real sockets (SPEC §6, §11.5–11.8)."""

import asyncio
import logging

import pytest
import websockets

from aha_gateway.certs import issue_cert, new_key
from aha_gateway.protocol import (
    In,
    Notice,
    Out,
    PairCode,
    Paired,
    PairStart,
    Ping,
    Pong,
    Renew,
    Renewed,
    Typing,
    Unpair,
)

from .conftest import Computer, Phone


async def pair(computer: Computer, phone: Phone):
    await computer.send(PairStart())
    code = await computer.recv()
    assert isinstance(code, PairCode)
    r = await phone.say(f"PAIR {code.code}")
    assert r.status_code == 200
    paired = await computer.recv()
    assert isinstance(paired, Paired)
    computer.certs.append(paired.cert)
    reply = await phone.receive()
    assert f"Paired with {computer.name}" in reply["html"]
    return paired.cert


async def test_mutual_handshake(computer):
    ready = await computer.connect()
    assert ready.routes == []
    await computer.send(Ping())
    assert isinstance(await computer.recv(), Pong)


async def test_wrong_pin_is_detected_by_the_computer(computer):
    with pytest.raises(AssertionError, match="pin"):
        await computer.connect(pin="AAAA")


async def test_bad_signature_is_rejected(computer):
    with pytest.raises((websockets.ConnectionClosed, ValueError)):
        await computer.connect(tamper=True)


async def test_pairing_then_messages_flow_both_ways(gateway, computer, phone):
    await computer.connect()
    cert = await pair(computer, phone)
    assert cert.address == "sim:+447900000001"

    await phone.say("hello there")
    inbound = await computer.recv()
    assert isinstance(inbound, In) and inbound.text == "hello there" and inbound.sender == cert.address

    await computer.send(
        Out(id="r1", to=cert.address, text="*Hi* Fe", buttons=[{"id": "ap-1-yes", "label": "✅ Approve"}])
    )
    event = await phone.receive()
    assert event["html"] == "<strong>Hi</strong> Fe"
    assert event["buttons"] == [{"id": "ap-1-yes", "label": "✅ Approve"}]

    await phone.say("✅ Approve", button="ap-1-yes")
    pressed = await computer.recv()
    assert pressed.button == "ap-1-yes"


async def test_typing_reaches_the_phone_only_for_own_numbers(gateway, computer, phone):
    await computer.connect()
    cert = await pair(computer, phone)
    await computer.send(Typing(to=cert.address))
    assert await phone.receive() == {"type": "typing", "to": "+447900000001", "on": True}
    await computer.send(Typing(to="sim:+447900000002"))  # not this computer's number: dropped
    await computer.send(Typing(to=cert.address, on=False))
    assert await phone.receive() == {"type": "typing", "to": "+447900000001", "on": False}


async def test_routes_come_back_from_certificates_after_reconnect(gateway, computer, phone):
    await computer.connect()
    await pair(computer, phone)
    await computer.close()
    await asyncio.sleep(0.1)
    await phone.say("anyone there?")
    assert "No aha computer is connected" in (await phone.receive())["html"]

    ready = await computer.connect()
    assert ready.routes == ["sim:+447900000001"]
    await phone.say("back?")
    assert (await computer.recv()).text == "back?"


async def test_certificate_for_another_computer_is_rejected(gateway, computer):
    stolen = issue_cert(gateway.relay.signing_key, "sim:+447900000009", "AAAA" + computer.instance[4:])
    computer.certs = [stolen]
    ready = await computer.connect()
    assert ready.routes == [] and ready.rejected == ["sim:+447900000009"]


async def test_certificate_from_another_gateway_is_rejected(computer):
    forged = issue_cert(new_key(), "sim:+447900000009", computer.instance)
    computer.certs = [forged]
    ready = await computer.connect()
    assert ready.rejected == ["sim:+447900000009"]


async def test_newest_pairing_takes_over_the_address(gateway, phone):
    first, second = Computer(gateway, "First"), Computer(gateway, "Second")
    await first.connect()
    await second.connect()
    await pair(first, phone)
    await second.send(PairStart())
    code = await second.recv()
    await phone.say(f"PAIR {code.code}")
    assert isinstance(await second.recv(), Paired)
    await phone.receive()
    await phone.say("who gets this?")
    assert (await second.recv()).text == "who gets this?"


async def test_computer_cannot_message_an_address_it_does_not_hold(gateway, computer, phone):
    await computer.connect()
    await computer.send(Out(id="x", to="sim:+447900000001", text="spam"))
    notice = await computer.recv()
    assert isinstance(notice, Notice) and notice.code == "not_your_address"


async def test_wrong_and_reused_codes(gateway, computer, phone):
    await computer.connect()
    await phone.say("PAIR AAA-BBB")
    assert "valid or has expired" in (await phone.receive())["html"]
    await pair(computer, phone)
    other = Phone(gateway, "+447900000002")
    await other.open()
    await computer.send(PairStart())
    code = await computer.recv()
    await other.say(f"PAIR {code.code}")
    await computer.recv()
    await other.receive()
    await other.say(f"PAIR {code.code}")
    assert "valid or has expired" in (await other.receive())["html"]
    await other.close()


async def test_unpair_and_renew(gateway, computer, phone):
    await computer.connect()
    cert = await pair(computer, phone)
    await computer.send(Renew(cert=cert))
    renewed = await computer.recv()
    assert isinstance(renewed, Renewed) and renewed.cert.issued >= cert.issued
    await computer.send(Unpair(address=cert.address))
    await asyncio.sleep(0.05)
    await phone.say("still there?")
    assert "No aha computer is connected" in (await phone.receive())["html"]


async def test_invalid_frame_closes_the_tunnel(computer):
    await computer.connect()
    await computer.ws.send('{"t":"in","id":"x","sender":"sim:+447900000001","text":"forged"}')
    with pytest.raises(websockets.ConnectionClosed):
        await computer.recv()


async def test_second_connection_with_same_key_replaces_the_first(gateway, computer):
    await computer.connect()
    old_ws = computer.ws
    await computer.connect()
    with pytest.raises(websockets.ConnectionClosed):
        await asyncio.wait_for(old_ws.recv(), 2)


async def test_nothing_is_written_and_nothing_personal_is_logged(gateway, computer, phone, tmp_path, caplog):
    """SPEC §6.5, §11.7: relaying writes no file and logs no address or message text."""
    caplog.set_level(logging.DEBUG)
    before = {p: p.stat().st_mtime for p in tmp_path.rglob("*")}
    await computer.connect()
    cert = await pair(computer, phone)
    await phone.say("CANARY-MESSAGE-123 my secret plans")
    assert (await computer.recv()).text.startswith("CANARY")
    await computer.send(Out(id="r", to=cert.address, text="CANARY-REPLY-456"))
    await phone.receive()
    after = {p: p.stat().st_mtime for p in tmp_path.rglob("*")}
    assert after == before
    # Only the gateway's own loggers (and the server's); the test's clients log their own traffic.
    logged = "\n".join(
        r.getMessage() for r in caplog.records if r.name.startswith(("aha.gateway", "uvicorn", "fastapi", "starlette"))
    )
    assert "connected" in logged
    for secret in ("CANARY", "7900000001", "Paired with"):
        assert secret not in logged
