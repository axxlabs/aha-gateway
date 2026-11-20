"""Certificates, pairing codes, routing and rate limits (SPEC §6.4, §6.5)."""

import pytest

from aha_gateway.certs import cert_valid, issue_cert, needs_renewal, new_key, public_b64
from aha_gateway.connectors.base import InboundMessage
from aha_gateway.pairing import PairingCodes, parse_pair_message
from aha_gateway.protocol import TO_GATEWAY, In, Out, Paired, frame_too_big, normalise_phone
from aha_gateway.relay import RateLimiter, Relay
from aha_gateway.router import Router


class T:
    def __init__(self, instance):
        self.instance, self.name = instance, ""
        self.frames = []

    async def send_frame(self, frame):
        self.frames.append(frame)


class Sim:
    prefix = "sim"

    def __init__(self):
        self.sent = []

    async def send(self, message):
        self.sent.append(message.text)


def relay(open_registration):
    r = Relay(new_key(), Router(), PairingCodes(), open_registration=open_registration)
    sim = Sim()
    r.add_connector(sim)
    return r, sim


async def test_open_registration_binds_new_numbers_to_the_only_computer():
    r, sim = relay(open_registration=True)
    home = T(public_b64(new_key()))
    r.router.attach(home)
    await r.inbound(InboundMessage(sender="sim:+447900000005", text="hi", name="Ana"))
    paired, inbound = home.frames
    assert isinstance(paired, Paired) and paired.cert.address == "sim:+447900000005" and paired.name == "Ana"
    assert paired.cert.instance == home.instance
    assert isinstance(inbound, In) and inbound.text == "hi"
    assert sim.sent == []
    await r.inbound(InboundMessage(sender="sim:+447900000005", text="again"))
    assert [type(f) for f in home.frames] == [Paired, In, In]  # registered once


async def test_open_registration_needs_exactly_one_computer():
    r, sim = relay(open_registration=True)
    await r.inbound(InboundMessage(sender="sim:+447900000005", text="hi"))
    a, b = T(public_b64(new_key())), T(public_b64(new_key()))
    r.router.attach(a)
    r.router.attach(b)
    await r.inbound(InboundMessage(sender="sim:+447900000005", text="hi"))
    assert a.frames == b.frames == []
    assert len(sim.sent) == 2 and all("No aha computer" in t for t in sim.sent)


async def test_without_open_registration_new_numbers_need_pairing():
    r, sim = relay(open_registration=False)
    home = T(public_b64(new_key()))
    r.router.attach(home)
    await r.inbound(InboundMessage(sender="sim:+447900000005", text="hi"))
    assert home.frames == [] and "No aha computer" in sim.sent[0]


def test_certificate_signed_for_one_instance_and_time():
    gw = new_key()
    me, other = public_b64(new_key()), public_b64(new_key())
    cert = issue_cert(gw, "sim:+447900000001", me, now=1000)
    assert cert_valid(cert, public_b64(gw), me, now=2000)
    assert not cert_valid(cert, public_b64(gw), other, now=2000)  # another computer
    assert not cert_valid(cert, public_b64(new_key()), me, now=2000)  # another gateway
    assert not cert_valid(cert, public_b64(gw), me, now=cert.expires)  # expired
    tampered = cert.model_copy(update={"address": "sim:+447900000002"})
    assert not cert_valid(tampered, public_b64(gw), me, now=2000)
    assert needs_renewal(cert, now=cert.expires - 10 * 86400)
    assert not needs_renewal(cert, now=2000)


def test_pairing_codes_are_single_use_and_expire():
    codes = PairingCodes()
    code = codes.create("A", now=0)
    assert len(code) == 7 and code[3] == "-"
    assert codes.redeem(code, now=10) == "A"
    assert codes.redeem(code, now=11) is None
    code = codes.create("A", now=0)
    assert codes.redeem(code, now=601) is None


def test_new_code_replaces_the_old_one_for_the_same_computer():
    codes = PairingCodes()
    first = codes.create("A", now=0)
    second = codes.create("A", now=1)
    assert codes.redeem(first, now=2) is None
    assert codes.redeem(second, now=2) == "A"


@pytest.mark.parametrize(
    "text,code",
    [
        ("PAIR 7K3-QF9", "7K3-QF9"),
        ("pair 7k3qf9", "7K3-QF9"),
        ("  Pair 7K3-QF9 ", "7K3-QF9"),
        ("pair me", None),
        ("hello", None),
    ],
)
def test_pair_message(text, code):
    assert parse_pair_message(text) == code


def test_router_newest_certificate_wins_and_detach_drops_routes():
    r = Router()
    a, b = T("A"), T("B")
    r.attach(a)
    r.attach(b)
    assert r.add_route("sim:+1", a, issued=100)
    assert not r.add_route("sim:+1", b, issued=50)
    assert r.lookup("sim:+1") is a
    assert r.add_route("sim:+1", b, issued=200)
    assert r.lookup("sim:+1") is b
    r.detach(b)
    assert r.lookup("sim:+1") is None


def test_rate_limit():
    limiter = RateLimiter(rate=1, burst=2)
    assert limiter.allow("x", now=0) and limiter.allow("x", now=0)
    assert not limiter.allow("x", now=0)
    assert limiter.allow("x", now=1.1)


def test_frames_are_strict():
    ok = Out(id="m1", to="sim:+447900000001", text="hi").model_dump_json()
    assert TO_GATEWAY.validate_json(ok)
    with pytest.raises(ValueError):
        TO_GATEWAY.validate_json('{"t":"out","id":"m1","to":"sim:+447900000001","text":"hi","extra":1}')
    with pytest.raises(ValueError):
        TO_GATEWAY.validate_json('{"t":"in","id":"m1","sender":"sim:+447900000001"}')  # computer can't send "in"
    with pytest.raises(ValueError):
        Out(id="m1", to="sim:+447900000001", buttons=[{"id": f"b{i}", "label": "x"} for i in range(4)])
    assert frame_too_big("x" * 1_000_001)
    assert not frame_too_big('{"image":{' + "x" * 1_500_000)


def test_normalise_phone():
    assert normalise_phone("+44 7900 000001") == "+447900000001"
    assert normalise_phone("0044 7900 000001") == "+447900000001"
    assert normalise_phone("hello") is None
