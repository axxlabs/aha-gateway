"""The simulator's two gates and the production build (SPEC §7.4, §11.8)."""

import subprocess
import zipfile
from pathlib import Path

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from aha_gateway.app import create_app
from aha_gateway.config import Settings
from aha_gateway.staging import viewer

ROOT = Path(__file__).resolve().parents[1]


def request(host: str, headers: dict | None = None) -> Request:
    raw = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    return Request({"type": "http", "client": (host, 1234), "headers": raw, "method": "GET", "path": "/test"})


def settings(tmp_path, **kw) -> Settings:
    return Settings(signing_key_file=tmp_path / "k", public_url="http://x", **kw)


def test_local_access_needs_loopback_without_forwarding(tmp_path):
    s = settings(tmp_path)
    assert viewer(request("127.0.0.1"), s) == ""
    for bad in (
        request("192.168.1.5"),
        request("127.0.0.1", {"X-Forwarded-For": "1.2.3.4"}),
        request("127.0.0.1", {"Forwarded": "for=1.2.3.4"}),
    ):
        with pytest.raises(HTTPException) as e:
            viewer(bad, s)
        assert e.value.status_code == 404


def test_proxy_access_needs_the_proxy_and_a_login(tmp_path):
    s = settings(tmp_path, staging_access="proxy", trusted_proxy="10.0.0.0/24")
    assert viewer(request("10.0.0.2", {"X-Auth-Request-User": "fe"}), s) == "fe"
    for bad in (request("10.0.0.2"), request("10.0.1.2", {"X-Auth-Request-User": "fe"})):
        with pytest.raises(HTTPException):
            viewer(bad, s)


async def test_send_needs_the_page_token(gateway, phone):
    r = await phone.http.post(
        "/test/send", json={"number": "+447900000001", "text": "hi"}, headers={"X-Sim-Token": "wrong"}
    )
    assert r.status_code == 403


async def test_bad_number_is_refused(gateway, phone):
    r = await phone.http.post(
        "/test/send", json={"number": "hello", "text": "hi"}, headers={"X-Sim-Token": phone.token}
    )
    assert r.status_code == 422


def test_without_the_staging_package_there_is_no_simulator(tmp_path):
    from fastapi.testclient import TestClient

    app = create_app(settings(tmp_path), staging=False)
    client = TestClient(app, client=("127.0.0.1", 5000))
    assert client.get("/test").status_code == 404
    assert client.get("/healthz").status_code == 200


def test_production_wheel_has_no_staging_code(tmp_path):
    subprocess.run(["uv", "build", "--wheel", "--out-dir", str(tmp_path), "-q"], cwd=ROOT, check=True)
    wheel = next(tmp_path.glob("*.whl"))
    names = zipfile.ZipFile(wheel).namelist()
    assert any(n.startswith("aha_gateway/app.py") for n in names)
    assert not [n for n in names if "staging" in n]
