# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Axxlabs Limited
"""A real gateway on a free port, and a fake computer that speaks the tunnel protocol."""

from __future__ import annotations

import asyncio
import json
import os
import socket
from pathlib import Path

import httpx
import pytest
import uvicorn
import websockets

from aha_gateway.app import create_app
from aha_gateway.certs import handshake_message, new_key, public_b64, sign, verify
from aha_gateway.config import Settings
from aha_gateway.protocol import TO_COMPUTER, Auth, Cert, Hello, Ready, b64


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Gateway:
    def __init__(self, app, port: int) -> None:
        self.app = app
        self.port = port
        self.url = f"http://127.0.0.1:{port}"
        self.ws_url = f"ws://127.0.0.1:{port}/v1/tunnel"
        self.relay = app.state.relay


@pytest.fixture
async def gateway(tmp_path: Path):
    port = free_port()
    settings = Settings(signing_key_file=tmp_path / "gateway.key", public_url=f"http://127.0.0.1:{port}")
    app = create_app(settings, staging=True)
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", access_log=False, ws_max_size=2_100_000)
    )
    task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.02)
    yield Gateway(app, port)
    server.should_exit = True
    await task


class Computer:
    """A minimal aha computer: handshake, then send and receive frames."""

    def __init__(self, gateway: Gateway, name: str = "Home") -> None:
        self.gateway = gateway
        self.key = new_key()
        self.instance = public_b64(self.key)
        self.name = name
        self.certs: list[Cert] = []
        self.ws = None
        self.ready: Ready | None = None
        self.gateway_pin: str | None = None

    async def connect(self, pin: str | None = None, tamper: bool = False) -> Ready:
        self.ws = await websockets.connect(self.gateway.ws_url, max_size=2_100_000)
        hello = Hello.model_validate_json(await self.ws.recv())
        self.gateway_pin = hello.gateway
        if pin is not None and hello.gateway != pin:
            raise AssertionError("gateway key does not match the pin")
        my_nonce = b64(os.urandom(32))
        sig = sign(self.key, handshake_message(hello.nonce, self.instance))
        if tamper:
            sig = sign(new_key(), handshake_message(hello.nonce, self.instance))
        await self.ws.send(
            Auth(instance=self.instance, nonce=my_nonce, sig=sig, certs=self.certs, name=self.name).model_dump_json()
        )
        self.ready = Ready.model_validate_json(await self.ws.recv())
        assert verify(hello.gateway, handshake_message(my_nonce), self.ready.sig)
        return self.ready

    async def send(self, frame) -> None:
        await self.ws.send(frame.model_dump_json(exclude_none=True))

    async def recv(self, timeout: float = 3):
        raw = await asyncio.wait_for(self.ws.recv(), timeout)
        return TO_COMPUTER.validate_json(raw)

    async def close(self) -> None:
        await self.ws.close()


@pytest.fixture
def computer(gateway):
    return Computer(gateway)


class Phone:
    """The simulator, as a browser would use it: POST to send, SSE to receive."""

    def __init__(self, gateway: Gateway, number: str) -> None:
        self.gateway = gateway
        self.number = number
        transport = httpx.AsyncHTTPTransport()
        self.http = httpx.AsyncClient(base_url=gateway.url, transport=transport, timeout=5)
        self.token = None
        self.events: asyncio.Queue = asyncio.Queue()
        self._task = None

    async def open(self) -> None:
        page = await self.http.get("/test")
        assert page.status_code == 200
        self.token = self.http.cookies.get("sim_token")
        ready = asyncio.Event()

        async def listen():
            async with self.http.stream("GET", "/test/events", params={"n": self.number}, timeout=None) as r:
                async for line in r.aiter_lines():
                    if line.startswith(": connected"):
                        ready.set()
                    if line.startswith("data: "):
                        await self.events.put(json.loads(line[6:]))

        self._task = asyncio.create_task(listen())
        await asyncio.wait_for(ready.wait(), 3)

    async def say(self, text: str = "", button: str | None = None) -> httpx.Response:
        return await self.http.post(
            "/test/send",
            json={"number": self.number, "text": text, "button": button},
            headers={"X-Sim-Token": self.token},
        )

    async def receive(self, timeout: float = 3) -> dict:
        return await asyncio.wait_for(self.events.get(), timeout)

    async def close(self) -> None:
        if self._task:
            self._task.cancel()
        await self.http.aclose()


@pytest.fixture
async def phone(gateway):
    p = Phone(gateway, "+447900000001")
    await p.open()
    yield p
    await p.close()
