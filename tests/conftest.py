# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Axxlabs Limited
"""A real gateway on a free port, a fake computer (tunnel) and fake devices. The gateway never decrypts, so
the fakes use dummy boxes."""

from __future__ import annotations

import asyncio
import os
import socket
from pathlib import Path

import pytest
import uvicorn
import websockets

from aha_gateway.app import create_app
from aha_gateway.certs import device_message, handshake_message, new_key, public_b64, sign, verify
from aha_gateway.config import Settings
from aha_gateway.protocol import TO_COMPUTER, TO_DEVICE, Auth, Cert, DevAuth, Hello, Ready, b64


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Gateway:
    def __init__(self, app, port: int) -> None:
        self.app = app
        self.port = port
        self.url = f"http://127.0.0.1:{port}"
        self.tunnel_url = f"ws://127.0.0.1:{port}/v1/tunnel"
        self.device_url = f"ws://127.0.0.1:{port}/v1/device"
        self.hub = app.state.hub


@pytest.fixture
async def gateway(tmp_path: Path):
    port = free_port()
    settings = Settings(
        signing_key_file=tmp_path / "gateway.key",
        vapid_key_file=tmp_path / "vapid.pem",
        public_url=f"http://127.0.0.1:{port}",
    )
    app = create_app(settings)
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", access_log=False, ws_max_size=3_000_000)
    )
    task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.02)
    yield Gateway(app, port)
    server.should_exit = True
    await task


class Computer:
    def __init__(self, gateway: Gateway, name: str = "Home") -> None:
        self.gateway = gateway
        self.key = new_key()
        self.instance = public_b64(self.key)
        self.name = name
        self.certs: list[Cert] = []
        self.ws = None
        self.ready: Ready | None = None
        self.pin: str | None = None

    async def connect(self, tamper: bool = False) -> Ready:
        self.ws = await websockets.connect(self.gateway.tunnel_url, max_size=3_000_000)
        hello = Hello.model_validate_json(await self.ws.recv())
        self.pin = hello.gateway
        my_nonce = b64(os.urandom(32))
        signer = new_key() if tamper else self.key
        sig = sign(signer, handshake_message(hello.nonce, self.instance))
        await self.ws.send(
            Auth(instance=self.instance, nonce=my_nonce, sig=sig, certs=self.certs, name=self.name).model_dump_json()
        )
        self.ready = Ready.model_validate_json(await self.ws.recv())
        assert verify(hello.gateway, handshake_message(my_nonce), self.ready.sig)
        return self.ready

    async def send(self, frame) -> None:
        await self.ws.send(frame.model_dump_json(exclude_none=True))

    async def recv(self, timeout: float = 3, skip_status: bool = True):
        while True:
            frame = TO_COMPUTER.validate_json(await asyncio.wait_for(self.ws.recv(), timeout))
            if skip_status and frame.t == "device":
                continue
            return frame

    async def close(self) -> None:
        await self.ws.close()


class Device:
    def __init__(self, gateway: Gateway) -> None:
        self.gateway = gateway
        self.key = new_key()
        self.dev = public_b64(self.key)
        self.ws = None
        self.hello: Hello | None = None

    async def open(self, origin: str | None = None) -> Hello:
        headers = {"Origin": origin} if origin else None
        self.ws = await websockets.connect(self.gateway.device_url, max_size=3_000_000, additional_headers=headers)
        self.hello = Hello.model_validate_json(await self.ws.recv())
        return self.hello

    async def auth(self, cert: Cert, tamper: bool = False):
        hello = await self.open()
        signer = new_key() if tamper else self.key
        await self.send(DevAuth(cert=cert, sig=sign(signer, device_message(hello.nonce, self.dev))))
        return await self.recv()

    async def send(self, frame) -> None:
        await self.ws.send(frame.model_dump_json(exclude_none=True))

    async def recv(self, timeout: float = 3):
        return TO_DEVICE.validate_json(await asyncio.wait_for(self.ws.recv(), timeout))

    async def closed_with(self, timeout: float = 3) -> int:
        try:
            while True:
                await asyncio.wait_for(self.ws.recv(), timeout)
        except websockets.ConnectionClosed as e:
            return e.rcvd.code if e.rcvd else 0


@pytest.fixture
def computer(gateway):
    return Computer(gateway)
