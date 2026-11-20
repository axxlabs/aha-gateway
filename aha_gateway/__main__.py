# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Axxlabs Limited
"""Run the gateway: `python -m aha_gateway`.

Listens on AHA_GW_HOST:AHA_GW_PORT, and also on the Unix socket AHA_GW_UNIX_SOCKET when set. The socket lets
a computer on the same machine (development) connect without the gateway listening on the network.
"""

import asyncio
import logging
import os

import uvicorn

from .app import create_app
from .config import Settings


def main() -> None:
    # Logs carry counts and error kinds only (SPEC §6.5); access logs are off because URLs and clients
    # would identify people.
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    app = create_app(Settings.from_env())
    common = {"access_log": False, "log_level": "warning", "ws_max_size": 2_100_000, "lifespan": "off"}
    configs = [
        uvicorn.Config(
            app,
            host=os.environ.get("AHA_GW_HOST", "127.0.0.1"),
            port=int(os.environ.get("AHA_GW_PORT", "8700")),
            **common,
        )
    ]
    if socket_path := os.environ.get("AHA_GW_UNIX_SOCKET"):
        configs.append(uvicorn.Config(app, uds=socket_path, **common))

    async def serve() -> None:
        await asyncio.gather(*(uvicorn.Server(c).serve() for c in configs))

    asyncio.run(serve())


if __name__ == "__main__":
    main()
