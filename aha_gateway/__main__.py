"""Run the gateway: `python -m aha_gateway`. Host and port from AHA_GW_HOST / AHA_GW_PORT."""

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
    uvicorn.run(
        app,
        host=os.environ.get("AHA_GW_HOST", "127.0.0.1"),
        port=int(os.environ.get("AHA_GW_PORT", "8700")),
        access_log=False,
        log_level="warning",
        ws_max_size=2_100_000,
    )


if __name__ == "__main__":
    main()
