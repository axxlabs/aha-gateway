# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Axxlabs Limited
"""Gateway settings, from environment variables only (SPEC §7.2)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_ORIGINS = "https://app.aha.axxlabs.ai,http://127.0.0.1:5173,http://localhost:5173"


@dataclass(frozen=True)
class Settings:
    signing_key_file: Path
    public_url: str
    vapid_key_file: Path = Path("/run/secrets/aha-gateway-vapid.pem")
    vapid_subject: str = "https://axxlabs.ai/aha/"
    billing: str = "off"  # off | stripe (SPEC §8)
    # Where this gateway's source is (AGPL §13; SPEC §10.1).
    source_url: str = "https://github.com/axxlabs/aha-gateway"
    # Browser origins allowed to open /v1/device (the app's own origin(s)); non-browser clients send none.
    app_origins: tuple[str, ...] = tuple(DEFAULT_ORIGINS.split(","))

    @classmethod
    def from_env(cls) -> Settings:
        billing = os.environ.get("AHA_GW_BILLING", "off")
        if billing not in ("off", "stripe"):
            raise SystemExit("AHA_GW_BILLING must be 'off' or 'stripe'")
        origins = tuple(
            o.strip() for o in os.environ.get("AHA_GW_APP_ORIGINS", DEFAULT_ORIGINS).split(",") if o.strip()
        )
        return cls(
            signing_key_file=Path(os.environ.get("AHA_GW_SIGNING_KEY_FILE", "/run/secrets/aha-gateway-key")),
            public_url=os.environ.get("AHA_GW_PUBLIC_URL", "http://127.0.0.1:8700"),
            vapid_key_file=Path(os.environ.get("AHA_GW_VAPID_KEY_FILE", "/run/secrets/aha-gateway-vapid.pem")),
            vapid_subject=os.environ.get("AHA_GW_VAPID_SUBJECT", "https://axxlabs.ai/aha/"),
            billing=billing,
            source_url=os.environ.get("AHA_GW_SOURCE_URL", "https://github.com/axxlabs/aha-gateway"),
            app_origins=origins,
        )
