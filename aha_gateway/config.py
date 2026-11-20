# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Axxlabs Limited
"""Gateway settings, from environment variables only (SPEC §7.2)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    signing_key_file: Path
    public_url: str
    billing: str = "off"  # off | stripe (SPEC §8)
    staging_access: str = "local"  # local | network | proxy (simulator only, SPEC §7.4)
    trusted_proxy: str = ""  # CIDR of the authenticating proxy when staging_access=proxy
    payment_url: str = ""
    # Staging/self-hosting with one computer: a number nobody has paired is registered to the only connected
    # computer on its first message, with no PAIR code (SPEC §6.4). Never on a shared gateway.
    open_registration: bool = False
    # Where this gateway's source is (AGPL §13): people who chat through it are its network users (SPEC §10.1).
    source_url: str = "https://github.com/axxlabs/aha-gateway"

    @classmethod
    def from_env(cls) -> Settings:
        billing = os.environ.get("AHA_GW_BILLING", "off")
        if billing not in ("off", "stripe"):
            raise SystemExit("AHA_GW_BILLING must be 'off' or 'stripe'")
        access = os.environ.get("AHA_GW_STAGING_ACCESS", "local")
        if access not in ("local", "network", "proxy"):
            raise SystemExit("AHA_GW_STAGING_ACCESS must be 'local', 'network' or 'proxy'")
        proxy = os.environ.get("AHA_GW_TRUSTED_PROXY", "")
        if access == "proxy" and not proxy:
            raise SystemExit("AHA_GW_STAGING_ACCESS=proxy needs AHA_GW_TRUSTED_PROXY")
        open_registration = os.environ.get("AHA_GW_OPEN_REGISTRATION", "0") == "1"
        if open_registration and billing != "off":
            raise SystemExit("AHA_GW_OPEN_REGISTRATION is for a gateway with one computer, not a billed one")
        return cls(
            signing_key_file=Path(os.environ.get("AHA_GW_SIGNING_KEY_FILE", "/run/secrets/aha-gateway-key")),
            public_url=os.environ.get("AHA_GW_PUBLIC_URL", "http://127.0.0.1:8700"),
            billing=billing,
            staging_access=access,
            trusted_proxy=proxy,
            payment_url=os.environ.get("AHA_GW_PAYMENT_URL", ""),
            open_registration=open_registration,
            source_url=os.environ.get("AHA_GW_SOURCE_URL", "https://github.com/axxlabs/aha-gateway"),
        )
