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
        return cls(
            signing_key_file=Path(os.environ.get("AHA_GW_SIGNING_KEY_FILE", "/run/secrets/aha-gateway-key")),
            public_url=os.environ.get("AHA_GW_PUBLIC_URL", "http://127.0.0.1:8700"),
            billing=billing,
            staging_access=access,
            trusted_proxy=proxy,
            payment_url=os.environ.get("AHA_GW_PAYMENT_URL", ""),
        )
