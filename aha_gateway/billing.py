"""Subscription check for the hosted gateway (SPEC §8).

The gateway keeps no customer records: subscriptions live in Stripe, keyed by the computer's instance public
key. v1 ships with billing off; the Stripe lookup is milestone M3.
"""

from __future__ import annotations

from typing import Protocol


class Billing(Protocol):
    async def active(self, instance: str) -> bool: ...


class BillingOff:
    """Self-hosted or staging: every computer may connect."""

    async def active(self, instance: str) -> bool:
        return True


def make_billing(mode: str) -> Billing:
    if mode == "off":
        return BillingOff()
    raise SystemExit("AHA_GW_BILLING=stripe is not available yet (SPEC §12, M3)")
