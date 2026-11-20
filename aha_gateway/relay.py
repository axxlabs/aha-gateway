"""The relay: inbound messages go to the computer that holds the address; outbound ones to the chat app.

Nothing is stored (SPEC §6.5): a message exists only in the local variables of these functions while it is
passed on. Logs carry counts and error kinds, never addresses or text.
"""

from __future__ import annotations

import logging
import time
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import messages
from .certs import issue_cert
from .connectors.base import Connector, InboundMessage, OutboundMessage
from .pairing import PairingCodes, parse_pair_message
from .protocol import In, Notice, Out, Paired, Typing
from .router import Router, TunnelLike

log = logging.getLogger("aha.gateway")

RATE_PER_SECOND = 10
RATE_BURST = 20


class RateLimiter:
    """Token bucket per address, in memory; buckets idle for a minute are dropped."""

    def __init__(self, rate: float = RATE_PER_SECOND, burst: float = RATE_BURST) -> None:
        self.rate, self.burst = rate, burst
        self._buckets: dict[str, tuple[float, float]] = {}

    def allow(self, key: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        if len(self._buckets) > 50_000:
            self._buckets = {k: v for k, v in self._buckets.items() if now - v[1] < 60}
        tokens, last = self._buckets.get(key, (self.burst, now))
        tokens = min(self.burst, tokens + (now - last) * self.rate)
        if tokens < 1:
            self._buckets[key] = (tokens, now)
            return False
        self._buckets[key] = (tokens - 1, now)
        return True


class Relay:
    def __init__(
        self, signing_key: Ed25519PrivateKey, router: Router, pairing: PairingCodes, open_registration: bool = False
    ) -> None:
        self.signing_key = signing_key
        self.open_registration = open_registration
        self.router = router
        self.pairing = pairing
        self.connectors: dict[str, Connector] = {}
        self.limiter = RateLimiter()

    def add_connector(self, connector: Connector) -> None:
        self.connectors[connector.prefix] = connector

    async def reply(self, to: str, text: str) -> None:
        await self.deliver(OutboundMessage(to=to, text=text))

    async def deliver(self, message: OutboundMessage) -> None:
        connector = self.connectors.get(message.to.split(":", 1)[0])
        if connector is None:
            log.warning("no connector for an outbound message")
            return
        await connector.send(message)

    # ---- person → computer

    async def inbound(self, message: InboundMessage) -> None:
        if not self.limiter.allow(message.sender):
            await self.reply(message.sender, messages.SLOW_DOWN)
            return
        code = parse_pair_message(message.text) if message.button is None else None
        if code is not None:
            await self._pair(message, code)
            return
        tunnel = self.router.lookup(message.sender)
        if tunnel is None and self.open_registration:
            tunnel = await self._register(message)
        if tunnel is None:
            await self.reply(message.sender, messages.NOT_CONNECTED)
            return
        await tunnel.send_frame(
            In(id=uuid.uuid4().hex, sender=message.sender, text=message.text, button=message.button, name=message.name)
        )

    async def _register(self, message: InboundMessage) -> TunnelLike | None:
        """Open registration: bind the number to the only connected computer, as pairing would."""
        tunnel = self.router.only_tunnel()
        if tunnel is None:  # none, or several: no way to tell whose number this is
            return None
        cert = issue_cert(self.signing_key, message.sender, tunnel.instance)
        self.router.add_route(message.sender, tunnel, cert.issued)
        await tunnel.send_frame(Paired(cert=cert, name=message.name))
        log.info("registered an address (open registration)")
        return tunnel

    async def _pair(self, message: InboundMessage, code: str) -> None:
        instance = self.pairing.redeem(code)
        if instance is None:
            await self.reply(message.sender, messages.PAIR_UNKNOWN)
            return
        tunnel = self.router.tunnel_for_instance(instance)
        if tunnel is None:
            await self.reply(message.sender, messages.PAIR_OFFLINE)
            return
        cert = issue_cert(self.signing_key, message.sender, instance)
        self.router.add_route(message.sender, tunnel, cert.issued)
        await tunnel.send_frame(Paired(cert=cert, name=message.name))
        await self.reply(message.sender, messages.PAIRED.format(name=tunnel.name or "your computer"))
        log.info("paired an address")

    # ---- computer → person

    async def outbound(self, tunnel: TunnelLike, frame: Out) -> None:
        if not self.router.owns(frame.to, tunnel):
            await tunnel.send_frame(Notice(code="not_your_address", detail="message not delivered"))
            return
        await self.deliver(
            OutboundMessage(to=frame.to, text=frame.text, buttons=list(frame.buttons), image=frame.image)
        )

    async def typing(self, tunnel: TunnelLike, frame: Typing) -> None:
        """Passed on like a message, with the same ownership check; nothing is kept (SPEC §6.3)."""
        if not self.router.owns(frame.to, tunnel):
            return
        connector = self.connectors.get(frame.to.split(":", 1)[0])
        if connector is not None:
            await connector.typing(frame.to, frame.on)
