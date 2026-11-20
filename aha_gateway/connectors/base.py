"""What every chat connector does (SPEC §7.1): hand inbound messages to the relay, send outbound ones."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from ..protocol import Button, Image


@dataclass(frozen=True)
class InboundMessage:
    sender: str  # address, e.g. "sim:+447900000001"
    text: str = ""
    button: str | None = None  # id of a pressed button
    name: str = ""  # display name the chat app gives, if any


@dataclass(frozen=True)
class OutboundMessage:
    to: str
    text: str = ""
    buttons: list[Button] = field(default_factory=list)
    image: Image | None = None


class Connector(Protocol):
    prefix: str  # address prefix this connector serves: "sim", "wa", "tg"

    async def send(self, message: OutboundMessage) -> None: ...

    async def typing(self, address: str, on: bool) -> None:
        """Show or hide the chat app's typing indicator for this person (SPEC §3.3, §7.1)."""
        ...
