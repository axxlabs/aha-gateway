# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Axxlabs Limited
"""Which connected computer serves which address. In memory only, rebuilt from certificates (SPEC §6.4)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


class TunnelLike(Protocol):
    instance: str
    name: str

    async def send_frame(self, frame) -> None: ...


@dataclass
class Route:
    tunnel: TunnelLike
    issued: int


@dataclass
class Router:
    _tunnels: dict[str, TunnelLike] = field(default_factory=dict)
    _routes: dict[str, Route] = field(default_factory=dict)

    def attach(self, tunnel: TunnelLike) -> TunnelLike | None:
        """Register a tunnel; returns the tunnel it replaces (same instance key), if any."""
        old = self._tunnels.get(tunnel.instance)
        if old is not None:
            self.detach(old)
        self._tunnels[tunnel.instance] = tunnel
        return old

    def detach(self, tunnel: TunnelLike) -> None:
        if self._tunnels.get(tunnel.instance) is tunnel:
            del self._tunnels[tunnel.instance]
        self._routes = {a: r for a, r in self._routes.items() if r.tunnel is not tunnel}

    def tunnel_for_instance(self, instance: str) -> TunnelLike | None:
        return self._tunnels.get(instance)

    def only_tunnel(self) -> TunnelLike | None:
        """The connected computer, if exactly one is connected."""
        return next(iter(self._tunnels.values())) if len(self._tunnels) == 1 else None

    def add_route(self, address: str, tunnel: TunnelLike, issued: int) -> bool:
        """The newest certificate wins (SPEC §6.4). Returns whether this tunnel now owns the address."""
        current = self._routes.get(address)
        if current is not None and current.tunnel is not tunnel and current.issued > issued:
            return False
        self._routes[address] = Route(tunnel, issued)
        return True

    def remove_route(self, address: str, tunnel: TunnelLike) -> None:
        current = self._routes.get(address)
        if current is not None and current.tunnel is tunnel:
            del self._routes[address]

    def lookup(self, address: str) -> TunnelLike | None:
        route = self._routes.get(address)
        return route.tunnel if route else None

    def owns(self, address: str, tunnel: TunnelLike) -> bool:
        return self.lookup(address) is tunnel

    def counts(self) -> dict[str, int]:
        return {"computers": len(self._tunnels), "addresses": len(self._routes)}
