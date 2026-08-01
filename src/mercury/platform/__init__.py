"""Direct dispatch for Mercury's Windows and Linux platform collectors."""

from __future__ import annotations

import sys
from typing import Awaitable, Callable

from mercury.models import Capability, CapabilityState

from .common import PlatformRecords

PlatformCollector = Callable[..., Awaitable[PlatformRecords]]


async def collect_platform(
    *,
    platform_name: str | None = None,
    windows_collector: PlatformCollector | None = None,
    linux_collector: PlatformCollector | None = None,
    **kwargs: object,
) -> PlatformRecords:
    """Call one concrete adapter selected directly from ``sys.platform``."""

    selected = sys.platform if platform_name is None else platform_name
    if selected == "win32":
        if windows_collector is None:
            from .windows import collect_platform as windows_collector

        return await windows_collector(**kwargs)
    if selected == "linux":
        if linux_collector is None:
            from .linux import collect_platform as linux_collector

        return await linux_collector(**kwargs)
    return PlatformRecords(
        capabilities=(
            Capability(
                name="platform_inventory",
                state=CapabilityState.UNSUPPORTED,
                source=f"sys.platform:{selected}",
                detail=(
                    "Mercury supports Windows and Ubuntu; "
                    "this platform has no inventory adapter"
                ),
            ),
        )
    )


__all__ = ["PlatformCollector", "PlatformRecords", "collect_platform"]
