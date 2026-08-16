"""pyjfl — an asynchronous client for JFL Active alarm panels.

A panel dials *out* to the address its installer programmed, so this package is a listener: one
`JflServer` accepts connections from many panels, each identified by the serial in its `0x21`
connection frame.

    from pyjfl import JflServer

    server = JflServer(host="0.0.0.0", port=9494)
    await server.async_start()

    link = server.link("0123456789")           # created on demand, outlives any one socket
    link.async_add_packet_listener(on_packet)  # every decoded frame
    await link.async_request_status()          # the panel never pushes status; it is polled

`pyjfl.protocol` is pure standard library with no I/O; `pyjfl.transport` is the asyncio listener
built on top of it.

Not affiliated with, endorsed by or supported by JFL Equipamentos Eletrônicos Ltda.
"""

from __future__ import annotations

from .protocol import *  # noqa: F403  — the codec's own curated `__all__`
from .protocol import __all__ as _protocol_all
from .transport import (
    COMMAND_TIMEOUT,
    RAW_FRAME_BUFFER,
    UNKNOWN_ACCEPT,
    UNKNOWN_HOLD,
    UNKNOWN_REJECT,
    WATCHDOG_FLOOR_SECONDS,
    WATCHDOG_KEEPALIVE_FACTOR,
    JflPanelLink,
    JflServer,
    RawFrame,
    check_port_available,
)

__all__ = [
    *_protocol_all,
    "COMMAND_TIMEOUT",
    "RAW_FRAME_BUFFER",
    "UNKNOWN_ACCEPT",
    "UNKNOWN_HOLD",
    "UNKNOWN_REJECT",
    "WATCHDOG_FLOOR_SECONDS",
    "WATCHDOG_KEEPALIVE_FACTOR",
    "JflPanelLink",
    "JflServer",
    "RawFrame",
    "check_port_available",
]
