"""pyjfl — an asynchronous client for JFL Active alarm panels.

Author: Jonis Maurin Ceará <jmceara AT gmail.com>
Based on the code developed by Carlos Jose Fernandes,
available at https://github.com/fernac03/JFL_ACTIVE

Copyright (C) 2026 Jonis Maurin Ceará.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU
General Public License as published by the Free Software Foundation, version 3.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
General Public License for more details. You should have received a copy of the GNU General Public
License along with this program. If not, see <https://www.gnu.org/licenses/>.

Not affiliated with, endorsed by or supported by JFL Equipamentos Eletrônicos Ltda.

**The topology is inverted.** Nothing here dials a panel. A JFL Active panel dials *out*, to the IP
and port its installer programmed into its reporting destination, so this package is a **listener**:
one `JflServer` accepts connections from many panels at once, and a panel is identified by the
serial in its `0x21` connection frame rather than by its address.

    from pyjfl import JflServer

    server = JflServer(host="0.0.0.0", port=9494)
    await server.async_start()

    link = server.link("0123456789")           # created on demand, outlives any one socket
    link.async_add_packet_listener(on_packet)  # every decoded frame
    await link.async_request_status()          # the panel never pushes status; it is polled

The package is in two halves and the split is deliberate:

* `pyjfl.protocol` is **pure** — standard library, no I/O, no sockets. It turns bytes into typed
  packets and typed commands into bytes, so it can be unit-tested and fuzzed on its own, and
  `mypy --strict` runs over it without dragging anything else in.
* `pyjfl.transport` is the asyncio listener built on top of it.

Two protocol rules the transport exists to get right, both of which are easy to break:

* The panel retransmits anything it does not hear an acknowledgement for, so `0x21`, `0x40` and
  `0x24` are answered immediately, ahead of the transmit queue, and the event acknowledgement goes
  out **even when decoding the frame failed**.
* A command is answered with a full status frame, and that frame is not the final state. Re-read the
  status after any command.

⚠️ **This talks to a real alarm system.** Five wrong passwords lock remote access at the panel until
someone performs a valid keypad operation, so there is no retry loop anywhere near the `0x37`
authenticated family, and callers must not add one.

This package is generated from the JFL_ALARM project rather than maintained separately; see that
repository's `docs/adr/0019-pyjfl-owns-the-codec-and-the-transport.md`.
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
]
