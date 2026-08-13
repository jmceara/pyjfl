"""The TCP listener JFL panels dial in to.

Author: Jonis Maurin Ceará <jmceara AT gmail.com>
Based on the code developed by Carlos Jose Fernandes,
available at https://github.com/fernac03/JFL_ACTIVE

**The topology is inverted.** Home Assistant does not connect to the panel; the panel connects to
Home Assistant, at the destination IP and port its installer programmed into it. One listener
therefore serves *many* panels at once, and everything that could be per-integration state — the
sequence counter, the transmit queue, the write lock, the watchdog, the response correlation — has
to be per *panel*. The architectural reference is Home Assistant's own SIA integration, the only
core integration with the same shape.

A panel is identified by the serial in its `0x21` connection frame, never by its source address: a
panel that reconnects from a new DHCP lease is the same panel, and one that reconnects from the same
address is not necessarily one. `JflPanelLink` is the object that outlives the socket, so a
reconnect rebinds one panel's transport and disturbs nothing else.

Two rules from the protocol shape the read path and are easy to get wrong:

* The panel retransmits anything it does not hear an acknowledgement for. So `0x21`, `0x40` and
  `0x24` are answered **immediately**, ahead of the transmit queue, and the event ack is written
  **before** listeners run and **even when decoding failed**. A decoding bug that skipped the ack
  would turn into an endless retransmission storm.
* The panel never pushes its status. `0x4D` has to be polled or there is no zone or partition state
  at all — which is why polling continues in read-only mode. Reading is not writing; see
  `async_send_command`, which is the only path a control command can take and the only one
  `read_only` blocks.

**This module imports no Home Assistant, and that is now load-bearing.** It is the transport half of
the future `pyjfl` library — `home-assistant/core` requires that all device communication live in a
published PyPI package, and core's own integration with this same inverted topology, SIA, puts its
TCP server in `pysiaalarm` for exactly that reason. The boundary, and what stays behind, is
`docs/adr/0019-pyjfl-owns-the-codec-and-the-transport.md`; `tests/test_library_boundary.py` fails if
a Home Assistant import creeps back in.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import socket
from collections import deque
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

from .protocol import (
    DEFAULT_KEEPALIVE_MINUTES,
    Cmd,
    CommandResponse,
    ConnectionInfo,
    EventBuffer,
    Frame,
    FrameReader,
    JflProtocolError,
    Packet,
    PanelEvent,
    PanelNotConnectedError,
    PanelStatus,
    ProgrammingBlock,
    Seq,
    WirelessInventory,
    build_connection_ack,
    build_event_ack,
    build_events_read,
    build_keepalive_ack,
    build_programming_read,
    build_status_request,
    build_wireless_read,
    decode,
)

__all__ = [
    "COMMAND_TIMEOUT",
    "RAW_FRAME_BUFFER",
    "UNKNOWN_ACCEPT",
    "UNKNOWN_HOLD",
    "UNKNOWN_REJECT",
    "WATCHDOG_FLOOR_SECONDS",
    "WATCHDOG_KEEPALIVE_FACTOR",
    "JflPanelLink",
    "JflServer",
    "PanelNotConnectedError",
    "RawFrame",
]

LOGGER = logging.getLogger(__name__)
"""A child of the integration's own logger while this module is in-tree, so
`logger: custom_components.jfl_alarm: debug` still reaches it. When it moves to `pyjfl`,
`manifest.json`'s `loggers` gains `pyjfl` — ADR-0019."""

READ_CHUNK: Final = 4096
"""Bytes to ask the socket for at a time. Frames are at most 255 bytes, so this is several."""

_EVENT_COUNTER_START: Final = 17
_EVENT_COUNTER_END: Final = 21
"""`CONTADOR` in the `0x24` frame. Sliced directly rather than via the decoder, because the
acknowledgement has to go out even when decoding the rest of the frame failed."""

# --- transport tuning ---------------------------------------------------------------------------
# These live here rather than in `const.py` because they are the *transport's* own knobs, and the
# transport is the half that leaves for `pyjfl`. `const.py` re-exports the three policy strings,
# which the config flow offers as choices.

WATCHDOG_FLOOR_SECONDS: Final = 90
"""Lower bound on the idle watchdog. A panel that says nothing for this long has gone away even if
its keep-alive interval would allow a longer silence."""

WATCHDOG_KEEPALIVE_FACTOR: Final = 2.5
"""Allow two missed keep-alives plus a margin before declaring a panel gone."""

RAW_FRAME_BUFFER: Final = 50
"""How many frames the per-panel diagnostics ring buffer keeps. Enough to see a reconnect and the
exchange around it, small enough that a diagnostics download stays readable."""

COMMAND_TIMEOUT: Final = 10.0
"""Seconds to wait for the acknowledgement of an authenticated `0x37` command."""

UNKNOWN_ACCEPT: Final = "accept"
"""Create a panel subentry automatically. The friendly default for a single-panel installation."""

UNKNOWN_HOLD: Final = "hold"
"""Keep the connection but create nothing; the panel is offered in the "add panel" flow."""

UNKNOWN_REJECT: Final = "reject"
"""Answer the connection frame with `RESULT = 0x00`, which makes the panel disconnect."""


def _utcnow() -> datetime:
    """Return the current UTC time.

    `homeassistant.util.dt.utcnow` is exactly this call, and reaching for the standard library
    directly is what keeps the module importable without Home Assistant. Test time-freezing is
    unaffected: both go through `datetime.now`.
    """
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class RawFrame:
    """One frame as it crossed the wire, for the diagnostics ring buffer."""

    at: datetime
    outbound: bool
    data: bytes

    def as_dict(self) -> dict[str, str | bool]:
        """Render for a diagnostics download. Hex, because the point is to re-decode it by hand."""
        return {
            "at": self.at.isoformat(),
            "outbound": self.outbound,
            "hex": self.data.hex(" "),
        }


class JflPanelLink:
    """Everything about one panel that has to outlive its socket.

    Created on demand, by whichever comes first: the coordinator asking for its panel at setup time,
    or a panel dialling in. It never goes away while the entry is loaded, so listeners registered
    against it survive any number of reconnections.
    """

    def __init__(self, server: JflServer, serial: str) -> None:
        """Prepare a link for the panel with this *serial*. No socket is implied."""
        self._server = server
        self.serial = serial
        self.info: ConnectionInfo | None = None
        self.last_status: PanelStatus | None = None
        self.last_seen: datetime | None = None
        self.address: str | None = None

        self._connection: _PanelConnection | None = None
        self._packet_listeners: list[Callable[[Packet], None]] = []
        self._availability_listeners: list[Callable[[bool], None]] = []
        self._frames: deque[RawFrame] = deque(maxlen=RAW_FRAME_BUFFER)

    # --- registration ---------------------------------------------------------------------------

    def async_add_packet_listener(self, listener: Callable[[Packet], None]) -> Callable[[], None]:
        """Call *listener* for every decoded packet. Returns a function that unregisters it."""
        self._packet_listeners.append(listener)

        def _remove() -> None:
            self._packet_listeners.remove(listener)

        return _remove

    def async_add_availability_listener(
        self, listener: Callable[[bool], None]
    ) -> Callable[[], None]:
        """Call *listener* whenever the panel connects or goes silent."""
        self._availability_listeners.append(listener)

        def _remove() -> None:
            self._availability_listeners.remove(listener)

        return _remove

    # --- state ----------------------------------------------------------------------------------

    @property
    def connected(self) -> bool:
        """True while a socket is bound to this panel."""
        return self._connection is not None

    @property
    def frames(self) -> list[RawFrame]:
        """The recent raw frames, oldest first."""
        return list(self._frames)

    def record_frame(self, *, outbound: bool, data: bytes) -> None:
        """Add a frame to the diagnostics ring buffer."""
        self._frames.append(RawFrame(at=_utcnow(), outbound=outbound, data=data))

    # --- transport binding ----------------------------------------------------------------------

    def bind(self, connection: _PanelConnection) -> None:
        """Attach a freshly identified socket, replacing any previous one for this panel."""
        previous = self._connection
        self._connection = connection
        if previous is not None and previous is not connection:
            # A panel that redials before we noticed the old socket died. Drop the stale one without
            # touching availability: from the user's point of view the panel never went away.
            LOGGER.debug("%s: replacing a stale connection", self.serial)
            previous.close()
        else:
            self._notify_availability(True)

    def unbind(self, connection: _PanelConnection) -> None:
        """Detach *connection*, ignoring the call if a newer socket has already replaced it."""
        if self._connection is not connection:
            return
        self._connection = None
        self._notify_availability(False)

    # --- traffic --------------------------------------------------------------------------------

    def handle_packet(self, packet: Packet) -> None:
        """Record a decoded packet and fan it out to the listeners."""
        self.last_seen = _utcnow()
        if isinstance(packet, ConnectionInfo):
            self.info = packet
        elif isinstance(packet, PanelStatus):
            self.last_status = packet
        for listener in list(self._packet_listeners):
            listener(packet)

    def _notify_availability(self, available: bool) -> None:
        for listener in list(self._availability_listeners):
            listener(available)

    def _require_connection(self) -> _PanelConnection:
        connection = self._connection
        if connection is None:
            raise PanelNotConnectedError(f"panel {self.serial} is not connected")
        return connection

    async def async_request_status(self) -> None:
        """Ask the panel for a status frame. A read, so it runs even in read-only mode."""
        connection = self._require_connection()
        await connection.async_send(build_status_request(connection.next_seq()))

    async def async_send_command(self, builder: Callable[[int], bytes]) -> None:
        """Queue a command frame built by *builder*, which is handed the sequence byte.

        **Every control command goes through here**, so that the read-only check and the queue
        cannot be bypassed by a platform that reaches for the socket directly.
        """
        connection = self._require_connection()
        await connection.async_send(builder(connection.next_seq()))

    async def async_read_programming(self, address: int, count: int) -> ProgrammingBlock:
        """Read one block of the panel's programming and wait for it.

        **Correlated by the echoed selector, not by the sequence byte.** A `0x44` reply repeats the
        address and count it was asked for, which is a stronger match than a sequence counter that
        wraps at 255 — and a full read is thirty-odd requests on a link that is also carrying the
        status poll, so a mismatched reply would silently attribute one region's bytes to another.

        ⚠️ The block returned is raw programming and may contain user access codes. Parse it with
        `protocol.programming`; never log it.
        """
        connection = self._require_connection()
        seq = connection.next_seq()
        return await connection.async_read_programming(
            address, count, build_programming_read(seq, address, count)
        )

    async def async_read_wireless(self, page: int) -> WirelessInventory:
        """Read one page of the panel's wireless inventory (`0x59`) and wait for it."""
        connection = self._require_connection()
        seq = connection.next_seq()
        return await connection.async_read_wireless(seq, build_wireless_read(seq, page))

    async def async_read_events(self, cursor: int) -> EventBuffer:
        """Read one page of the panel's event buffer (`0x48`), forward from *cursor*.

        *cursor* is the highest event serial the caller already has; `0` starts at the oldest record
        the panel still holds. See `docs/protocol/event-buffer.md`.
        """
        connection = self._require_connection()
        seq = connection.next_seq()
        return await connection.async_read_events(seq, build_events_read(seq, cursor))

    async def async_send_authenticated(self, builder: Callable[[int], bytes]) -> CommandResponse:
        """Send a `0x37` command and wait for its acknowledgement.

        The authenticated family is the only one that acknowledges at all, and the only one that can
        lock the panel out, so its replies are correlated by sequence byte rather than assumed.
        """
        connection = self._require_connection()
        seq = connection.next_seq()
        return await connection.async_send_awaiting_ack(seq, builder(seq))


class _PanelConnection:
    """One socket. Lives from `accept` to close and knows which panel it carries."""

    def __init__(
        self,
        server: JflServer,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Wrap the stream pair a freshly accepted connection arrives as."""
        self._server = server
        self._reader = reader
        self._writer = writer
        self._frames = FrameReader()
        self._seq = Seq()
        self._write_lock = asyncio.Lock()
        self._tx: asyncio.Queue[bytes] = asyncio.Queue()
        self._pending: dict[int, asyncio.Future[CommandResponse]] = {}
        self._pending_blocks: dict[tuple[int, int], asyncio.Future[ProgrammingBlock]] = {}
        self._pending_inventory: dict[int, asyncio.Future[WirelessInventory]] = {}
        self._pending_events: dict[int, asyncio.Future[EventBuffer]] = {}
        """Keyed by the **echoed selector**, `(address, count)`, not by the sequence byte."""

        self._tx_task: asyncio.Task[None] | None = None
        self._closing = False

        peer = writer.get_extra_info("peername")
        self.address: str = f"{peer[0]}:{peer[1]}" if peer else "unknown"
        self.link: JflPanelLink | None = None

    # --- lifecycle ------------------------------------------------------------------------------

    def next_seq(self) -> int:
        """Allocate the next sequence byte for this panel. Never `0x00`."""
        return self._seq.next()

    async def run(self) -> None:
        """Read frames until the socket closes or the idle watchdog fires."""
        LOGGER.debug("connection opened from %s", self.address)
        self._tx_task = asyncio.create_task(self._drain_tx())
        try:
            await self._read_loop()
        except (TimeoutError, ConnectionResetError, BrokenPipeError, OSError) as err:
            LOGGER.debug("connection from %s ended: %s", self.address, err)
        finally:
            await self._shutdown()

    async def _read_loop(self) -> None:
        while True:
            try:
                data = await asyncio.wait_for(
                    self._reader.read(READ_CHUNK), timeout=self._watchdog_seconds()
                )
            except TimeoutError:
                # No forced disconnect while the panel is talking: we simply stop waiting and let
                # the panel redial. AGENTS.md's reference implementation, SIA, does the same.
                LOGGER.debug(
                    "%s: idle for more than %.0f s, closing so the panel redials",
                    self._who(),
                    self._watchdog_seconds(),
                )
                return
            if not data:
                LOGGER.debug("%s: closed by the panel", self._who())
                return
            await self._consume(data)

    def _watchdog_seconds(self) -> float:
        """Return how long silence is tolerated: `max(90 s, 2.5 x keep-alive)`."""
        return max(
            float(WATCHDOG_FLOOR_SECONDS),
            WATCHDOG_KEEPALIVE_FACTOR * self._server.keepalive_minutes * 60,
        )

    async def _shutdown(self) -> None:
        self._closing = True
        if self._tx_task is not None:
            self._tx_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._tx_task
        # Two dicts of differently-typed futures, so they are drained separately rather than
        # through a heterogeneous tuple that erases both element types to `object`.
        for acknowledgements in self._pending.values():
            if not acknowledgements.done():
                acknowledgements.cancel()
        for page in self._pending_events.values():
            if not page.done():
                page.cancel()
        for inventory in self._pending_inventory.values():
            if not inventory.done():
                inventory.cancel()
        for block in self._pending_blocks.values():
            if not block.done():
                block.cancel()
        self._pending.clear()
        self._pending_blocks.clear()
        self._pending_inventory.clear()
        self._pending_events.clear()
        if self.link is not None:
            self.link.unbind(self)
        self._server.forget(self)
        self._writer.close()
        with contextlib.suppress(ConnectionError, OSError):
            await self._writer.wait_closed()
        LOGGER.debug("connection from %s closed", self.address)

    def close(self) -> None:
        """Ask this connection to go away. Safe to call more than once."""
        self._closing = True
        self._writer.close()

    def _who(self) -> str:
        return self.link.serial if self.link is not None else self.address

    # --- receive --------------------------------------------------------------------------------

    async def _consume(self, data: bytes) -> None:
        try:
            frames = self._frames.feed(data)
        except JflProtocolError as err:
            # A frame the reader cannot even delimit. Never fatal — one panel speaking a dialect we
            # do not know must not take down a listener serving every other panel.
            LOGGER.debug("%s: undecodable input (%s), resynchronising", self._who(), err)
            self._frames.reset()
            return
        for frame in frames:
            await self._handle_frame(frame)

    async def _handle_frame(self, frame: Frame) -> None:
        if self._server.log_raw_frames:
            LOGGER.debug("%s: rx %s", self._who(), frame.raw.hex(" "))
        if self.link is not None:
            self.link.record_frame(outbound=False, data=frame.raw)

        # Acknowledge first, decode second. The panel retransmits anything it does not hear back,
        # and an event in particular repeats forever, so a decoding failure must not cost the ack.
        await self._acknowledge(frame)

        try:
            packet = decode(frame)
        except (JflProtocolError, ValueError, IndexError) as err:
            LOGGER.debug("%s: could not decode %s: %s", self._who(), frame, err)
            return

        LOGGER.debug("%s: rx %s", self._who(), type(packet).__name__)

        if isinstance(packet, ConnectionInfo):
            await self._identify(frame, packet)
            return
        if isinstance(packet, CommandResponse):
            self._resolve_pending(packet)
        if isinstance(packet, ProgrammingBlock):
            self._resolve_pending_block(packet)
        if isinstance(packet, WirelessInventory):
            self._resolve_pending_inventory(packet)
        if isinstance(packet, EventBuffer):
            self._resolve_pending_events(packet)
        if isinstance(packet, PanelEvent):
            LOGGER.debug(
                "%s: event %s partition %s subject %s",
                self._who(),
                packet.code,
                packet.partition,
                packet.subject,
            )
        if self.link is not None:
            self.link.handle_packet(packet)

    async def _acknowledge(self, frame: Frame) -> None:
        """Answer the three panel-initiated commands, ahead of the transmit queue."""
        if frame.cmd == Cmd.EVENT:
            counter = frame.slice(_EVENT_COUNTER_START, _EVENT_COUNTER_END)
            await self._write_now(build_event_ack(frame.seq, counter))
        elif frame.cmd == Cmd.KEEP_ALIVE:
            await self._write_now(
                build_keepalive_ack(frame.seq, keepalive_minutes=self._server.keepalive_minutes)
            )

    async def _identify(self, frame: Frame, info: ConnectionInfo) -> None:
        """Bind this socket to a panel and answer its connection frame.

        The acknowledgement echoes the **panel's** sequence byte, not one of ours — which is why the
        frame is threaded through here rather than only the decoded packet.
        """
        accepted = self._server.accepts(info)
        LOGGER.debug(
            "%s: connection frame from %s, model 0x%02X firmware %s, %s",
            info.serial,
            self.address,
            info.model_byte,
            info.firmware,
            "accepted" if accepted else "rejected",
        )
        ack = build_connection_ack(
            frame.seq, accept=accepted, keepalive_minutes=self._server.keepalive_minutes
        )
        if not accepted:
            await self._write_now(ack)
            self.close()
            return

        # Bind before writing, so both the introduction and its acknowledgement land in the
        # diagnostics ring buffer. A dump that starts after the handshake hides the handshake, which
        # is the part a connection bug is most likely to be in.
        link = self._server.link(info.serial)
        link.address = self.address
        self.link = link
        link.record_frame(outbound=False, data=frame.raw)
        link.bind(self)
        await self._write_now(ack)
        link.handle_packet(info)
        self._server.notify_connected(info)

    def _resolve_pending(self, response: CommandResponse) -> None:
        future = self._pending.pop(response.seq, None)
        if future is not None and not future.done():
            future.set_result(response)

    def _resolve_pending_inventory(self, inventory: WirelessInventory) -> None:
        """Hand a `0x59` page to whoever asked for it, if anyone did."""
        future = self._pending_inventory.pop(inventory.seq, None)
        if future is not None and not future.done():
            future.set_result(inventory)

    def _resolve_pending_events(self, page: EventBuffer) -> None:
        """Hand a `0x48` page to whoever asked for it, correlated by sequence byte.

        Like `0x59` and unlike `0x44`: the reply carries no copy of the cursor it answers, so the
        sequence byte is the only thing that distinguishes one page from the next.
        """
        future = self._pending_events.pop(page.seq, None)
        if future is not None and not future.done():
            future.set_result(page)

    def _resolve_pending_block(self, block: ProgrammingBlock) -> None:
        """Hand a programming block to whoever asked for that exact selector.

        An unsolicited block — one nobody is waiting for — is dropped rather than kept. It would
        mean another programmer is on the panel at the same time, and adopting its reply would mix
        two readers' views of the address space.
        """
        future = self._pending_blocks.pop((block.address, block.count), None)
        if future is not None and not future.done():
            future.set_result(block)

    # --- transmit -------------------------------------------------------------------------------

    async def _drain_tx(self) -> None:
        """Write queued frames one at a time, so two commands never interleave on the wire."""
        while True:
            frame = await self._tx.get()
            try:
                await self._write_now(frame)
            except (ConnectionError, OSError) as err:
                LOGGER.debug("%s: could not send: %s", self._who(), err)
            finally:
                self._tx.task_done()

    async def _write_now(self, frame: bytes) -> None:
        """Write immediately, bypassing the queue. Used for acknowledgements, which cannot wait."""
        if self._closing:
            return
        async with self._write_lock:
            if self._server.log_raw_frames:
                LOGGER.debug("%s: tx %s", self._who(), frame.hex(" "))
            if self.link is not None:
                self.link.record_frame(outbound=True, data=frame)
            self._writer.write(frame)
            await self._writer.drain()

    async def async_send(self, frame: bytes) -> None:
        """Queue *frame* behind anything already waiting to go out."""
        if self._closing:
            raise PanelNotConnectedError("connection is closing")
        await self._tx.put(frame)

    async def async_read_programming(
        self, address: int, count: int, frame: bytes
    ) -> ProgrammingBlock:
        """Queue a `0x44` request and wait for the reply carrying the same selector."""
        selector = (address, count)
        future: asyncio.Future[ProgrammingBlock] = asyncio.get_running_loop().create_future()
        self._pending_blocks[selector] = future
        try:
            await self.async_send(frame)
            async with asyncio.timeout(COMMAND_TIMEOUT):
                return await future
        finally:
            self._pending_blocks.pop(selector, None)

    async def async_read_wireless(self, seq: int, frame: bytes) -> WirelessInventory:
        """Queue a `0x59` request and wait for the page carrying the same sequence byte.

        Correlated by sequence rather than by the echoed selector the `0x44` path uses, because a
        `0x59` reply does not echo the page it answers — it carries only the records. The sequence
        byte is what distinguishes page 1's reply from page 2's.
        """
        future: asyncio.Future[WirelessInventory] = asyncio.get_running_loop().create_future()
        self._pending_inventory[seq] = future
        try:
            await self.async_send(frame)
            async with asyncio.timeout(COMMAND_TIMEOUT):
                return await future
        finally:
            self._pending_inventory.pop(seq, None)

    async def async_read_events(self, seq: int, frame: bytes) -> EventBuffer:
        """Queue a `0x48` request and wait for the page carrying the same sequence byte."""
        future: asyncio.Future[EventBuffer] = asyncio.get_running_loop().create_future()
        self._pending_events[seq] = future
        try:
            await self.async_send(frame)
            async with asyncio.timeout(COMMAND_TIMEOUT):
                return await future
        finally:
            self._pending_events.pop(seq, None)

    async def async_send_awaiting_ack(self, seq: int, frame: bytes) -> CommandResponse:
        """Queue *frame* and wait for the acknowledgement carrying the same sequence byte."""
        future: asyncio.Future[CommandResponse] = asyncio.get_running_loop().create_future()
        self._pending[seq] = future
        try:
            await self.async_send(frame)
            async with asyncio.timeout(COMMAND_TIMEOUT):
                return await future
        finally:
            self._pending.pop(seq, None)


def check_port_available(host: str, port: int) -> None:
    """Raise `OSError` if *host*:*port* is already bound by something else.

    A blocking, synchronous probe — bind immediately, then release. Callers on an event loop must
    run it in an executor, the same way `JflServer.async_start` itself never blocks the loop.

    Exists so a caller can give a specific "this port is taken" error *before* attempting
    `JflServer.async_start()`, which would otherwise raise the same `OSError` but only after the
    caller has already committed to starting up — a config flow wants to know first, while the user
    can still change their answer.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind((host, port))


class JflServer:
    """The listener. One per config entry, serving every panel that dials in to its port."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        keepalive_minutes: int = DEFAULT_KEEPALIVE_MINUTES,
        log_raw_frames: bool = False,
        unknown_panels: str = UNKNOWN_ACCEPT,
    ) -> None:
        """Configure a listener. Nothing is bound until `async_start` runs."""
        self.host = host
        self.port = port
        self.keepalive_minutes = keepalive_minutes
        self.log_raw_frames = log_raw_frames
        self.unknown_panels = unknown_panels

        self._server: asyncio.Server | None = None
        self._links: dict[str, JflPanelLink] = {}
        self._connections: set[_PanelConnection] = set()
        self._known: set[str] = set()
        self._pending_panels: dict[str, ConnectionInfo] = {}
        self._discovery: Callable[[ConnectionInfo], None] | None = None

    # --- lifecycle ------------------------------------------------------------------------------

    async def async_start(self) -> None:
        """Bind and start accepting. Raises `OSError` if the port is taken."""
        self._server = await asyncio.start_server(
            self._on_client, host=self.host, port=self.port, reuse_address=True
        )
        LOGGER.debug("listening on %s:%s", self.host, self.port)

    async def async_stop(self) -> None:
        """Close the listener and every panel socket, and actually free the port.

        **The panel sockets are closed before `wait_closed` is awaited, and that order is not
        cosmetic.** Since Python 3.12 `Server.wait_closed()` waits for the connection handlers to
        finish, and ours are parked in a socket read that only ends when the socket does. Closing
        the listener first and the connections afterwards deadlocks: unloading the config entry
        never returns, and the port is never freed. The tests catch this by connecting a panel and
        then unloading.
        """
        server = self._server
        self._server = None
        if server is not None:
            server.close()
        for connection in list(self._connections):
            connection.close()
        self._connections.clear()
        if server is not None:
            with contextlib.suppress(Exception):
                await server.wait_closed()
        LOGGER.debug("listener on %s:%s stopped", self.host, self.port)

    @property
    def is_running(self) -> bool:
        """True while the listener is bound."""
        return self._server is not None

    # --- panels ---------------------------------------------------------------------------------

    def link(self, serial: str) -> JflPanelLink:
        """Return the link for *serial*, creating it if this is the first mention of the panel."""
        if serial not in self._links:
            self._links[serial] = JflPanelLink(self, serial)
        return self._links[serial]

    @property
    def links(self) -> Iterator[JflPanelLink]:
        """Every panel this listener knows about, connected or not."""
        return iter(self._links.values())

    def async_set_known_panels(self, serials: set[str]) -> None:
        """Tell the listener which serials have a subentry, so the rest count as unknown."""
        self._known = set(serials)
        for serial in serials:
            self._pending_panels.pop(serial, None)

    @property
    def pending_panels(self) -> dict[str, ConnectionInfo]:
        """Panels that have dialled in without a subentry, offered by the "add panel" flow."""
        return dict(self._pending_panels)

    def async_set_discovery_callback(
        self, discovery: Callable[[ConnectionInfo], None] | None
    ) -> None:
        """Register what to do when an unconfigured panel identifies itself."""
        self._discovery = discovery

    def accepts(self, info: ConnectionInfo) -> bool:
        """Decide whether to answer a connection frame with `RESULT = 0x01`.

        Only the explicit *reject* policy refuses. Holding is not refusing: a held panel stays
        connected so the user can see it in the "add panel" list, which they cannot do if it has
        been disconnected before it finished introducing itself.
        """
        if info.serial in self._known:
            return True
        return self.unknown_panels != UNKNOWN_REJECT

    def notify_connected(self, info: ConnectionInfo) -> None:
        """Route a newly identified, unconfigured panel to whoever handles discovery."""
        if info.serial in self._known:
            return
        self._pending_panels[info.serial] = info
        if self.unknown_panels == UNKNOWN_ACCEPT and self._discovery is not None:
            self._discovery(info)

    # --- connection bookkeeping -----------------------------------------------------------------

    async def _on_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        connection = _PanelConnection(self, reader, writer)
        self._connections.add(connection)
        try:
            await connection.run()
        except asyncio.CancelledError:
            connection.close()
            raise
        except Exception:
            # One panel must never take down a listener that is serving every other panel, so the
            # catch is deliberately broad. This is genuinely an error: it means a bug in our code.
            LOGGER.exception("unhandled error on the connection from %s", connection.address)
            connection.close()

    def forget(self, connection: _PanelConnection) -> None:
        """Drop a closed connection from the bookkeeping set."""
        self._connections.discard(connection)
