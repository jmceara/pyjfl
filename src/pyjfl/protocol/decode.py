"""Turn validated frames into typed packets.

Every offset here is **absolute**, indexed straight into the frame exactly as the JFL PDFs number
their fields, via `Frame.byte()` and `Frame.slice()`. Doing arithmetic against the payload instead
is how the old integration ended up reading partitions at 13 and `SELET` at 54.

Sources: `docs/protocol/status-frame.md`, `commands.md`, `fence.md`, `discrepancies.md`.

Dispatch is on **`frame.cmd`**, never on the length of the data. The old integration dispatches on
`len(recv())`, which is why it drops frames whenever TCP coalesces two of them.
"""

from __future__ import annotations

from .frames import Frame
from .models import (
    EVENT_RECORD_SIZE,
    Cmd,
    CommandAck,
    CommandResponse,
    ConnectionInfo,
    EventBuffer,
    EventRecord,
    FencePermissions,
    FenceState,
    KeepAlive,
    LoginInfo,
    LoginResult,
    MonitorStatus,
    Packet,
    PanelEvent,
    PanelStatus,
    PartitionPermissions,
    PartitionState,
    ProblemFlag,
    Problems,
    ProgrammingBlock,
    UnknownPacket,
    WirelessDevice,
    WirelessInventory,
    ZoneState,
    ZoneStatus,
)
from .programming import INVENTORY_RECORD_SIZE

# --- helpers ------------------------------------------------------------------------------------


def bcd_to_int(byte: int) -> int:
    """Decode one 'por nibble' BCD byte: high nibble first.

    `docs/protocol/frame-format.md`: `0x46` in a seconds field is 46 seconds, not 70.
    """
    return (byte >> 4) * 10 + (byte & 0x0F)


def decode_clock(data: bytes) -> str:
    """Decode the six-byte `HORA` field to `DD/MM/YY HH:MM:SS`.

    **The order is day first**: `DIA MES ANO HORA MIN SEG`, all BCD. Returns an empty string for a
    short or absent field rather than raising — a malformed clock must never cost us a status frame.
    """
    if len(data) < 6:
        return ""
    day, month, year, hour, minute, second = (bcd_to_int(byte) for byte in data[:6])
    return f"{day:02d}/{month:02d}/{year:02d} {hour:02d}:{minute:02d}:{second:02d}"


def bitmap_to_flags(data: bytes, *, lsb_first: bool) -> frozenset[int]:
    """Decode a zone bitmap to a set of 1-based numbers.

    **The direction is not a detail — the two bitmaps in this protocol disagree.** See
    `docs/protocol/discrepancies.md`:

    * `P-INIB` (offsets 104-116) is **LSB-first**: bit 0 of byte 1 is zone 1. The specification says
      otherwise and is wrong. Proven against the panel's own UI: `P-INIB = 80 B7 …` matched exactly
      which zones offered a bypass checkbox, including both gaps at zones 12 and 15.
    * The `0x52` bypass **command** is **MSB-first**: bit 7 of byte 1 is zone 1. Proven by effect —
      ActiveNet sent byte 2 = `0x80` and zone 9 became inhibited.

    Read the wrong way round, this ships bypass switches on the wrong zones and looks fine.
    """
    numbers: set[int] = set()
    for index, byte in enumerate(data):
        for bit in range(8):
            mask = (1 << bit) if lsb_first else (0x80 >> bit)
            if byte & mask:
                numbers.add(index * 8 + bit + 1)
    return frozenset(numbers)


def flags_to_bitmap(numbers: frozenset[int] | set[int], length: int, *, lsb_first: bool) -> bytes:
    """Encode 1-based numbers into a bitmap. The exact inverse of `bitmap_to_flags`.

    Numbers beyond `length * 8` are ignored rather than raising: a caller asking to bypass zone 40
    on a twelve-zone panel has made a recoverable mistake, and the panel would reject it anyway.
    """
    buffer = bytearray(length)
    for number in numbers:
        index, bit = divmod(number - 1, 8)
        if 0 <= index < length:
            buffer[index] |= (1 << bit) if lsb_first else (0x80 >> bit)
    return bytes(buffer)


def nibbles_to_zones(
    data: bytes, *, limit: int, bypassable: frozenset[int] = frozenset()
) -> tuple[ZoneState, ...]:
    """Decode the `ZONA` block to zone states.

    Two zones share a byte, **high nibble first**: byte 31's high nibble is zone 1 and its low
    nibble is zone 2. This is a third bit order, distinct from both bitmaps above.

    Zones reading `DISABLED` are dropped — they do not exist on this installation and must not
    become entities. `limit` caps the result at the model's zone count, because reading the full
    50-byte block on a twelve-zone panel would invent thirty-eight zones.
    """
    zones: list[ZoneState] = []
    for index, byte in enumerate(data):
        for half, nibble in enumerate(((byte >> 4) & 0x0F, byte & 0x0F)):
            number = index * 2 + half + 1
            if number > limit:
                return tuple(zones)
            status = _zone_status(nibble)
            if status is not ZoneStatus.DISABLED:
                zones.append(ZoneState(number, status, number in bypassable))
    return tuple(zones)


def _zone_status(nibble: int) -> ZoneStatus:
    """Map a nibble to `ZoneStatus`, treating an undocumented value as disabled.

    Undocumented nibbles must not raise: a firmware that grows a new state would otherwise take the
    whole status frame down.
    """
    try:
        return ZoneStatus(nibble)
    except ValueError:
        return ZoneStatus.DISABLED


def _problems(data: bytes) -> Problems:
    """Decode the five `PROB` bytes to a set of flags, bit 0 first."""
    active = {
        flag
        for index, byte in enumerate(data)
        for bit in range(8)
        if byte & (1 << bit)
        for flag in [_problem_flag(index * 8 + bit)]
        if flag is not None
    }
    return Problems(frozenset(active))


def _problem_flag(position: int) -> ProblemFlag | None:
    """Map a flat bit index to a flag, ignoring the reserved fifth byte."""
    try:
        return ProblemFlag(position)
    except ValueError:
        return None


def _text(data: bytes) -> str:
    """Decode an ASCII field, dropping the `0xFF` padding JFL uses."""
    return bytes(byte for byte in data if byte not in (0xFF, 0x00)).decode("latin-1").strip()


# --- per-command decoders -----------------------------------------------------------------------


def decode_connection(frame: Frame) -> ConnectionInfo:
    """Decode the 102-byte `0x21` connection frame. Source: `docs/protocol/commands.md`.

    Layout, absolute::

        4-13   NS serial      14-28  IMEI          29-40  MAC       41  MOD
        42-44  VER            45-48  IP/SIM/via/operator
        49     signal         50     problem       51     partition count
        52-83  accounts       84     SELET         85-100 SPART

    `SELET` is at **84**. The old integration reads 54, which lands inside the account field, always
    finds `0x00`, and concludes the panel has no electric fence. That is the root cause of the
    project's original bug. See `docs/protocol/fence.md`.
    """
    partitions: tuple[PartitionState, ...] = ()
    fence = FenceState(0x00)
    if len(frame.raw) > 100:
        fence = FenceState(frame.byte(84))
        partitions = tuple(PartitionState(byte) for byte in frame.slice(85, 101))

    version = _text(frame.slice(42, 45))
    return ConnectionInfo(
        serial=_text(frame.slice(4, 14)),
        model_byte=frame.byte(41),
        firmware=version,
        mac=_text(frame.slice(29, 41)),
        imei=_text(frame.slice(14, 29)),
        partition_count=frame.byte(51) if len(frame.raw) > 51 else 0,
        # STATUS[52] is signal(1) problem(1) partition count(1) accounts(32) SELET(1) SPART(16),
        # so the signal level is the first of them, at absolute offset 49.
        signal=frame.byte(49) if len(frame.raw) > 49 else 0,
        fence=fence,
        partitions=partitions,
    )


def decode_event(frame: Frame) -> PanelEvent:
    """Decode the 24-byte `0x24` Contact ID event. Source: `docs/protocol/commands.md`.

    Layout, absolute::

        4-7   CONTA     8-11  EVENTO    12-13 PARTICAO
        14-16 USUA/ZONA 17-20 CONTADOR  21    SPART      22 PROB

    The subject field is at **`raw[14:17]`**. The `Develop-2.0` branch reads `raw[12:16]`, which
    mixes the partition into the zone number.

    `SPART` carries the fence state, which is a second independent signal for the same fact — the
    `ELET` byte in the status frame being the first, and the Contact ID code with partition 99 the
    third.
    """
    return PanelEvent(
        account=_text(frame.slice(4, 8)),
        code=_text(frame.slice(8, 12)),
        partition=_text(frame.slice(12, 14)),
        subject=_text(frame.slice(14, 17)),
        counter=frame.slice(17, 21),
        fence=FenceState(frame.byte(21)) if len(frame.raw) > 22 else FenceState(0x00),
        problem=frame.byte(22) if len(frame.raw) > 23 else 0,
        seq=frame.seq,
    )


def decode_status(frame: Frame) -> PanelStatus:
    """Decode the status frame — the reply to `0x4D`/`0x56` and to every path-A command.

    Source: `docs/protocol/status-frame.md`. Read defensively rather than asserting a length:
    firmware 7.60 sends **127 bytes, not the documented 123**, with the extra bytes at the tail, and
    every documented offset up to 116 still holds.

    Three separate bit orders meet in this one frame, which is the easiest place in the project to
    write a subtle, dangerous bug:

    * `PGM` (13), `PGM2` (117), `P-PGM` (87), `P-PGM2` (118) — **LSB** is PGM 1.
    * `P-INIB` (104-116) — **LSB** is the lowest zone, contrary to the specification.
    * `ZONA` (31-80) — **high nibble** is the lower zone number.
    """
    raw = frame.raw
    size = len(raw)

    bypassable: frozenset[int] = frozenset()
    if size > 117:
        # P-INIB is LSB-first. See bitmap_to_flags and docs/protocol/discrepancies.md.
        bypassable = bitmap_to_flags(frame.slice(104, 117), lsb_first=True)

    return PanelStatus(
        programming_checksum=frame.slice(4, 6),
        clock=decode_clock(frame.slice(6, 12)),
        # Expose the voltage. Never invent percentage buckets: Develop-2.0 did, and they are wrong.
        battery_volts=frame.byte(12) / 14,
        pgm=frame.byte(13),
        # Partitions start at 14. The old integration reads 13, so its partition 1 is the PGM byte.
        partitions=tuple(PartitionState(byte) for byte in frame.slice(14, 30)),
        fence=FenceState(frame.byte(30)),
        zones=nibbles_to_zones(frame.slice(31, 81), limit=100, bypassable=bypassable),
        problems=_problems(frame.slice(81, 86)),
        fence_permissions=FencePermissions(frame.byte(86) if size > 86 else 0),
        pgm_permissions=frame.byte(87) if size > 87 else 0,
        pgm_permissions_high=frame.byte(118) if size > 118 else 0,
        partition_permissions=tuple(PartitionPermissions(byte) for byte in frame.slice(88, 104)),
        # PGM2 is at 117. The old integration reads 116, which is the last P-INIB byte.
        pgm_high=frame.byte(117) if size > 117 else 0,
        siren=frame.byte(120) if size > 120 else 0,
        updating=bool(frame.byte(121)) if size > 121 else False,
        seq=frame.seq,
    )


def decode_keepalive(frame: Frame) -> KeepAlive:
    """Decode the five-byte `0x40` keep-alive. Answer promptly or the panel gives up on us."""
    return KeepAlive(seq=frame.seq)


def decode_login(frame: Frame) -> LoginInfo:
    """Decode the `0x43` login reply. Source: `docs/protocol/observed-frames.md`.

    The reply is **53 bytes, not the 51 the specification claims**::

        4  MOD    5-7  VER    8  RESULT    9-10  KP    11-20 NS    21-35 IMEI    36-47 MAC

    Direction is resolved by length, not by command byte: both the request and the reply are `0x43`.
    That is not the same as dispatching on length — the command byte still selects the decoder; the
    length only distinguishes which side of the exchange this frame is.
    """
    if frame.length < 50:
        # The 43-byte request: SENHA[3] TP NS[9] CLIENTE[24] NOTIF. ActiveNet sends SENHA = FF FF FF
        # and TP = 0x04 (Programador), and the panel accepts it. No panel password is used anywhere
        # in the operating command set.
        return LoginInfo(result=LoginResult.REJECTED, seq=frame.seq)

    result = LoginResult.ACCEPTED if frame.byte(8) == 0x01 else LoginResult.REJECTED
    return LoginInfo(
        result=result,
        model_byte=frame.byte(4),
        firmware=_text(frame.slice(5, 8)),
        serial=_text(frame.slice(11, 21)),
        # The board revision is in the tail, after the 12-byte MAC (offset 36-47). On the captured
        # panel it reads `54 03 31 30`, whose digits "10" the app displays as 1.0. Scanning only the
        # tail avoids the digits inside the serial and the MAC earlier in the frame.
        hardware_version=_hardware_version(frame.slice(48, frame.length - 1))
        if frame.length > 51
        else "",
        seq=frame.seq,
    )


def _hardware_version(tail: bytes) -> str:
    """Extract a board revision like *1.0* from the `0x43` reply's tail.

    The tail is `54 03 31 30` on the captured panel; only the ASCII digits are meaningful, and the
    first is the major and the rest the minor — `"10"` → `"1.0"`. The `54 03` prefix's meaning is
    unconfirmed and deliberately ignored rather than guessed at. See
    `docs/protocol/observed-frames.md`.
    """
    digits = "".join(chr(byte) for byte in tail if 0x30 <= byte <= 0x39)
    if len(digits) >= 2:
        return f"{digits[0]}.{digits[1:]}"
    return digits


def decode_monitor_status(frame: Frame) -> MonitorStatus:
    """Decode the 57-byte `0x93` monitoring-station reply.

    The layout mirrors the `STATUS[52]` block of the connection frame, which is what makes 57 add up
    (4 header + 52 + 1 checksum)::

        4 signal   5 problem   6 partition count   7-38 accounts   39 SELET   40-55 SPART

    **Inferred, not captured** — there is no `0x93` fixture, because ActiveNet never issued one in
    the 2026-08-08 session. Verify before relying on it. See `docs/protocol/fence.md`, which notes
    this reply carries two fence values the 123-byte frame does not: `0x04` and `0x84`.
    """
    size = len(frame.raw)
    return MonitorStatus(
        signal=frame.byte(4) if size > 4 else 0,
        accounts=tuple(frame.slice(offset, offset + 2).hex().upper() for offset in range(7, 39, 2))
        if size > 38
        else (),
        fence=FenceState(frame.byte(39)) if size > 39 else FenceState(0x00),
        partitions=tuple(PartitionState(byte) for byte in frame.slice(40, 56)) if size > 55 else (),
        seq=frame.seq,
    )


def decode_command_response(frame: Frame) -> Packet:
    """Decode the reply to an authenticated `0x37` command: `7B 08 SEQ 37 03 C0 RESP K`.

    `RESP` is at absolute offset 6. An unrecognised value returns `UnknownPacket` rather than
    guessing, because the caller's next decision — whether the panel is one wrong password closer to
    locking out — must never rest on a guess. See AGENTS.md §6.
    """
    if len(frame.raw) < 8:
        return UnknownPacket(cmd=frame.cmd, payload=frame.payload, seq=frame.seq)
    try:
        ack = CommandAck(frame.byte(6))
    except ValueError:
        return UnknownPacket(cmd=frame.cmd, payload=frame.payload, seq=frame.seq)
    return CommandResponse(ack=ack, seq=frame.seq)


def decode_programming(frame: Frame) -> Packet:
    """Decode a `0x44` reply: `7B LL SEQ 44 | AH AL N | KP1 KP2 | <N bytes> | K`.

    Source: `docs/protocol/programming.md`. The **selector is echoed verbatim**, which is what lets
    a reply be matched to its request without trusting the sequence byte.

    A frame whose length does not match its own `N` becomes an `UnknownPacket` rather than a block
    with a short `data`: the alternative is silently parsing records out of somebody else's bytes,
    and this is the one command whose payload contains access codes.

    ⚠️ The returned `data` is raw programming. Parse it with `protocol.programming`; never log it.
    """
    if frame.length < 10:
        # Our own 8-byte *request* also carries 0x44. It is not a reply and has no data.
        return UnknownPacket(cmd=frame.cmd, payload=frame.payload, seq=frame.seq)
    address = (frame.byte(4) << 8) | frame.byte(5)
    count = frame.byte(6)
    data = frame.slice(9, 9 + count)
    if len(data) != count:
        return UnknownPacket(cmd=frame.cmd, payload=frame.payload, seq=frame.seq)
    return ProgrammingBlock(
        address=address,
        count=count,
        checksum=frame.slice(7, 9),
        data=data,
        seq=frame.seq,
    )


def decode_wireless(frame: Frame) -> Packet:
    """Decode a `0x59` reply: `7B 86 SEQ 59 | 08 | <8 x 16-byte records> | K`.

    Source: `docs/protocol/programming.md`, where every field was verified against the panel's own
    UI. Unused records are filled with `0xFF` and are dropped here — the panel packs only populated
    slots into a page, so the record's **index byte is the true slot**, not its position.
    """
    if frame.length < 6:
        return UnknownPacket(cmd=frame.cmd, payload=frame.payload, seq=frame.seq)

    devices: list[WirelessDevice] = []
    offset = 5
    while offset + INVENTORY_RECORD_SIZE <= frame.length - 1:
        raw = frame.slice(offset, offset + INVENTORY_RECORD_SIZE)
        offset += INVENTORY_RECORD_SIZE
        if len(raw) < INVENTORY_RECORD_SIZE or raw[0] in (0x00, 0xFF):
            continue
        devices.append(
            WirelessDevice(
                slot=raw[0],
                serial=int.from_bytes(raw[1:5], "big"),
                zone=raw[5],
                open=raw[7] == 0x01,
                last_seen=decode_wireless_clock(raw[8:14]),
                repeater=raw[15] >> 4,
                link=raw[15] & 0x0F,
                raw=raw,
                # Offset 6 as nibble pair (0x40 -> "4.0"); offset 14 the low-battery flag. Both
                # confirmed against the UI on 2026-08-09 — see docs/protocol/programming.md.
                firmware=f"{raw[6] >> 4}.{raw[6] & 0x0F}",
                low_battery=raw[14] != 0x00,
            )
        )
    return WirelessInventory(devices=tuple(devices), seq=frame.seq)


def decode_events(frame: Frame) -> Packet:
    """Decode a `0x48` event-buffer reply into its 14-byte records.

    **Fully decoded 2026-08-09.** ::

        7B LL SEQ 48 | 08 | <8 x 14-byte records> | K

    Source: `docs/protocol/event-buffer.md`, confirmed over 1073 records from one download. The `08`
    after the command is the records-per-page count the request asked for. Empty and terminator
    slots (`serial` all-`00` or all-`FF`) are dropped, matching the wireless decoder's treatment of
    unused slots.

    Our own *request* also carries `0x48` and is ten bytes; it is not a reply and holds no records,
    so it returns `UnknownPacket` via the length guard in `decode()`.
    """
    records: list[EventRecord] = []
    offset = 5
    while offset + EVENT_RECORD_SIZE <= frame.length - 1:
        raw = frame.slice(offset, offset + EVENT_RECORD_SIZE)
        offset += EVENT_RECORD_SIZE
        serial = int.from_bytes(raw[0:4], "big")
        if serial in (0x00000000, 0xFFFFFFFF):
            continue
        records.append(
            EventRecord(
                serial=serial,
                # Two BCD bytes whose hex digits *are* the Contact ID digits: 0x13 0x81 -> "1381".
                contact_id=f"{raw[4]:02X}{raw[5]:02X}",
                subject=raw[6],
                partition=raw[7],
                timestamp=decode_wireless_clock(raw[8:14]),
            )
        )
    return EventBuffer(records=tuple(records), seq=frame.seq)


def decode_wireless_clock(data: bytes) -> str:
    """Decode a wireless record's six BCD bytes: `DD MM YY HH MM SS`.

    The same order as the status frame's clock and the **reverse** of what `0x55` takes, which is
    hour-first. Returns an empty string rather than raising: a malformed timestamp must not cost the
    device that carries it.
    """
    if len(data) < 6 or any((byte >> 4) > 9 or (byte & 0x0F) > 9 for byte in data[:6]):
        return ""
    day, month, year, hour, minute, second = (bcd_to_int(byte) for byte in data[:6])
    return f"{day:02d}/{month:02d}/{year:02d} {hour:02d}:{minute:02d}:{second:02d}"


# --- dispatch -----------------------------------------------------------------------------------

_STATUS_COMMANDS = frozenset(
    {
        Cmd.STATUS,
        Cmd.STATUS_USER,
        Cmd.ARM,
        Cmd.DISARM,
        Cmd.PGM_ON,
        Cmd.PGM_OFF,
        Cmd.BYPASS,
        Cmd.ARM_STAY,
        Cmd.ARM_AWAY,
        Cmd.SET_DATETIME,
    }
)
"""Commands the panel answers with a full status frame, echoing the command byte.

**There is no acknowledgement anywhere in this family.** Verify a command took effect by reading the
relevant byte of the reply — and then read the status again, because the reply is not final: arming
returned a frame still showing zone 9 open, and the panel auto-bypassed it a second later,
announcing that only via event 1570.
"""


def decode(frame: Frame) -> Packet:
    """Decode *frame* into a typed packet.

    Dispatches on `frame.cmd`. An unrecognised command becomes an `UnknownPacket` carrying its raw
    payload rather than being dropped — logged at debug, that is how the next undocumented command
    gets found. Four commands were discovered exactly that way in the 2026-08-08 capture.
    """
    cmd = frame.cmd

    if cmd == Cmd.CONNECTION:
        return decode_connection(frame)
    if cmd == Cmd.EVENT:
        return decode_event(frame)
    if cmd == Cmd.KEEP_ALIVE:
        return decode_keepalive(frame)
    if cmd == Cmd.LOGIN:
        return decode_login(frame)
    if cmd == Cmd.AUTH:
        return decode_command_response(frame)
    if cmd == Cmd.MONITOR_STATUS:
        return decode_monitor_status(frame)
    if cmd == Cmd.READ_PROGRAMMING:
        return decode_programming(frame)
    if cmd == Cmd.READ_WIRELESS:
        return decode_wireless(frame)
    if cmd == Cmd.READ_EVENTS and frame.length > 0x0A:
        # Length guards out our own ten-byte request, which also carries 0x48.
        return decode_events(frame)
    if cmd in _STATUS_COMMANDS and frame.length > 100:
        # Length is a guard, not the dispatch: these command bytes also appear on the frames *we*
        # send, which are five or six bytes long and carry no status.
        return decode_status(frame)

    return UnknownPacket(cmd=cmd, payload=frame.payload, seq=frame.seq)
