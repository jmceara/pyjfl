"""Build the frames this integration sends.

Source: `docs/protocol/commands.md`. **Every builder for an operating command is checked byte for
byte against a frame ActiveNet actually sent to the user's panel on 2026-08-08**, so these are
transcriptions rather than interpretations of the PDF.

Two things govern everything in this module:

* **Panel-initiated frames are answered with the panel's own sequence byte**, not ours. Getting this
  wrong makes the panel retransmit, and an event retransmits forever.
* **Prefer the unauthenticated path.** The capture proved every operation the integration needs is
  available without a password, which removes the only lockout hazard in the project. The
  authenticated family is here for diagnosis, kept behind explicit, intention-revealing names.
"""

from __future__ import annotations

from .decode import flags_to_bitmap
from .frames import build_frame
from .models import EVENTS_PER_PAGE, WIRELESS_PER_PAGE, AuthFunc, Cmd
from .programming import MAX_READ

FENCE_PARTITION = 0x63
"""Partition 99, the electric fence. See `docs/protocol/fence.md`."""

DEFAULT_KEEPALIVE_MINUTES = 5
"""What ActiveNet answers with. The protocol permits 1-20."""


class Seq:
    """Sequence-byte allocator.

    Runs `0x01`-`0xFF` and **never yields `0x00`**. The specification forbids zero; ActiveNet's own
    `protocolo/e.N()` wraps to it and therefore transmits it, so we accept zero on receive and never
    send it. See `docs/protocol/discrepancies.md`.
    """

    def __init__(self, start: int = 1) -> None:
        """Begin at *start*, clamped into the legal range."""
        self._value = max(1, min(0xFF, start))

    def next(self) -> int:
        """Return the current value and advance, wrapping `0xFF` back to `0x01`."""
        value = self._value
        self._value = 1 if value >= 0xFF else value + 1
        return value

    @property
    def peek(self) -> int:
        """The value `next()` will return, without consuming it."""
        return self._value


class Password:
    """A panel user code that cannot be logged by accident.

    AGENTS.md §4 forbids a password reaching a log line, a diagnostics dump or a traceback. Making
    the *type* redact itself means that holds even in code nobody reviewed: an f-string, a `repr()`
    in a traceback and a careless `LOGGER.debug("%s", password)` all print `***`.

    The digits are reachable only through `encode()`, which is called at the moment the frame is
    built and nowhere else.
    """

    __slots__ = ("_digits",)

    def __init__(self, digits: str) -> None:
        """Store *digits*, which must be 4 or 6 numeric characters."""
        cleaned = digits.strip()
        if not cleaned.isdigit() or len(cleaned) not in (4, 6):
            raise ValueError("panel password must be 4 or 6 digits")
        self._digits = cleaned

    def encode(self) -> bytes:
        """Return the three BCD bytes for the wire.

        Source: `docs/protocol/commands.md`. Two digits per byte; a 4-digit code pads the third byte
        with `0xFF`, so `1234` becomes `12 34 FF` and `123456` becomes `12 34 56`.
        """
        padded = self._digits.ljust(6, "F")
        return bytes(int(padded[offset : offset + 2], 16) for offset in (0, 2, 4))

    def __repr__(self) -> str:
        """Never reveal the digits. AGENTS.md §4."""
        return "***"

    __str__ = __repr__


NO_PASSWORD = b"\xff\xff\xff"
"""What ActiveNet logs in with, and what the panel accepts.

`SENHA = FF FF FF` with `TP = 0x04` (Programador) returned `RESULT = 0x01` from the real panel. This
is the single most consequential finding of the capture: **no panel password is used anywhere in the
operating command set**, so the lockout hazard the project was designed around does not apply.
"""


# --- replies to panel-initiated frames ----------------------------------------------------------


def build_connection_ack(
    panel_seq: int, *, accept: bool = True, keepalive_minutes: int = DEFAULT_KEEPALIVE_MINUTES
) -> bytes:
    """Answer a `0x21` connection frame: `7B 07 SEQ 21 RESULT KEEPALIVE K`.

    `RESULT` `0x01` accepts, `0x00` rejects and the panel disconnects. Echoes the **panel's**
    sequence byte. Captured: `7B 07 F9 21 01 05 A0`.
    """
    result = 0x01 if accept else 0x00
    return build_frame(panel_seq, Cmd.CONNECTION, bytes([result, keepalive_minutes]))


def build_keepalive_ack(
    panel_seq: int, *, keepalive_minutes: int = DEFAULT_KEEPALIVE_MINUTES
) -> bytes:
    """Answer a `0x40` keep-alive: `7B 06 SEQ 40 KEEPALIVE K`. Interval in minutes, 1-20."""
    return build_frame(panel_seq, Cmd.KEEP_ALIVE, bytes([keepalive_minutes]))


def build_event_ack(panel_seq: int, counter: bytes) -> bytes:
    """Answer a `0x24` event: `7B 0A SEQ 24 OK CONTADOR[4] K`.

    **Echo `counter` verbatim** — it is binary, not ASCII like the fields around it. And acknowledge
    the event *even when decoding it failed*: an unacknowledged event is retransmitted indefinitely,
    so a decoding bug would otherwise become a flood.
    """
    return build_frame(panel_seq, Cmd.EVENT, bytes([0x01]) + counter[:4].ljust(4, b"\x00"))


# --- unauthenticated commands, path A -----------------------------------------------------------
#
# None of these carries a password and none can lock the panel out. All were captured from
# ActiveNet driving the user's Active 32 Duo. The reply to every one of them is a full status
# frame with the command byte echoed — there is no acknowledgement in this family.


def build_status_request(seq: int) -> bytes:
    """Request a status refresh: `7B 05 SEQ 4D K`. No payload."""
    return build_frame(seq, Cmd.STATUS)


def build_arm(seq: int, partition: int) -> bytes:
    """Arm a partition, or the fence with `partition=0x63`. Captured: `7B 06 6F 4E 01 5D`."""
    return build_frame(seq, Cmd.ARM, bytes([partition]))


def build_disarm(seq: int, partition: int) -> bytes:
    """Disarm a partition, or the fence. Captured: `7B 06 79 4F 01 4A`."""
    return build_frame(seq, Cmd.DISARM, bytes([partition]))


def build_arm_stay(seq: int, partition: int) -> bytes:
    """Arm a partition in stay mode: `7B 06 SEQ 53 PART K`. Documented, not captured."""
    return build_frame(seq, Cmd.ARM_STAY, bytes([partition]))


def build_arm_away(seq: int, partition: int) -> bytes:
    """Arm a partition in away mode: `7B 06 SEQ 54 PART K`. Documented, not captured.

    Note the panel does not distinguish arm from arm-away in its *events* — both emit `3407`. The
    mode is only readable from `PART[i]`.
    """
    return build_frame(seq, Cmd.ARM_AWAY, bytes([partition]))


def build_pgm_on(seq: int, pgm: int) -> bytes:
    """Switch a PGM on. Captured: `7B 06 45 50 02 6A`.

    ⚠️ The PGM programmed with **function 18 drives the electric fence**. Switching it off turns the
    fence off, so it must never be exposed as an ordinary toggle. See `docs/protocol/fence.md`.
    """
    return build_frame(seq, Cmd.PGM_ON, bytes([pgm]))


def build_pgm_off(seq: int, pgm: int) -> bytes:
    """Switch a PGM off. Captured: `7B 06 49 51 02 67`. See the warning on `build_pgm_on`."""
    return build_frame(seq, Cmd.PGM_OFF, bytes([pgm]))


def build_bypass_bitmap(seq: int, zones: frozenset[int] | set[int]) -> bytes:
    """Set the manual-bypass bitmap: `7B 12 SEQ 52 INIBE[13] K`.

    **The bitmap is MSB-first**: bit 7 of byte 1 is zone 1. This is the opposite of `P-INIB` in the
    status frame, which is LSB-first despite the specification claiming both are MSB-first. See
    `docs/protocol/discrepancies.md`; getting it backwards inhibits the wrong zones silently.

    The command replaces the whole bitmap, so pass **every** zone that should stay inhibited, not
    only the one being changed. An empty set clears all bypasses, captured as thirteen zero bytes.

    Captured, bypassing zone 9: `7B 12 4F 52 00 80` followed by eleven zero bytes and `F4`.
    """
    return build_frame(seq, Cmd.BYPASS, flags_to_bitmap(zones, 13, lsb_first=False))


def build_set_datetime(
    seq: int, *, hour: int, minute: int, second: int, day: int, month: int, year: int
) -> bytes:
    """Set the panel clock: `7B 0B SEQ 55 HORA MIN SEG DIA MES ANO K`, all BCD.

    **The order is hour first, and it is the reverse of the clock the status frame reports**, which
    is day first. Captured: `7B 0B 02 55 16 17 59 08 08 26 59` — 16:17:59 on 08/08/26.

    `year` is the last two digits.

    Each field is range-checked, not merely BCD-checked: `99` encodes perfectly well as BCD but is
    not an hour, and a panel with a wrong clock timestamps every event it reports from then on.
    """
    for value, low, high, name in (
        (hour, 0, 23, "hour"),
        (minute, 0, 59, "minute"),
        (second, 0, 59, "second"),
        (day, 1, 31, "day"),
        (month, 1, 12, "month"),
    ):
        if not low <= value <= high:
            raise ValueError(f"{name} out of range: {value}")

    values = (hour, minute, second, day, month, year % 100)
    return build_frame(seq, Cmd.SET_DATETIME, bytes(_to_bcd(value) for value in values))


def _to_bcd(value: int) -> int:
    """Encode 0-99 as one 'por nibble' BCD byte, high nibble first."""
    if not 0 <= value <= 99:
        raise ValueError(f"cannot BCD-encode {value}")
    return ((value // 10) << 4) | (value % 10)


def build_login(
    seq: int, *, serial: str = "", client: str = "", password: bytes = NO_PASSWORD
) -> bytes:
    """Log in: `7B 2B SEQ 43 SENHA[3] TP NS[9] CLIENTE[24] NOTIF K`.

    Defaults to exactly what ActiveNet sends: `SENHA = FF FF FF`, `TP = 0x04` (Programador). The
    panel replies `RESULT = 0x01`. The specification's own note is explicit — *"Quando logado
    através do software receptor de eventos deve-se enviar 0xFF, 0xFF, 0xFF"*.
    """
    payload = bytearray(password[:3].ljust(3, b"\xff"))
    payload.append(0x04)  # TP: Programador
    payload += serial.encode("ascii", "ignore")[:9].ljust(9, b"\xff")
    payload += client.encode("ascii", "ignore")[:24].ljust(24, b"\xff")
    payload.append(0xFF)  # NOTIF
    return build_frame(seq, Cmd.LOGIN, bytes(payload))


def build_monitor_status_request(seq: int) -> bytes:
    """Request the monitoring-station view: `7B 05 SEQ 93 K`. Reply is 57 bytes."""
    return build_frame(seq, Cmd.MONITOR_STATUS)


def build_programming_read(seq: int, address: int, count: int) -> bytes:
    """Read a block of the programming: `7B 08 SEQ 44 AH AL N K`. Always 8 bytes.

    Source: `docs/protocol/programming.md`. The selector is a **big-endian start address and a byte
    count**, not an opaque block id — proven by ActiveNet's 39 reads tiling the space contiguously,
    each starting exactly where the previous one ended. Captured: `7B 08 02 44 00 00 60 55`.

    `count` is capped at `MAX_READ` (112), the largest ActiveNet ever asks for. Nothing has asked
    the panel for more, so nothing knows what it does with more.

    ⚠️ This command reads a space that contains **every user's access code** in clear. Parse the
    reply with `programming.parse_users`, which never returns one.
    """
    if not 0 <= address <= 0xFFFF:
        raise ValueError(f"programming address out of range: {address:#06x}")
    if not 0 < count <= MAX_READ:
        raise ValueError(f"programming read count must be 1-{MAX_READ}, got {count}")
    return build_frame(seq, Cmd.READ_PROGRAMMING, bytes([address >> 8, address & 0xFF, count]))


def build_wireless_read(seq: int, page: int, *, per_page: int = WIRELESS_PER_PAGE) -> bytes:
    """Read one page of the wireless device inventory: `7B 07 SEQ 59 08 PAGE K`.

    Source: `docs/protocol/programming.md`, where the reply is fully decoded. Pages are zero-based
    and the panel **packs only populated slots into a page**, so page 0 of a nine-device panel
    returned slots 1-6, 10 and 11 — the record's own index byte is the true slot, and a page is
    never partly wasted.

    This is live device data — last transmission time, link quality, open/closed — where the
    `0x1800` programming table is the static enrolment list. They cross-validate.
    """
    if page < 0:
        raise ValueError(f"wireless page cannot be negative: {page}")
    return build_frame(seq, Cmd.READ_WIRELESS, bytes([per_page, page]))


def build_events_read(seq: int, cursor: int, *, per_page: int = EVENTS_PER_PAGE) -> bytes:
    """Read one page of the panel's event buffer: `7B 0A SEQ 48 08 SS SS SS SS K`.

    Source: `docs/protocol/event-buffer.md`, decoded from the programmer's *Baixar buffer* on
    2026-08-09. *cursor* is the **event serial to page forward from**, big-endian — the highest
    serial the caller already holds. `0` starts at the oldest record the panel still keeps.

    **Paging is forward only, from oldest to newest.** There is no "give me the last twenty": the
    only way to reach the newest record is to walk. That is a property of the panel, not a
    limitation of this builder, and it is why the caller decides how far to go.
    """
    if cursor < 0 or cursor > 0xFFFFFFFF:
        raise ValueError(f"event cursor out of range: {cursor}")
    return build_frame(seq, Cmd.READ_EVENTS, bytes([per_page, *cursor.to_bytes(4, "big")]))


# --- the electric fence, both paths -------------------------------------------------------------


def build_fence_arm(seq: int, *, password: Password | None = None) -> bytes:
    """Arm the electric fence.

    Path A by default, which is what the capture proved works::

        7B 06 SEQ 4E 63 K        captured: 7B 06 1A 4E 63 4A

    Passing *password* switches to the authenticated path B (`0x37`/`0xC1`), which returns a real
    acknowledgement and is therefore useful for diagnosis — at the cost of the lockout risk. Path A
    needs no password and cannot lock the panel out, so it stays the default.
    """
    if password is None:
        return build_arm(seq, FENCE_PARTITION)
    return build_auth_fence(seq, password=password, arm=True)


def build_fence_disarm(seq: int, *, password: Password | None = None) -> bytes:
    """Disarm the electric fence. Path A captured: `7B 06 22 4F 63 73`. See `build_fence_arm`."""
    if password is None:
        return build_disarm(seq, FENCE_PARTITION)
    return build_auth_fence(seq, password=password, arm=False)


# --- authenticated commands, path B -------------------------------------------------------------
#
# ⚠️ AGENTS.md §6. Five wrong passwords block remote operation at the panel until someone performs
# a valid keypad operation. **Stop after the first 0xA1 reply.** There must be no retry loop
# anywhere near this family. Nothing in the integration's normal operation needs it.


def build_auth(seq: int, func: AuthFunc, password: Password, *, kind: int, target: int) -> bytes:
    """Build an authenticated command: `7B 0C SEQ 37 07 FUNC SENHA[3] TIPO TARGET K`.

    Prefer the intention-revealing wrappers below; they exist so that a reader can see at a glance
    which operation a call performs, rather than decoding two integers.
    """
    payload = bytes([0x07, func]) + password.encode() + bytes([kind, target])
    return build_frame(seq, Cmd.AUTH, payload)


def build_auth_arm(seq: int, password: Password, partition: int, *, arm: bool = True) -> bytes:
    """Arm or disarm a partition with a password. `TIPO` `0x01` arms, `0x00` disarms."""
    return build_auth(
        seq, AuthFunc.ARM_DISARM, password, kind=0x01 if arm else 0x00, target=partition
    )


def build_auth_fence(seq: int, password: Password, *, arm: bool = True) -> bytes:
    """Arm or disarm the fence with a password: the same function, target `0x63`.

    This is the path the specification documents for the fence. It is **not** needed — path A works
    — but it acknowledges, so it can tell you *why* a command was refused.
    """
    return build_auth_arm(seq, password, FENCE_PARTITION, arm=arm)


def build_auth_bypass(seq: int, password: Password, zone: int) -> bytes:
    """Bypass a single zone with a password. Target is a zone number, `0x01`-`0x63`."""
    return build_auth(seq, AuthFunc.BYPASS, password, kind=0x00, target=zone)


def build_auth_pgm(seq: int, password: Password, pgm: int, *, on: bool) -> bytes:
    """Switch a PGM with a password.

    Uses `0xC7`. The PDF's §5 heading says `0xC7` while its example frame says `0xC3`; the heading
    is consistent with the rest of the function list and the example is not, so the heading wins.
    Unresolved on hardware — see `docs/protocol/discrepancies.md`.
    """
    return build_auth(seq, AuthFunc.PGM, password, kind=0x01 if on else 0x00, target=pgm)
