"""Command builders, checked byte for byte against what ActiveNet actually sent.

Author: Jonis Maurin Ceará <jmceara AT gmail.com>
Based on the code developed by Carlos Jose Fernandes,
available at https://github.com/fernac03/JFL_ACTIVE

Sprint 1 task 1.4. The acceptance criterion is that every builder for an operating command
reproduces the corresponding captured frame exactly, sequence byte and checksum included. That is
what turns these from interpretations of a PDF into transcriptions.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from pyjfl.protocol.decode import decode
from pyjfl.protocol.encode import (
    FENCE_PARTITION,
    NO_PASSWORD,
    Password,
    Seq,
    build_arm,
    build_auth_fence,
    build_auth_pgm,
    build_bypass_bitmap,
    build_connection_ack,
    build_disarm,
    build_event_ack,
    build_fence_arm,
    build_fence_disarm,
    build_keepalive_ack,
    build_login,
    build_pgm_off,
    build_pgm_on,
    build_set_datetime,
    build_status_request,
)
from pyjfl.protocol.frames import Frame, is_valid
from pyjfl.protocol.models import Cmd, PanelEvent

Loader = Callable[[str], bytes]


# --- the acceptance criterion: byte-match the capture -------------------------------------------


@pytest.mark.parametrize(
    ("fixture", "builder"),
    [
        ("cmd-fence-arm-0x4E63.hex", lambda: build_fence_arm(0x1A)),
        ("cmd-fence-disarm-0x4F63.hex", lambda: build_fence_disarm(0x22)),
        ("cmd-part1-arm-0x4E01.hex", lambda: build_arm(0x6F, 1)),
        ("cmd-part1-disarm-0x4F01.hex", lambda: build_disarm(0x79, 1)),
        ("cmd-pgm2-on-0x5002.hex", lambda: build_pgm_on(0x45, 2)),
        ("cmd-pgm2-off-0x5102.hex", lambda: build_pgm_off(0x49, 2)),
        ("cmd-bypass-zone9-0x52.hex", lambda: build_bypass_bitmap(0x4F, {9})),
        ("cmd-unbypass-all-0x52.hex", lambda: build_bypass_bitmap(0x5F, set())),
    ],
    ids=lambda value: value if isinstance(value, str) else "",
)
def test_builder_reproduces_the_captured_frame(
    fixture: str, builder: Callable[[], bytes], load_frame: Loader
) -> None:
    """Sprint 1 task 1.4 acceptance, one row per operation captured on 2026-08-08."""
    assert builder() == load_frame(fixture)


def test_login_reproduces_the_captured_request(load_frame: Loader) -> None:
    """ActiveNet's login: `SENHA = FF FF FF`, `TP = 0x04` (Programador)."""
    assert build_login(0x01) == load_frame("login-request-0x43.hex")


# --- the fence, the project's primary goal ------------------------------------------------------


def test_fence_uses_partition_99_on_the_unauthenticated_path() -> None:
    """`7B 06 1A 4E 63 4A` — no password, no login, no lockout risk. docs/protocol/fence.md."""
    frame = Frame(build_fence_arm(0x1A))
    assert frame.cmd == Cmd.ARM
    assert frame.payload == bytes([FENCE_PARTITION])
    assert frame.checksum == 0x4A


def test_fence_defaults_to_the_path_with_no_lockout_risk() -> None:
    """Path A unless a password is explicitly supplied. The default must never be the risky one."""
    assert Frame(build_fence_arm(0x10)).cmd == Cmd.ARM
    assert Frame(build_fence_arm(0x10, password=Password("1234"))).cmd == Cmd.AUTH


def test_the_authenticated_fence_path_targets_partition_99_too() -> None:
    """Path B is `0x37`/`0xC1` with target `0x63`. Kept for diagnosis: it actually acknowledges."""
    frame = Frame(build_auth_fence(0x10, Password("1234"), arm=True))
    assert frame.cmd == Cmd.AUTH
    assert frame.payload[1] == 0xC1
    assert frame.payload[-1] == FENCE_PARTITION
    assert frame.payload[-2] == 0x01, "TIPO 0x01 arms"


# --- passwords must not be loggable -------------------------------------------------------------


def test_password_never_reveals_itself() -> None:
    """AGENTS.md §4: not in a log line, not in a diagnostics dump, not in a traceback."""
    password = Password("1234")
    assert repr(password) == "***"
    assert str(password) == "***"
    assert f"{password}" == "***"
    assert "1234" not in repr(password)
    assert "1234" not in f"careless log line: {password}"


def test_password_is_not_in_the_objects_dict() -> None:
    """`__slots__` keeps it out of `vars()`, which diagnostics helpers walk."""
    assert not hasattr(Password("1234"), "__dict__")


@pytest.mark.parametrize(
    ("digits", "expected"),
    [("1234", b"\x12\x34\xff"), ("123456", b"\x12\x34\x56"), ("0000", b"\x00\x00\xff")],
)
def test_password_encodes_as_bcd_with_ff_padding(digits: str, expected: bytes) -> None:
    """docs/protocol/commands.md: two digits per byte, a 4-digit code pads the third with `0xFF`."""
    assert Password(digits).encode() == expected


@pytest.mark.parametrize("bad", ["123", "12345", "abcd", "", "12 34"])
def test_password_rejects_anything_the_panel_would_not_accept(bad: str) -> None:
    with pytest.raises(ValueError, match="4 or 6 digits"):
        Password(bad)


def test_the_default_login_carries_no_password_at_all() -> None:
    """The capture's most consequential finding: the operating command set needs no password."""
    assert NO_PASSWORD == b"\xff\xff\xff"
    assert Frame(build_login(0x01)).payload[:3] == NO_PASSWORD


# --- replies to panel-initiated frames ----------------------------------------------------------


def test_connection_ack_echoes_the_panels_sequence_byte() -> None:
    """Captured: `7B 07 F9 21 01 05 A0`. Using our own counter makes the panel retransmit."""
    assert build_connection_ack(0xF9, keepalive_minutes=5) == bytes.fromhex("7B07F9210105A0")


def test_a_rejected_connection_sends_result_zero() -> None:
    assert Frame(build_connection_ack(0x10, accept=False)).payload[0] == 0x00


def test_keepalive_ack_carries_the_interval() -> None:
    frame = Frame(build_keepalive_ack(0x33, keepalive_minutes=5))
    assert frame.seq == 0x33
    assert frame.payload == bytes([0x05])


def test_event_ack_echoes_the_counter_verbatim(load_frame: Loader) -> None:
    """An unacknowledged event is retransmitted indefinitely, so this must be exact."""
    event = decode(Frame(load_frame("event-fence-1.hex")))
    assert isinstance(event, PanelEvent)
    ack = Frame(build_event_ack(event.seq, event.counter))
    assert ack.seq == event.seq
    assert ack.payload[1:5] == event.counter
    assert ack.length == 10


# --- other builders -----------------------------------------------------------------------------


def test_status_request_has_no_payload() -> None:
    """`7B 05 SEQ 4D K` — the shortest legal frame."""
    frame = Frame(build_status_request(0x03))
    assert frame.length == 5
    assert frame.payload == b""


def test_set_datetime_is_hour_first_unlike_the_status_clock() -> None:
    """Captured: `7B 0B 02 55 16 17 59 08 08 26 59` — 16:17:59 on 08/08/26.

    The status frame reports its clock **day first**. This command is the reverse, and nothing in
    the frame distinguishes them, so the order is asserted here rather than trusted.
    """
    built = build_set_datetime(0x02, hour=16, minute=17, second=59, day=8, month=8, year=2026)
    assert built == bytes.fromhex("7B0B025516175908082659")


@pytest.mark.parametrize(
    ("field", "value"),
    [("hour", 24), ("minute", 60), ("second", 60), ("day", 0), ("day", 32), ("month", 13)],
)
def test_set_datetime_rejects_impossible_values(field: str, value: int) -> None:
    """Range-checked, not merely BCD-checked.

    `99` encodes perfectly well as BCD but is not an hour, and a panel with a wrong clock timestamps
    every event it reports from then on.
    """
    fields: dict[str, int] = {
        "hour": 1,
        "minute": 2,
        "second": 3,
        "day": 4,
        "month": 5,
        "year": 2026,
    }
    fields[field] = value
    with pytest.raises(ValueError, match=f"{field} out of range"):
        build_set_datetime(0x01, **fields)  # type: ignore[arg-type]


def test_bypass_replaces_the_whole_bitmap_not_just_one_zone() -> None:
    """The command carries every inhibited zone, so a caller passing one zone clears the others."""
    frame = Frame(build_bypass_bitmap(0x10, {9, 10}))
    assert frame.payload[1] == 0b1100_0000, "MSB-first: bit 7 is zone 9, bit 6 zone 10"


def test_authenticated_pgm_uses_0xc7() -> None:
    """The PDF heading says `0xC7`, its example says `0xC3`. See docs/protocol/discrepancies.md."""
    assert Frame(build_auth_pgm(0x10, Password("1234"), 2, on=True)).payload[1] == 0xC7


# --- sequence allocation ------------------------------------------------------------------------


def test_sequence_never_yields_zero() -> None:
    """The specification forbids `0x00`. Panels emit it; we accept it and never send it."""
    seq = Seq(0xFE)
    assert [seq.next() for _ in range(4)] == [0xFE, 0xFF, 0x01, 0x02]


def test_sequence_clamps_a_bad_start() -> None:
    assert Seq(0).peek == 0x01
    assert Seq(-5).peek == 0x01
    assert Seq(0x100).peek == 0xFF


def test_peek_does_not_consume() -> None:
    seq = Seq(0x10)
    assert seq.peek == 0x10
    assert seq.peek == 0x10
    assert seq.next() == 0x10
    assert seq.peek == 0x11


# --- everything we build must be readable back --------------------------------------------------


@pytest.mark.parametrize(
    "builder",
    [
        lambda: build_fence_arm(0x1A),
        lambda: build_fence_disarm(0x22),
        lambda: build_arm(0x01, 1),
        lambda: build_disarm(0x01, 1),
        lambda: build_pgm_on(0x01, 2),
        lambda: build_bypass_bitmap(0x01, {1, 9, 32}),
        lambda: build_status_request(0x01),
        lambda: build_login(0x01, serial="123456789", client="home assistant"),
        lambda: build_connection_ack(0x01),
        lambda: build_keepalive_ack(0x01),
        lambda: build_event_ack(0x01, b"\x00\x00\x39\x19"),
        lambda: build_set_datetime(0x01, hour=1, minute=2, second=3, day=4, month=5, year=2026),
        lambda: build_auth_fence(0x01, Password("123456")),
    ],
)
def test_every_builder_emits_a_valid_frame(builder: Callable[[], bytes]) -> None:
    """Length byte, checksum and structure — a builder that produces junk must fail here."""
    assert is_valid(builder())
