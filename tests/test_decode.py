"""Decoding real captured frames into typed packets.

Sprint 1 task 1.3. Every assertion here is checked against a frame the panel actually sent on
2026-08-08, cross-referenced with what the ActiveNet UI displayed at that moment. Where the two
disagree with the specification, the panel wins.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from pyjfl.protocol.decode import (
    bcd_to_int,
    bitmap_to_flags,
    decode,
    decode_clock,
    flags_to_bitmap,
    nibbles_to_zones,
)
from pyjfl.protocol.frames import Frame
from pyjfl.protocol.models import (
    ConnectionInfo,
    PanelEvent,
    PanelStatus,
    UnknownPacket,
    ZoneStatus,
)

Loader = Callable[[str], bytes]


def _decode(load_frame: Loader, name: str) -> object:
    return decode(Frame(load_frame(name)))


# --- helpers -----------------------------------------------------------------------------------


def test_bcd_is_read_per_nibble() -> None:
    """docs/protocol/frame-format.md: `0x46` in a seconds field is 46 seconds, not 70."""
    assert bcd_to_int(0x46) == 46
    assert bcd_to_int(0x00) == 0
    assert bcd_to_int(0x59) == 59


def test_clock_is_day_first() -> None:
    """`DIA MES ANO HORA MIN SEG`. Reading it month-first silently shifts every timestamp."""
    assert decode_clock(bytes([0x08, 0x08, 0x26, 0x16, 0x22, 0x50])) == "08/08/26 16:22:50"


def test_clock_survives_a_short_field() -> None:
    """A malformed clock must never cost us the whole status frame."""
    assert decode_clock(b"\x08\x08") == ""


# --- the two opposite bitmaps ------------------------------------------------------------------


def test_p_inib_decodes_lsb_first_matching_the_panel_ui() -> None:
    """The specification is wrong about this one. docs/protocol/discrepancies.md.

    `P-INIB = 80 B7` was read from the panel while its own UI offered a bypass checkbox for zones
    8, 9, 10, 11, 13, 14 and 16 — and *not* for 1-7, 12 or 15. Decoded LSB-first it matches exactly,
    including both gaps. Decoded the documented way it would mean "only zone 1".
    """
    assert bitmap_to_flags(bytes([0x80, 0xB7]), lsb_first=True) == {8, 9, 10, 11, 13, 14, 16}


def test_the_bypass_command_encodes_msb_first() -> None:
    """The command really is MSB-first, proven by effect.

    ActiveNet sent byte 2 = `0x80` and zone 9 became inhibited. So the two bitmaps in this protocol
    genuinely disagree, and both directions need their own test.
    """
    assert flags_to_bitmap({9}, 13, lsb_first=False)[:2] == bytes([0x00, 0x80])


@pytest.mark.parametrize("lsb_first", [True, False])
@pytest.mark.parametrize(
    "zones",
    [set(), {1}, {8}, {9}, {1, 8, 9, 16}, {32}, set(range(1, 33)), {3, 17, 29}],
)
def test_bitmap_round_trips(zones: set[int], lsb_first: bool) -> None:
    """Sprint 1 task 1.3 acceptance: the two helpers must be exact inverses, both ways round."""
    encoded = flags_to_bitmap(zones, 13, lsb_first=lsb_first)
    assert bitmap_to_flags(encoded, lsb_first=lsb_first) == zones


def test_out_of_range_zones_are_ignored_rather_than_raising() -> None:
    """Asking to bypass zone 400 is recoverable; the panel would reject it anyway."""
    assert flags_to_bitmap({400}, 13, lsb_first=True) == bytes(13)


# --- zone nibbles ------------------------------------------------------------------------------


def test_zone_nibbles_are_high_first() -> None:
    """Byte 31's high nibble is zone 1, its low nibble zone 2: a third bit order in one frame."""
    zones = nibbles_to_zones(bytes([0x78]), limit=32)
    assert [(z.number, z.status) for z in zones] == [
        (1, ZoneStatus.OPEN),
        (2, ZoneStatus.CLOSED),
    ]


def test_disabled_zones_do_not_become_entities() -> None:
    """Nibble 0 means the zone is not in use on this installation, so it must not appear at all."""
    assert [z.number for z in nibbles_to_zones(bytes([0x08]), limit=32)] == [2]


def test_zone_limit_caps_at_the_model_size() -> None:
    """Reading the full 50-byte block on a 12-zone panel would invent 38 zones."""
    assert len(nibbles_to_zones(b"\x88" * 25, limit=12)) == 12


def test_an_undocumented_nibble_does_not_raise() -> None:
    """A firmware that grows a new state must not take the status frame down."""
    assert nibbles_to_zones(bytes([0x9F]), limit=32) == ()


# --- real frames -------------------------------------------------------------------------------


def test_connection_frame(load_frame: Loader) -> None:
    """The `0x21` frame, field by field, against the capture."""
    info = _decode(load_frame, "connection-0x21.hex")
    assert isinstance(info, ConnectionInfo)
    assert info.model_byte == 0xA0
    assert info.spec.name == "Active 32 Duo"
    assert info.firmware == "760", "firmware 7.60, not the 7.5 recorded earlier"
    assert info.partition_count == 1
    assert info.partitions[0].disarmed


def test_selet_is_at_offset_84_not_54(load_frame: Loader) -> None:
    """The root cause of the project's original bug.

    The old integration reads `SELET` at 54, lands inside the account field, finds `0x00` and
    concludes the panel has no electric fence. At 84 it reads `0x01`: the fence exists and is
    disarmed. See docs/protocol/fence.md.
    """
    info = _decode(load_frame, "connection-0x21.hex")
    assert isinstance(info, ConnectionInfo)
    assert info.fence.present
    assert info.fence.disarmed


def test_status_after_arming_the_fence(load_frame: Loader) -> None:
    """`ELET` at 30 went `0x01` -> `0x02`, and the alarm partitions were untouched."""
    status = _decode(load_frame, "status-after-fence-arm.hex")
    assert isinstance(status, PanelStatus)
    assert status.fence.armed
    assert not status.fence.triggered
    assert status.partitions[0].disarmed, "arming the fence must not touch partition 1"


def test_status_after_disarming_the_fence(load_frame: Loader) -> None:
    status = _decode(load_frame, "status-after-fence-disarm.hex")
    assert isinstance(status, PanelStatus)
    assert status.fence.disarmed
    assert status.fence.present


def test_battery_is_volts_not_a_percentage(load_frame: Loader) -> None:
    """`197 / 14 = 14.07 V`, which matched the 14,1 V the UI displayed.

    `Develop-2.0` invents percentage buckets from this byte and they are wrong.
    """
    status = _decode(load_frame, "status-after-fence-arm.hex")
    assert isinstance(status, PanelStatus)
    assert status.battery_volts == pytest.approx(14.07, abs=0.01)


def test_zone_9_was_open_and_everything_else_closed(load_frame: Loader) -> None:
    """Matched the panel's UI at the time of capture."""
    status = _decode(load_frame, "status-after-fence-arm.hex")
    assert isinstance(status, PanelStatus)
    open_zones = [z.number for z in status.zones if z.status is ZoneStatus.OPEN]
    assert open_zones == [9]


def test_bypassable_zones_match_the_ui(load_frame: Loader) -> None:
    """Zones 12 and 15 must be absent — the LSB-first proof, on a real frame."""
    status = _decode(load_frame, "status-after-fence-arm.hex")
    assert isinstance(status, PanelStatus)
    bypassable = {z.number for z in status.zones if z.may_bypass}
    assert 12 not in bypassable
    assert 15 not in bypassable
    assert {8, 9, 10, 11, 13, 14, 16} <= bypassable


def test_pgm_permissions_match_which_buttons_the_ui_enabled(load_frame: Loader) -> None:
    """`P-PGM = 0x0A` -> PGMs 2 and 4, exactly the two the UI offered. LSB is PGM 1."""
    status = _decode(load_frame, "status-after-fence-arm.hex")
    assert isinstance(status, PanelStatus)
    enabled = {n for n in range(1, 9) if status.pgm_permissions & (1 << (n - 1))}
    assert enabled == {2, 4}


def test_pgm_state_after_switching_pgm_2_on(load_frame: Loader) -> None:
    status = _decode(load_frame, "status-after-pgm-on.hex")
    assert isinstance(status, PanelStatus)
    assert status.pgm_on(2)
    assert not status.pgm_on(1)


def test_no_troubles_reported(load_frame: Loader) -> None:
    """`PROB` all zero matched the all-green problems display."""
    status = _decode(load_frame, "status-after-fence-arm.hex")
    assert isinstance(status, PanelStatus)
    assert not status.problems.any


def test_manual_bypass_shows_as_nibble_1(load_frame: Loader) -> None:
    """Zone 9 went `7` -> `1` when ActiveNet inhibited it."""
    status = _decode(load_frame, "status-after-bypass.hex")
    assert isinstance(status, PanelStatus)
    zone_9 = next(z for z in status.zones if z.number == 9)
    assert zone_9.status is ZoneStatus.BYPASSED


# --- events ------------------------------------------------------------------------------------


def test_fence_arm_event(load_frame: Loader) -> None:
    """Code 3407, partition 99, user `099` — not `000`, which is for the fence *alarm*."""
    event = _decode(load_frame, "event-fence-1.hex")
    assert isinstance(event, PanelEvent)
    assert event.code == "3407"
    assert event.partition == "99"
    assert event.is_fence
    assert event.subject == "099"


def test_spart_inside_the_event_carries_the_fence_state(load_frame: Loader) -> None:
    """A second independent signal for the same fact, sub-second and without polling."""
    event = _decode(load_frame, "event-fence-1.hex")
    assert isinstance(event, PanelEvent)
    assert event.fence.armed


def test_zone_alarm_event(load_frame: Loader) -> None:
    """The real alarm that went off during the capture: code 1130, zone 10, `SPART 0x82`."""
    event = _decode(load_frame, "event-zone-alarm-1130.hex")
    assert isinstance(event, PanelEvent)
    assert event.code == "1130"
    assert event.partition == "01"
    assert event.subject == "010"
    assert event.fence.armed and event.fence.triggered


def test_event_counter_stays_binary(load_frame: Loader) -> None:
    """It must be echoed verbatim in the acknowledgement, so it is never converted to text."""
    event = _decode(load_frame, "event-zone-alarm-1130.hex")
    assert isinstance(event, PanelEvent)
    assert isinstance(event.counter, bytes)
    assert len(event.counter) == 4


# --- dispatch ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path", sorted((Path(__file__).parent / "fixtures").glob("*.hex")), ids=lambda p: p.stem
)
def test_every_fixture_decodes_without_raising(path: Path, load_frame: Loader) -> None:
    """Sprint 1 task 1.3 acceptance: every fixture from Sprint 0 decodes."""
    assert decode(Frame(load_frame(path.name))) is not None


def test_an_unknown_command_is_returned_not_dropped() -> None:
    """Four undocumented commands were found precisely because they were not dropped silently."""
    frame = Frame(bytes([0x7B, 0x06, 0x01, 0x5A, 0x11, 0x00]))
    packet = decode(Frame(bytes([*frame.raw[:-1], 0])))
    assert isinstance(packet, UnknownPacket)
    assert packet.cmd == 0x5A


def test_a_short_command_frame_is_not_mistaken_for_a_status_frame() -> None:
    """`0x4E` appears on the frames we send too, and those carry no status."""
    packet = decode(Frame(bytes.fromhex("7B061A4E634A")))
    assert isinstance(packet, UnknownPacket)


# --- paths that only appear in less common frames -----------------------------------------------


def test_problem_flags_decode_from_the_prob_bytes() -> None:
    """`PROB` bit 0 of byte 2 is Ethernet, bit 7 is AC mains. docs/protocol/status-frame.md."""
    from pyjfl.protocol.decode import _problems
    from pyjfl.protocol.models import ProblemFlag

    problems = _problems(bytes([0x00, 0x81, 0x00, 0x00, 0x00]))
    assert problems.any
    assert ProblemFlag.ETHERNET in problems
    assert ProblemFlag.AC_MAINS in problems
    assert ProblemFlag.SIREN not in problems


def test_the_reserved_fifth_prob_byte_does_not_raise() -> None:
    """Byte 5 is documented as reserved; bits there have no flag and must be ignored quietly."""
    from pyjfl.protocol.decode import _problems

    assert not _problems(bytes([0x00, 0x00, 0x00, 0x00, 0xFF])).any


def test_keepalive_decodes() -> None:
    """`7B 05 SEQ 40 K`. It must be answered promptly or the panel gives up on us."""
    from pyjfl.protocol.encode import build_frame
    from pyjfl.protocol.models import Cmd, KeepAlive

    packet = decode(Frame(build_frame(0x21, Cmd.KEEP_ALIVE)))
    assert isinstance(packet, KeepAlive)
    assert packet.seq == 0x21


def test_login_reply_decodes() -> None:
    """The reply is 53 bytes, not the 51 the specification claims.

    Reconstructed from the capture: MOD at 4, VER at 5-7, RESULT at 8, KP at 9-10, serial at 11-20.
    """
    from pyjfl.protocol.frames import build_frame
    from pyjfl.protocol.models import Cmd, LoginInfo

    payload = bytes([0xA0]) + b"760" + bytes([0x01]) + b"\x88\x35" + b"2684645096"
    payload += b"\xff" * (49 - len(payload))
    packet = decode(Frame(build_frame(0x01, Cmd.LOGIN, payload)))
    assert isinstance(packet, LoginInfo)
    assert packet.accepted
    assert packet.model_byte == 0xA0
    assert packet.firmware == "760"
    assert packet.serial == "2684645096"


def test_a_rejected_login_is_not_accepted() -> None:
    from pyjfl.protocol.frames import build_frame
    from pyjfl.protocol.models import Cmd, LoginInfo

    payload = bytes([0xA0]) + b"760" + bytes([0x00]) + b"\xff" * 44
    packet = decode(Frame(build_frame(0x01, Cmd.LOGIN, payload)))
    assert isinstance(packet, LoginInfo)
    assert not packet.accepted


def test_monitor_status_decodes() -> None:
    """The 57-byte `0x93` reply. Inferred layout — see the docstring; no fixture exists."""
    from pyjfl.protocol.frames import build_frame
    from pyjfl.protocol.models import Cmd, MonitorStatus

    payload = bytearray(52)
    payload[35] = 0x02  # SELET at absolute 39
    payload[36] = 0x02  # SPART[0] at absolute 40
    packet = decode(Frame(build_frame(0x01, Cmd.MONITOR_STATUS, bytes(payload))))
    assert isinstance(packet, MonitorStatus)
    assert packet.fence.armed
    assert packet.partitions[0].armed


@pytest.mark.parametrize(
    ("resp", "ok", "dangerous"),
    [(0xBE, True, False), (0xA1, False, True), (0xAA, False, True), (0xA8, False, False)],
)
def test_authenticated_command_responses(resp: int, ok: bool, dangerous: bool) -> None:
    """AGENTS.md §6: `0xA1` and `0xAA` must be distinguishable from an ordinary refusal.

    On the first `0xA1` the caller has to stop. Five of them block remote operation at the panel
    until someone uses the keypad, so this must never be lumped in with "command refused".
    """
    from pyjfl.protocol.frames import build_frame
    from pyjfl.protocol.models import Cmd, CommandResponse

    packet = decode(Frame(build_frame(0x01, Cmd.AUTH, bytes([0x03, 0xC0, resp]))))
    assert isinstance(packet, CommandResponse)
    assert packet.ok is ok
    assert packet.locks_panel_out is dangerous


def test_an_unrecognised_ack_is_not_guessed_at() -> None:
    """Whether the panel is one wrong password from lockout must never rest on a guess."""
    from pyjfl.protocol.frames import build_frame
    from pyjfl.protocol.models import Cmd

    packet = decode(Frame(build_frame(0x01, Cmd.AUTH, bytes([0x03, 0xC0, 0x77]))))
    assert isinstance(packet, UnknownPacket)


def test_a_truncated_auth_reply_is_unknown() -> None:
    from pyjfl.protocol.frames import build_frame
    from pyjfl.protocol.models import Cmd

    assert isinstance(decode(Frame(build_frame(0x01, Cmd.AUTH, b"\x03"))), UnknownPacket)


def test_a_truncated_status_frame_does_not_raise() -> None:
    """Read defensively: a short frame must degrade, not take the connection down."""
    from pyjfl.protocol.decode import decode_status
    from pyjfl.protocol.frames import build_frame
    from pyjfl.protocol.models import Cmd

    status = decode_status(Frame(build_frame(0x01, Cmd.STATUS, bytes(80))))
    assert status.pgm_high == 0
    assert not status.updating


def test_pgm_out_of_range_is_rejected(load_frame: Loader) -> None:
    status = _decode(load_frame, "status-after-pgm-on.hex")
    assert isinstance(status, PanelStatus)
    with pytest.raises(ValueError, match="PGM out of range"):
        status.pgm_on(17)
