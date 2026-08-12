"""Decoding the fields recovered from the 2026-08-09 comprehensive ActiveNet capture.

Author: Jonis Maurin Ceará <jmceara AT gmail.com>

Sprint 8, tasks 8.3-8.8. Every frame built here is assembled from bytes the panel actually sent on
2026-08-09, cross-referenced with what the ActiveNet UI displayed at that moment — the same method
as `test_decode.py`. The raw log lives outside the repository (it is non-redacted); these literals
are the specific, non-sensitive record bodies each assertion needs.

What each test pins down is documented in `docs/captures/2026-08-09-decode.md` and folded into
`docs/protocol/programming.md`, `docs/protocol/event-buffer.md` and the code under test.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from pyjfl.protocol.decode import decode
from pyjfl.protocol.frames import Frame, build_frame
from pyjfl.protocol.models import (
    Cmd,
    EventBuffer,
    LoginInfo,
    SignalQuality,
    WirelessInventory,
)
from pyjfl.protocol.programming import (
    ZONE_TYPE_NAMES,
    HolidayRecord,
    ZoneRecord,
    parse_holidays,
)


def _decode(seq: int, cmd: int, payload: bytes) -> object:
    """Wrap a command's payload in a valid frame and decode it, checksum and all."""
    return decode(Frame(build_frame(seq, cmd, payload)))


# --- 0x59 wireless inventory: model, firmware, signal, low battery, repeater --------------------

# Two real records from page 0 of the 2026-08-09 inventory. Serials are printed on the detectors and
# already appear in docs/protocol/programming.md; they are not secrets.
_WIRELESS_ZONE_14 = bytes.fromhex("01B205AF2A0E40000908261719300004")
_WIRELESS_ZONE_20 = bytes.fromhex("04BA009B811440000908261650220014")


def test_wireless_signal_scale_is_confirmed() -> None:
    """The low nibble of offset 15 is the signal scale: 4 = Excelente, confirmed against the UI."""
    packet = _decode(0x3F, Cmd.READ_WIRELESS, b"\x08" + _WIRELESS_ZONE_14 + _WIRELESS_ZONE_20)
    assert isinstance(packet, WirelessInventory)
    by_zone = {device.zone: device for device in packet.devices}

    assert by_zone[14].signal is SignalQuality.EXCELLENT
    assert by_zone[20].signal is SignalQuality.EXCELLENT


def test_wireless_model_comes_from_the_serial_high_byte() -> None:
    """`0xB2` is an IRD-650, `0xBA` an SL-320 DUO+ — the "+" variant carries a different byte."""
    packet = _decode(0x3F, Cmd.READ_WIRELESS, b"\x08" + _WIRELESS_ZONE_14 + _WIRELESS_ZONE_20)
    assert isinstance(packet, WirelessInventory)
    by_zone = {device.zone: device for device in packet.devices}

    assert by_zone[14].model == "IRD-650 DUO"
    assert by_zone[14].serial == 2986716970
    assert by_zone[20].model == "SL-320 DUO+"


def test_wireless_firmware_and_battery_and_repeater() -> None:
    """Offset 6 is firmware (0x40 -> 4.0), 14 the battery flag, 15's high nibble the repeater."""
    packet = _decode(0x3F, Cmd.READ_WIRELESS, b"\x08" + _WIRELESS_ZONE_14 + _WIRELESS_ZONE_20)
    assert isinstance(packet, WirelessInventory)
    by_zone = {device.zone: device for device in packet.devices}

    assert by_zone[14].firmware == "4.0"
    assert by_zone[14].low_battery is False
    assert by_zone[14].repeater == 0
    assert by_zone[20].repeater == 1  # "via repetidor 1" in the UI


def test_wireless_unknown_serial_byte_yields_no_model() -> None:
    """An unmapped family byte must resolve to None, never a guessed model name."""
    unknown = bytes([0x01, 0xC7, 0x00, 0x00, 0x01, 0x05, 0x40, 0x00]) + bytes(8)
    packet = _decode(0x01, Cmd.READ_WIRELESS, b"\x08" + unknown)
    assert isinstance(packet, WirelessInventory)
    assert packet.devices[0].model is None


# --- 0x48 event buffer --------------------------------------------------------------------------

# A supervision fault on zone 21 (partition 1) and a fence disarm (partition 99) — real records.
_EVENT_SUPERVISION = bytes.fromhex("0000350113811501210326155023")
_EVENT_FENCE_DISARM = bytes.fromhex("0000379814070063150726112442")


def test_event_buffer_record_layout() -> None:
    """14-byte record: serial(4) + Contact ID(2 BCD) + subject + partition + BCD timestamp(6)."""
    packet = _decode(0x5F, Cmd.READ_EVENTS, b"\x08" + _EVENT_SUPERVISION + _EVENT_FENCE_DISARM)
    assert isinstance(packet, EventBuffer)
    assert len(packet.records) == 2

    supervision = packet.records[0]
    assert supervision.serial == 0x3501
    assert supervision.contact_id == "1381"
    assert supervision.subject == 21
    assert supervision.partition == 1
    assert supervision.timestamp == "21/03/26 15:50:23"
    assert supervision.is_fence is False


def test_event_buffer_marks_fence_events() -> None:
    """Partition 99 is the electric fence, in the buffer exactly as in the live event stream."""
    packet = _decode(0x5F, Cmd.READ_EVENTS, b"\x08" + _EVENT_SUPERVISION + _EVENT_FENCE_DISARM)
    assert isinstance(packet, EventBuffer)
    fence = packet.records[1]
    assert fence.contact_id == "1407"
    assert fence.partition == 99
    assert fence.is_fence is True


def test_event_buffer_drops_empty_slots() -> None:
    """Terminator slots (all 0xFF or all 0x00) are not events and must not appear."""
    terminator = b"\xff" * 14
    packet = _decode(0x5F, Cmd.READ_EVENTS, b"\x08" + _EVENT_SUPERVISION + terminator)
    assert isinstance(packet, EventBuffer)
    assert len(packet.records) == 1


def test_event_request_is_not_decoded_as_a_reply() -> None:
    """Our own ten-byte 0x48 request carries no records — it must not decode to an EventBuffer."""
    request = decode(Frame(build_frame(0x5F, Cmd.READ_EVENTS, b"\x08\x00\x00\x34\x57")))
    assert not isinstance(request, EventBuffer)


# --- 0x43 login reply: the hardware version -----------------------------------------------------


def test_login_reply_carries_the_hardware_version() -> None:
    """The board revision is in the 0x43 tail (`54 03 31 30` -> "10" -> 1.0), not in `0x21`."""
    payload = (
        bytes([0xA0])  # model
        + b"760"  # firmware
        + bytes([0x01])  # result = accepted
        + bytes([0xD9, 0xBF])  # KP
        + b"0000000000"  # serial (synthetic)
        + b"\xff" * 15  # IMEI absent
        + b"000000000000"  # MAC (synthetic)
        + bytes([0x54, 0x03])
        + b"10"  # hardware-version tail
    )
    packet = decode(Frame(build_frame(0x01, Cmd.LOGIN, payload)))
    assert isinstance(packet, LoginInfo)
    assert packet.accepted
    assert packet.hardware_version == "1.0"


# --- zone record: type nibble and the chime bit -------------------------------------------------


def test_zone_chime_bit_is_confirmed() -> None:
    """Marking Chime on zone 21 flipped attribute byte 3 from 0x21 to 0x61 — bit 0x40, alone."""
    chime_on = ZoneRecord(21, "Rad Escri", bytes.fromhex("10 FF FF 61 81 FF FF".replace(" ", "")))
    chime_off = ZoneRecord(21, "Rad Escri", bytes.fromhex("10 FF FF 21 81 FF FF".replace(" ", "")))
    assert chime_on.chime is True
    assert chime_off.chime is False


def test_zone_type_index_is_the_low_nibble_and_none_when_disabled() -> None:
    """The type is the low nibble of attribute byte 0; a disabled zone (0x00) has no type."""
    enabled = ZoneRecord(10, "I Cozinha", bytes.fromhex("12 FF FF 11 01 FF FF".replace(" ", "")))
    disabled = ZoneRecord(12, "ZONA 12", bytes.fromhex("00 FF FF 11 01 FF FF".replace(" ", "")))
    assert enabled.enabled is True
    assert enabled.zone_type_index == 2
    assert disabled.enabled is False
    assert disabled.zone_type_index is None


def test_the_zone_type_labels_are_only_the_anchored_ones() -> None:
    """The value space is **not** a dense index of the app's nine-entry list, and this holds it.

    Five labels map to 0-4 in list order, and then the last of the nine jumps to **9**: zone 22 was
    set to *24 horas tamper* and the panel was written `0x19`. So two codes exist that the app never
    offers, and the two labels with no code are *Ronda* and *24 horas pânico*.

    Every assertion below is a real observation from the 2026-08-09 session. The negative ones are
    the point of the test: reading the dropdown straight down and calling 5 *Ronda*, 6 *24 horas
    pânico* and 7 *24 horas tamper* is exactly what this table did until 2026-08-10, and three of
    those eight labels were wrong. ADR-0013.
    """
    assert ZONE_TYPE_NAMES == {
        0: "Imediata",
        1: "Temporizada 1",
        2: "Temporizada 2",
        3: "Seguidora",
        4: "24 horas",
        9: "24 horas tamper",
    }
    for unproven in (5, 6, 7, 8):
        assert unproven not in ZONE_TYPE_NAMES, (
            f"{unproven} has no labelled observation; a name here would be a confident falsehood"
        )


# --- holidays at 0x0000 -------------------------------------------------------------------------


def test_holidays_are_bcd_day_month_pairs() -> None:
    """The 0x0000 region opens with the panel's holidays as DD/MM BCD pairs."""
    block = bytes.fromhex(
        "01012104010507091210021115112512" + "0101" * 8  # eight programmed  # unused slots
    )
    holidays = parse_holidays(block, 0x0000)
    assert len(holidays) == 16
    assert holidays[0] == HolidayRecord(index=1, day=1, month=1)
    assert holidays[3].formatted == "07/09"  # Independência
    assert holidays[7].formatted == "25/12"  # Natal
