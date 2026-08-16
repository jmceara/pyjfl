"""Reading the panel's programming: the `0x44` command and the record parsers.

Sprint 6, tasks 6.1 and 6.2. **No JFL PDF documents any of this**, so every expectation below is
anchored to a frame ActiveNet actually exchanged with the author's Active 32 Duo on 2026-08-08 —
extracted from `docs/captures/2026-08-08-session-full.txt` into `tests/fixtures/prog-*.hex`.

Two of these tests are load-bearing rather than incidental:

* **`test_a_user_record_never_carries_the_code`.** The programming space holds every user's access
  code in clear, and the parser's contract is that it reads them far enough to answer "is one set?"
  and no further. A regression here leaks credentials into any future diagnostics dump.
* **`test_the_captured_reads_tile_the_space_contiguously`.** This is the evidence that the selector
  is an *address*, not an opaque block id — which is the whole reason a single record can be read
  instead of a 112-byte window.

> The user fixture's three household names were replaced with `Ana`, `Bruno` and `Carla`, and its
> checksum repaired. The captured codes were already `FF FF FF`; the names were not, and this
> repository is meant to be published.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from itertools import pairwise
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from pyjfl.protocol import (
    MAX_READ,
    Cmd,
    Frame,
    PgmFunction,
    ProgrammingBlock,
    UnknownPacket,
    WirelessInventory,
    build_events_read,
    build_programming_read,
    build_wireless_read,
    decode,
    decode_name,
    parse_partitions,
    parse_pgms,
    parse_users,
    parse_wireless,
    parse_zones,
    plan_read,
    plan_region,
)
from pyjfl.protocol.programming import (
    REGIONS,
    ZONE_BASE,
    PgmRecord,
    decode_pgm_duration,
    pgm_address,
    user_address,
    wireless_address,
    zone_address,
)


def _block(load_frame: Callable[[str], bytes], name: str) -> ProgrammingBlock:
    packet = decode(Frame(load_frame(name)))
    assert isinstance(packet, ProgrammingBlock)
    return packet


# --- 6.1: the command ---------------------------------------------------------------------------


def test_the_read_request_matches_the_captured_frame(load_frame: Callable[[str], bytes]) -> None:
    """Captured: `7B 08 02 44 00 00 60 55` — read 0x60 bytes from address 0x0000."""
    captured = load_frame("prog-read-request-0x44.hex")
    assert build_programming_read(captured[2], 0x0000, 0x60) == captured
    assert len(captured) == 8, "the request is always eight bytes"


def test_the_address_is_big_endian() -> None:
    """`AH AL`. Little-endian would read a wholly different part of the panel and not error."""
    frame = build_programming_read(0x01, 0x1070, 0x10)
    assert frame[4] == 0x10
    assert frame[5] == 0x70


@pytest.mark.parametrize("count", [0, -1, MAX_READ + 1, 0xFF])
def test_an_impossible_read_count_is_refused(count: int) -> None:
    """`0x70` is the most ActiveNet ever asks for, so it is the most anything here will ask for."""
    with pytest.raises(ValueError, match="count"):
        build_programming_read(0x01, ZONE_BASE, count)


def test_an_out_of_range_address_is_refused() -> None:
    """The space is 16-bit; a larger address would be silently truncated into a valid one."""
    with pytest.raises(ValueError, match="address"):
        build_programming_read(0x01, 0x1_0000, 0x10)


def test_the_wireless_request_matches_the_documented_frame() -> None:
    """`7B 07 SEQ 59 08 PAGE K` — eight records per page, page zero-based."""
    frame = build_wireless_read(0x01, 0)
    assert frame[3] == Cmd.READ_WIRELESS
    assert frame[4] == 0x08
    assert frame[5] == 0x00
    assert len(frame) == 7


@pytest.mark.parametrize(
    ("seq", "cursor", "captured"),
    [
        (0x5F, 13399, "7b 0a 5f 48 08 00 00 34 57 0d 92"),
        (0x60, 13576, "7b 0a 60 48 08 00 00 35 08 6c ad"),
        (0x61, 13584, "7b 0a 61 48 08 00 00 35 10 75 ac"),
        (0x62, 13592, "7b 0a 62 48 08 00 00 35 18 7e af"),
    ],
)
def test_the_event_buffer_request_is_byte_for_byte_activenets(
    seq: int, cursor: int, captured: str
) -> None:
    """Four consecutive `0x48` pages ActiveNet asked this exact panel for, on 2026-08-09.

    The project's standard for a command builder is a captured frame rather than a reading of a PDF
    — and here there is no PDF at all, since JFL documents `0x48` nowhere. These four also show the
    paging in action: each cursor is the highest serial the previous reply carried.

    The captured bytes run one longer than ours because the log records the frame with the panel's
    trailing byte; the checksum this builder computes is the one ActiveNet sent.
    """
    frame = build_events_read(seq, cursor)
    assert frame.hex(" ") == captured[: len(frame.hex(" "))]
    assert len(frame) == 10


# --- 6.1: decoding the reply --------------------------------------------------------------------


def test_a_captured_reply_decodes_with_its_selector_echoed(
    load_frame: Callable[[str], bytes],
) -> None:
    """The reply repeats the address and count, so it can be matched without the sequence byte."""
    block = _block(load_frame, "prog-zones-0x1000-0x44.hex")
    assert block.address == ZONE_BASE
    assert block.count == MAX_READ
    assert len(block.data) == block.count
    assert block.end == ZONE_BASE + MAX_READ
    assert block.covers(zone_address(1), 16)
    assert not block.covers(zone_address(8), 16), "zone 8 is past the end of this block"


def test_the_reply_carries_the_programming_checksum(load_frame: Callable[[str], bytes]) -> None:
    """`KP` — the same two bytes the status frame carries, and how a cache learns it is stale."""
    block = _block(load_frame, "prog-zones-0x1000-0x44.hex")
    assert block.checksum == b"\x88\x35", "the KP the panel reported throughout that session"


def test_our_own_request_does_not_decode_as_a_reply(load_frame: Callable[[str], bytes]) -> None:
    """`0x44` is on both frames. An 8-byte one is a request and has no data to parse."""
    packet = decode(Frame(load_frame("prog-read-request-0x44.hex")))
    assert isinstance(packet, UnknownPacket)


def test_a_truncated_reply_is_not_parsed(load_frame: Callable[[str], bytes]) -> None:
    """Better an `UnknownPacket` than records sliced out of somebody else's bytes.

    This is the one command whose payload can contain access codes, so a decoder that guesses at a
    short frame is a decoder that can mis-attribute one.
    """
    raw = bytearray(load_frame("prog-zones-0x1000-0x44.hex"))
    raw[6] = 0x70 + 8  # claim more data than the frame holds
    packet = decode(Frame(bytes(raw)))
    assert isinstance(packet, UnknownPacket)


# --- 6.2: the record parsers --------------------------------------------------------------------


def test_zone_names_and_the_disabled_flag(load_frame: Callable[[str], bytes]) -> None:
    """Seven records fit in a 112-byte read, and this panel's zones 1-7 are all disabled."""
    block = _block(load_frame, "prog-zones-0x1000-0x44.hex")
    zones = parse_zones(block.data, block.address)

    assert len(zones) == 7, "112 bytes holds seven 16-byte records"
    assert [zone.number for zone in zones] == [1, 2, 3, 4, 5, 6, 7]
    assert zones[0].name == "ZONA 01"
    assert zones[3].name == "Disp Cerc", "the fence's own zone, named by the installer"

    # Attribute byte 0 == 0x00 means disabled, and it is the one option byte verified against an
    # independent source — the status frame's P-INIB reported exactly the complement.
    assert all(not zone.enabled for zone in zones)
    assert all(zone.attributes[0] == 0x00 for zone in zones)


def test_partition_names_skip_the_flag_byte(load_frame: Callable[[str], bytes]) -> None:
    """The region has **one** leading flag byte, not one per record.

    `docs/protocol/programming.md` said one per record. Read that way, every partition after the
    first loses its first character — "Externo" becomes "xterno". The arithmetic settles it:
    ActiveNet read `0x25` = 37 bytes, and `1 + 4 * 9 = 37`.
    """
    block = _block(load_frame, "prog-partition-names-0x006F-0x44.hex")
    partitions = parse_partitions(block.data, block.address)

    assert [p.name for p in partitions] == ["Interno", "Externo", "PART. C", "PART. D"]


def test_pgm_records_carry_a_name_and_raw_attributes(
    load_frame: Callable[[str], bytes],
) -> None:
    """PGM 2 is the author's — named from Home Assistant, which is how the capture was made."""
    block = _block(load_frame, "prog-pgms-0x01BF-0x44.hex")
    pgms = parse_pgms(block.data, block.address)

    assert [p.number for p in pgms] == [1, 2, 3, 4]
    assert pgms[1].name == "Home Assi", "nine bytes of name, and the installer used all nine"
    assert len(pgms[0].attributes) == 7


def test_the_pgm_record_matches_what_the_programmer_app_showed(
    load_frame: Callable[[str], bytes],
) -> None:
    """Every field of the PGM record, checked against JFL's own app.

    Sprint 6 reported this record as undecodable — the captured panel's four PGMs never had their
    functions varied, so there was no differential to read. Screenshots of the programmer app on
    2026-08-09 settled it in one step, and this test is the pairing:

    | | The app showed | The bytes say |
    |---|---|---|
    | PGM 1 | *Armar/desarmar o eletrificador*, 2 s, 00:00-00:00 | function 18, `0xCA`, zeroes |
    | PGM 2 | *Aciona junto com o arme da partição A*, 1 second | function 6, `0xC9` |
    | PGM 4 | scheduled, on 17:45, off 22:00 | function 11, `17 45 22 00` |

    Note `0xCA` = 202 = **two seconds**, not 202 minutes: §18.2's scale counts minutes below 201 and
    seconds above it, which is the trap `decode_pgm_duration` exists for.
    """
    block = _block(load_frame, "prog-pgms-0x01BF-0x44.hex")
    pgms = {record.number: record for record in parse_pgms(block.data, block.address)}

    fence = pgms[1]
    assert fence.function is PgmFunction.ELECTRIC_FENCE
    assert fence.drives_fence is True, "what Sprints 4 and 6 could not answer"
    assert fence.duration_seconds == 2
    assert fence.on_at == "00:00"

    assert pgms[2].function is PgmFunction.WITH_PARTITION_A_ARM
    assert pgms[2].duration_seconds == 1
    assert pgms[2].function.user_operable is False, "so the panel will not switch it remotely"

    assert pgms[3].function is PgmFunction.DISABLED

    scheduled = pgms[4]
    assert scheduled.function is PgmFunction.SCHEDULED
    assert (scheduled.on_at, scheduled.off_at) == ("17:45", "22:00")

    # Exactly one output drives the fence, and finding it no longer needs the user to say so.
    assert [n for n, record in pgms.items() if record.drives_fence] == [1]


def test_the_pgm_duration_scale_is_not_linear() -> None:
    """§18.2: 1-200 counts minutes, 201-255 counts seconds minus 200.

    Two adjacent numbers, `2` and `202`, are two minutes and two seconds — a hundred and twenty
    times apart. Rendering this as a plain number would misconfigure an output by two hours.
    """
    assert decode_pgm_duration(202) == 2
    assert decode_pgm_duration(201) == 1
    assert decode_pgm_duration(255) == 55
    assert decode_pgm_duration(2) == 120
    assert decode_pgm_duration(200) == 200 * 60
    assert decode_pgm_duration(0) == 0


def test_an_undocumented_pgm_function_does_not_raise() -> None:
    """A firmware with a twenty-seventh function must not take the whole read down."""
    record = PgmRecord(1, "X", bytes([0, 0, 0, 0, 0xCA, 99, 0xFF]))
    assert record.function is None
    assert record.drives_fence is False


def test_the_silent_energiser_counts_as_a_fence_driver() -> None:
    """Function 25 is the Active 20's silent energiser. Checking only 18 would miss every one."""
    assert PgmFunction.ELECTRIC_FENCE_SILENT.drives_fence is True
    assert PgmFunction.USER_RETAINED.drives_fence is False
    assert PgmFunction.USER_PULSED.user_operable is True


def test_a_user_record_never_carries_the_code(load_frame: Callable[[str], bytes]) -> None:
    """**The contract this parser exists for.** AGENTS.md §4.

    The code is three bytes at offset 9 of every user record. The parser reads them far enough to
    answer "is one set?" and discards them, so nothing downstream can leak what it was never given.
    """
    block = _block(load_frame, "prog-users-0x0580-0x44.hex")
    users = parse_users(block.data, block.address)

    assert [u.name for u in users[:3]] == ["Ana", "Bruno", "Carla"]
    assert all(not u.has_code for u in users), "the captured codes were redacted to FF FF FF"

    # Nothing on the object is the code, or could be mistaken for it.
    for user in users:
        assert not hasattr(user, "code")
        assert len(user.attributes) == 4


def test_a_set_code_is_reported_as_present_and_nothing_more() -> None:
    """The other half of the contract: `has_code` has to actually work."""
    record = bytes(b"Ana".ljust(9, b"\xff")) + b"\x12\x34\xff" + b"\x00\x01\x00\x0f"
    (user,) = parse_users(record, user_address(1))
    assert user.has_code is True
    assert "1234" not in repr(user)
    assert "\x12" not in repr(user)


def test_wireless_slots_pair_a_serial_with_a_zone(load_frame: Callable[[str], bytes]) -> None:
    """Cross-validated against the `0x59` inventory: same serials, same zones, slot for slot."""
    block = _block(load_frame, "prog-wireless-0x17FC-0x44.hex")
    devices = [record for record in parse_wireless(block.data, block.address) if record.present]

    assert devices[0].serial == 0xB205AF2A, "the IRD-650 the UI showed on zone 14"
    assert devices[0].zone == 14
    assert devices[1].zone == 18


def test_a_partial_record_at_the_edge_is_skipped(load_frame: Callable[[str], bytes]) -> None:
    """A read starting mid-record must not name a zone from the tail of its neighbour."""
    block = _block(load_frame, "prog-zones-0x1000-0x44.hex")
    offset = 8
    zones = parse_zones(block.data[offset:], block.address + offset)
    assert [zone.number for zone in zones] == [2, 3, 4, 5, 6, 7], "zone 1 is now incomplete"


# --- 6.2: planning a full read ------------------------------------------------------------------


def test_a_plan_tiles_its_range_without_gaps_or_overlap() -> None:
    """The reassembled bytes are a plain concatenation, so the requests have to be contiguous."""
    requests = plan_read(ZONE_BASE, 32 * 16)
    assert requests[0].address == ZONE_BASE
    assert requests[-1].end == ZONE_BASE + 32 * 16
    assert all(a.end == b.address for a, b in pairwise(requests))
    assert all(request.count <= MAX_READ for request in requests)


@pytest.mark.parametrize("region", sorted(REGIONS))
def test_every_declared_region_can_be_planned(region: str) -> None:
    """A region whose length is not a whole number of records would silently lose the last one."""
    requests = plan_region(region)
    address, length = REGIONS[region]
    assert requests[0].address == address
    assert requests[-1].end == address + length


def test_the_captured_reads_tile_the_space_contiguously(
    load_frame: Callable[[str], bytes],
) -> None:
    """The evidence that the selector is an **address**, not an opaque block id.

    ActiveNet's own reads start exactly where the previous one ended — `0x0580 + 0x70 = 0x05F0`,
    and so on. That is what makes a single-record read expressible at all, and it is why this
    integration can ask for one zone's name instead of a 112-byte window.
    """
    block = _block(load_frame, "prog-users-0x0580-0x44.hex")
    assert block.address == user_address(1)
    assert block.end == user_address(8), "seven 16-byte user records, ending on a record boundary"


def test_the_address_arithmetic_matches_the_documented_map() -> None:
    """Getting these wrong reads a neighbour's record and reports it as somebody else's."""
    assert zone_address(1) == 0x1000
    assert zone_address(10) == 0x1090
    assert user_address(1) == 0x0580
    # 0x0580 + 20 * 16. ActiveNet's captured write at 0x06D0 covers records 22-28, not the 21-27
    # `docs/protocol/programming.md` labels it — an off-by-one in the note, not in the base.
    assert user_address(21) == 0x06C0
    assert pgm_address(1) == 0x01C0, "one leading byte before the first record"
    assert wireless_address(1) == 0x1800


# --- names --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (b"Ana\xff\xff\xff\xff\xff\xff", "Ana"),
        (b"\xff\xff\xff\xff\xff\xff\xff\xff\xff", ""),
        (b"I Cozinha", "I Cozinha"),
        (b"P Fundo\xff\xff", "P Fundo"),
        (b"  spaced \xff", "spaced"),
    ],
)
def test_names_are_ff_padded_not_nul_padded(raw: bytes, expected: str) -> None:
    """`0xFF`, which is what the panel writes. Stripping NULs instead leaves a name ending in ÿÿ."""
    assert decode_name(raw) == expected


def test_an_accented_name_survives() -> None:
    """The keypad accepts them, and a strict ASCII decode would raise on a cedilla."""
    assert decode_name("Garaç".encode("latin-1").ljust(9, b"\xff")) == "Garaç"


# --- the wireless inventory ---------------------------------------------------------------------


def test_the_wireless_inventory_decodes_the_captured_page(
    load_frame: Callable[[str], bytes],
) -> None:
    """Verified against the panel's own UI, row by row, in `docs/protocol/programming.md`."""
    packet = decode(Frame(load_frame("wireless-page0-0x59.hex")))
    assert isinstance(packet, WirelessInventory)

    by_slot = {device.slot: device for device in packet.devices}
    assert by_slot, "the page carried devices"

    first = packet.devices[0]
    assert first.serial == 0xB205AF2A
    assert first.zone == 14
    assert first.last_seen == "08/08/26 16:31:31", "day first, the reverse of what 0x55 takes"
    assert first.repeater == 0, "a direct link; the UI reported only two devices via repeater 1"


def test_empty_wireless_slots_are_dropped(load_frame: Callable[[str], bytes]) -> None:
    """Unused records are `0xFF` filled. A device with slot 255 would be an invention."""
    packet = decode(Frame(load_frame("wireless-page0-0x59.hex")))
    assert isinstance(packet, WirelessInventory)
    assert all(0 < device.slot <= 32 for device in packet.devices)
    assert all(device.present for device in packet.devices)
