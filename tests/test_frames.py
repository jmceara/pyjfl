"""Framing, checksums and stream resynchronisation.

Sprint 1 task 1.1. The acceptance criterion is the fuzz test at the bottom: every captured fixture,
split at arbitrary boundaries with garbage injected, must never raise and must always recover sync.

This is where the old integration's most persistent bug lives, so it gets the strongest tests.
"""

from __future__ import annotations

import random
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from pyjfl.protocol.frames import (
    HEADER,
    LEGACY_HEADER,
    MAX_FRAME_LENGTH,
    WIRELESS_HEADER,
    Frame,
    FrameReader,
    UnsupportedProtocolError,
    build_frame,
    checksum_for,
    is_valid,
    xor_all,
)

FIXTURES = sorted((Path(__file__).parent / "fixtures").glob("*.hex"))

FENCE_ARM = bytes.fromhex("7B061A4E634A")


# --- checksum ----------------------------------------------------------------------------------


def test_xor_all_of_a_valid_frame_is_zero() -> None:
    """docs/protocol/frame-format.md: the checksum is included in its own XOR."""
    assert xor_all(FENCE_ARM) == 0


def test_checksum_matches_the_documented_worked_example() -> None:
    """`7B ^ 06 ^ 1A ^ 4E ^ 63 = 4A`, from docs/protocol/fence.md."""
    assert checksum_for(FENCE_ARM[:-1]) == 0x4A


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.stem)
def test_every_fixture_is_valid(path: Path, load_frame: Callable[[str], bytes]) -> None:
    """Real frames captured from the panel must pass the validator."""
    assert is_valid(load_frame(path.name))


# --- Frame -------------------------------------------------------------------------------------


def test_frame_exposes_the_header_fields() -> None:
    frame = Frame(FENCE_ARM)
    assert frame.start == HEADER
    assert frame.length == 6
    assert frame.seq == 0x1A
    assert frame.cmd == 0x4E
    assert frame.payload == b"\x63"
    assert frame.checksum == 0x4A


def test_absolute_offsets_read_like_the_specification(
    load_frame: Callable[[str], bytes],
) -> None:
    """`frame.byte(n)` must be the PDF's offset n, so decoders cannot drift.

    ELET at 30 and P-PGM at 87 are checked against a status frame captured immediately after the
    fence was armed. The old integration reads partitions at 13 and SELET at 54 precisely because it
    does arithmetic against the payload instead.
    """
    frame = Frame(load_frame("status-after-fence-arm.hex"))
    assert frame.byte(30) == 0x02, "ELET: fence armed"
    assert frame.byte(14) == 0x01, "PART[0]: partition 1 disarmed and unaffected"
    assert frame.byte(87) == 0x0A, "P-PGM: PGMs 2 and 4 operable"
    assert frame.slice(4, 6) == b"\x88\x35", "KP"


def test_frame_repr_is_safe_for_a_log() -> None:
    """The repr is used in debug logging, so it must be compact and total."""
    text = repr(Frame(FENCE_ARM))
    assert "0x4E" in text
    assert "63" in text


# --- build_frame -------------------------------------------------------------------------------


def test_build_frame_reproduces_a_captured_command() -> None:
    """The arm-fence frame ActiveNet actually sent, byte for byte."""
    assert build_frame(0x1A, 0x4E, b"\x63") == FENCE_ARM


def test_build_frame_never_emits_sequence_zero() -> None:
    """The specification forbids 0x00; panels emit it, we do not.

    See docs/protocol/discrepancies.md — ActiveNet's own `protocolo/e.N()` wraps to zero.
    """
    assert Frame(build_frame(0x00, 0x4D)).seq == 0x01


def test_build_frame_rejects_an_oversized_payload() -> None:
    with pytest.raises(ValueError, match="maximum"):
        build_frame(0x01, 0x4D, b"\x00" * MAX_FRAME_LENGTH)


# --- FrameReader -------------------------------------------------------------------------------


def test_reader_returns_a_whole_frame() -> None:
    assert [f.raw for f in FrameReader().feed(FENCE_ARM)] == [FENCE_ARM]


def test_reader_splits_two_frames_arriving_in_one_read(
    load_frame: Callable[[str], bytes],
) -> None:
    """The bug that motivated this package.

    The old integration dispatches on `len(recv())`, so when two frames arrive coalesced it matches
    neither expected size and drops both.
    """
    status = load_frame("status-after-fence-arm.hex")
    frames = FrameReader().feed(FENCE_ARM + status)
    assert [f.raw for f in frames] == [FENCE_ARM, status]


@pytest.mark.parametrize("split", range(1, len(FENCE_ARM)))
def test_reader_reassembles_a_frame_split_at_any_point(split: int) -> None:
    """TCP may deliver a frame in any number of pieces."""
    reader = FrameReader()
    assert reader.feed(FENCE_ARM[:split]) == []
    assert [f.raw for f in reader.feed(FENCE_ARM[split:])] == [FENCE_ARM]


def test_reader_delivers_frames_one_byte_at_a_time(
    load_frame: Callable[[str], bytes],
) -> None:
    """The pathological case: every byte in its own segment."""
    status = load_frame("status-after-fence-arm.hex")
    reader = FrameReader()
    produced = [frame for byte in status for frame in reader.feed(bytes([byte]))]
    assert [f.raw for f in produced] == [status]


def test_a_stray_header_inside_a_payload_does_not_lose_the_next_frame() -> None:
    """`0x7B` is `{` and appears in ASCII payloads.

    A reader that trusts the first `0x7B` and skips `length` bytes on a checksum failure loses
    synchronisation permanently. Dropping one byte recovers.
    """
    noise = bytes([HEADER, 0x40, 0x00, 0x00])
    frames = FrameReader().feed(noise + FENCE_ARM)
    assert [f.raw for f in frames] == [FENCE_ARM]


def test_reader_recovers_after_a_corrupted_frame() -> None:
    """A frame with a broken checksum must cost one frame, not the rest of the connection."""
    corrupt = bytearray(FENCE_ARM)
    corrupt[-1] ^= 0xFF
    reader = FrameReader()
    frames = reader.feed(bytes(corrupt) + FENCE_ARM)
    assert [f.raw for f in frames] == [FENCE_ARM]
    assert reader.dropped_bytes > 0


def test_reader_does_not_buffer_without_bound() -> None:
    """Garbage must not accumulate.

    `7B FF` repeated is the worst realistic case: every byte looks like the start of a
    maximum-length frame. The reader must keep discarding rather than growing, whether it gets
    there by dropping single bytes or by the emergency buffer cap.
    """
    reader = FrameReader()
    for _ in range(20):
        reader.feed(bytes([HEADER, 0xFF]) * 64)
    assert reader.pending <= MAX_FRAME_LENGTH * 4
    assert reader.dropped_bytes > 0


def test_reader_keeps_an_incomplete_frame_buffered() -> None:
    reader = FrameReader()
    reader.feed(FENCE_ARM[:3])
    assert reader.pending == 3
    reader.reset()
    assert reader.pending == 0


# --- other protocol generations ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("header", "expected"),
    [(LEGACY_HEADER, "legacy"), (WIRELESS_HEADER, "0x7A")],
)
def test_an_unsupported_generation_raises_a_distinct_error(header: int, expected: str) -> None:
    """Report which protocol the panel speaks rather than emitting endless checksum errors.

    See docs/protocol/discrepancies.md: a real Active 8W is expected to speak `0x7A`.
    """
    with pytest.raises(UnsupportedProtocolError) as error:
        FrameReader().feed(bytes([header, 0x10, 0x01, 0x21]))
    assert expected in error.value.name
    assert error.value.header == header


def test_those_headers_inside_a_payload_are_not_mistaken_for_a_protocol_switch() -> None:
    """Only the first byte of a stream is tested — `0xB3` and `0x7A` occur in payloads."""
    reader = FrameReader()
    reader.feed(FENCE_ARM)
    assert reader.feed(bytes([LEGACY_HEADER, WIRELESS_HEADER]) + FENCE_ARM)


# --- the acceptance criterion --------------------------------------------------------------------


@pytest.mark.parametrize("seed", range(40))
def test_fuzz_arbitrary_splits_and_injected_garbage(
    seed: int, load_frame: Callable[[str], bytes]
) -> None:
    """Sprint 1 task 1.1 acceptance.

    Every captured fixture, concatenated in a random order with random garbage injected between
    frames, delivered in random-sized chunks. The reader must never raise, and every genuine frame
    must still come out — the garbage may add frames, but it must not remove any.

    The stream deliberately *starts* with a real frame, because a real connection does: the panel
    opens with its `0x21` connection frame. That first byte is the one the reader tests for a
    foreign protocol generation, so feeding it random noise would trip `UnsupportedProtocolError`
    on a coincidental `0xB3` or `0x7A` and prove nothing.
    """
    rng = random.Random(seed)
    genuine = [load_frame(path.name) for path in FIXTURES]
    rng.shuffle(genuine)

    stream = bytearray(genuine[0])
    for frame in genuine[1:]:
        stream += bytes(rng.randrange(256) for _ in range(rng.randrange(0, 6)))
        stream += frame

    reader = FrameReader()
    produced: list[bytes] = []
    position = 0
    while position < len(stream):
        chunk = bytes(stream[position : position + rng.randrange(1, 64)])
        position += len(chunk)
        produced += [frame.raw for frame in reader.feed(chunk)]

    for frame in genuine:
        assert frame in produced, f"lost a genuine frame: cmd 0x{frame[3]:02X}"
    assert all(is_valid(frame) for frame in produced), "produced an invalid frame"


def test_fuzz_pure_garbage_never_raises() -> None:
    """Random bytes must be survivable: a badly desynchronised peer must not crash us."""
    rng = random.Random(1234)
    reader = FrameReader()
    for _ in range(200):
        for frame in reader.feed(bytes(rng.randrange(256) for _ in range(rng.randrange(1, 300)))):
            assert is_valid(frame.raw)
