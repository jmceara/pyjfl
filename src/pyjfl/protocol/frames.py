"""Framing and checksums for the JFL `0x7B` protocol.

Author: Jonis Maurin Ceará <jmceara AT gmail.com>
Based on the code developed by Carlos Jose Fernandes,
available at https://github.com/fernac03/JFL_ACTIVE

Source: `docs/protocol/frame-format.md`, itself taken from
`docs/referencia/comando/Protocolo Comandos Active 100_32_20bus_20_8_20Eth.pdf` §2.

A frame is::

    A        B        C        D        DATA...   K
    0x7B     length   seq      cmd      payload   checksum

`B` is the **total** length including `A`, `B`, `C`, `D`, `DATA` and `K`. `K` is the XOR of every
byte in the frame *including itself*, so a valid frame XORs to zero.

This module is the reader the old integration never had, and the two rules it implements are the
reason the old one drops frames:

1. **Never frame by the size of a read.** TCP coalesces and splits arbitrarily; the old integration
   dispatches on `len(recv())` and silently loses both frames whenever two arrive together.
2. **On a checksum failure, drop one byte — never `length` bytes.** `0x7B` is the ASCII `{` and
   occurs freely inside account numbers, IMEIs and Contact ID payloads. A reader that trusts the
   first `0x7B` it sees and skips `length` bytes on failure loses synchronisation permanently.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

HEADER: Final = 0x7B
"""Start-of-frame byte, the ASCII character `{`."""

LEGACY_HEADER: Final = 0xB3
"""Header of the pre-5.0 protocol generation (Active 32 Duo firmware 1.0-4.9). Not implemented."""

WIRELESS_HEADER: Final = 0x7A
"""Header of the third protocol generation, two-byte length.

Found in ActiveNet's own `protocolo/b`, covering the Active 8W and the QC / Vulcano / Acessus
lines. Not implemented. See `docs/protocol/discrepancies.md` — note this conflicts with the old
integration's claim that model byte `0xA8` is an Active 8W on the `0x7B` protocol.
"""

MIN_FRAME_LENGTH: Final = 5
"""Header, length, sequence, command, checksum — the shortest legal frame, e.g. the `0x4D` poll."""

MAX_FRAME_LENGTH: Final = 255
"""The length field is one byte. The command protocol uses at most 128; monitoring goes to 255."""

_MAX_BUFFER = MAX_FRAME_LENGTH * 4
"""Give up and resynchronise rather than buffer without bound when a stream is garbage."""


class JflProtocolError(Exception):
    """Base class for every protocol-level error raised by this package."""


class PanelNotConnectedError(JflProtocolError):
    """A command cannot be sent because the panel has no socket bound right now.

    Deliberately **not** a `HomeAssistantError`: this package is the future `pyjfl` library
    (ADR-0019) and must not depend on Home Assistant. Every caller that can surface the failure to a
    user catches it and re-raises `HomeAssistantError` with a translation key — see
    `coordinator._async_send` and `button.py`.
    """


class UnsupportedProtocolError(JflProtocolError):
    """The peer is speaking a JFL protocol generation this package does not implement.

    Raised instead of mis-parsing, so the integration can tell the user *which* protocol its panel
    speaks rather than reporting a stream of checksum errors.
    """

    def __init__(self, header: int, name: str) -> None:
        """Record the header byte that was seen and the generation it identifies."""
        self.header = header
        self.name = name
        super().__init__(f"panel speaks the {name} protocol (header 0x{header:02X}), not 0x7B")


def xor_all(data: bytes) -> int:
    """Return the XOR of every byte in *data*.

    A frame is valid when this is zero over the whole frame, checksum included.
    """
    result = 0
    for byte in data:
        result ^= byte
    return result


def checksum_for(frame_without_checksum: bytes) -> int:
    """Return the checksum byte to append to a frame under construction."""
    return xor_all(frame_without_checksum)


def is_valid(frame: bytes) -> bool:
    """Return whether *frame* is a complete, correctly checksummed frame."""
    return (
        len(frame) >= MIN_FRAME_LENGTH
        and frame[0] == HEADER
        and frame[1] == len(frame)
        and xor_all(frame) == 0
    )


@dataclass(frozen=True, slots=True)
class Frame:
    """One complete, checksum-validated frame.

    `raw` is the frame exactly as it arrived. Every other attribute is a view onto it, so a decoder
    can work in whichever terms the source document uses.
    """

    raw: bytes

    @property
    def start(self) -> int:
        """The header byte. Always `0x7B` for a frame this package produced."""
        return self.raw[0]

    @property
    def length(self) -> int:
        """The declared total length, which equals `len(raw)` for a validated frame."""
        return self.raw[1]

    @property
    def seq(self) -> int:
        """The sequence byte.

        The specification says `0x01`-`0xFF`, but ActiveNet's own `protocolo/e.N()` wraps to zero,
        so `0x00` does occur on the wire. Accept it on receive; never emit it. See
        `docs/protocol/discrepancies.md`.
        """
        return self.raw[2]

    @property
    def cmd(self) -> int:
        """The command byte. Dispatch on this, never on `len(raw)`."""
        return self.raw[3]

    @property
    def payload(self) -> bytes:
        """Everything between the command byte and the checksum."""
        return self.raw[4:-1]

    @property
    def checksum(self) -> int:
        """The trailing checksum byte."""
        return self.raw[-1]

    def byte(self, absolute_offset: int) -> int:
        """Return the byte at *absolute_offset*, counting from the header.

        The JFL PDFs number every field by its absolute offset in the frame, so decoders should
        index that way too: `frame.byte(30)` is `ELET`, and it reads the same as the document. Doing
        arithmetic against `payload` instead is how the old integration ended up reading partitions
        at 13 and `SELET` at 54.
        """
        return self.raw[absolute_offset]

    def slice(self, start: int, end: int) -> bytes:
        """Return `raw[start:end]` using absolute offsets, for the same reason as `byte`."""
        return self.raw[start:end]

    def __repr__(self) -> str:
        """Render as command and length, with the payload as hex — safe for a debug log."""
        return (
            f"Frame(cmd=0x{self.cmd:02X}, seq=0x{self.seq:02X}, "
            f"len={self.length}, payload={self.payload.hex(' ').upper()})"
        )


def build_frame(seq: int, cmd: int, payload: bytes = b"") -> bytes:
    """Build a complete frame with its checksum appended.

    `seq` is masked into `0x01`-`0xFF`: the specification forbids `0x00` and, although panels do
    emit it, this package never does.
    """
    if not 0 <= cmd <= 0xFF:
        raise ValueError(f"command byte out of range: {cmd}")
    total = MIN_FRAME_LENGTH + len(payload)
    if total > MAX_FRAME_LENGTH:
        raise ValueError(f"frame would be {total} bytes, maximum is {MAX_FRAME_LENGTH}")
    body = bytes([HEADER, total, seq & 0xFF or 0x01, cmd]) + payload
    return body + bytes([checksum_for(body)])


class FrameReader:
    """Reassemble frames from a TCP byte stream.

    Feed it whatever `recv()` returned — a partial frame, several frames, or a frame split across
    reads — and it returns the complete, validated frames it can make. Anything incomplete stays
    buffered for the next call.

    The reader is self-healing: a bad byte costs one byte of resynchronisation, not a frame.
    """

    def __init__(self) -> None:
        """Start with an empty buffer and zeroed diagnostics."""
        self._buffer = bytearray()
        self._checked_first_byte = False
        self.dropped_bytes = 0
        """Bytes discarded during resynchronisation. Non-zero means something is wrong upstream."""
        self.desyncs = 0
        """Times the buffer was abandoned wholesale. Should stay at zero against a real panel."""

    def feed(self, data: bytes) -> list[Frame]:
        """Add *data* to the buffer and return every complete frame it now contains.

        Raises `UnsupportedProtocolError` if the very first byte of the stream identifies a protocol
        generation this package does not implement. Only the first byte is tested, and only once per
        connection, because `0xB3` and `0x7A` occur naturally inside payloads and testing later
        would produce false alarms.

        This relies on a real connection opening with a frame, which it does: the panel dials out
        and immediately sends its `0x21` connection frame. Call `reset()` between connections so the
        test applies again to the next one.
        """
        if data and not self._checked_first_byte:
            self._checked_first_byte = True
            if data[0] == LEGACY_HEADER:
                raise UnsupportedProtocolError(LEGACY_HEADER, "legacy 0xB3")
            if data[0] == WIRELESS_HEADER:
                raise UnsupportedProtocolError(WIRELESS_HEADER, "0x7A two-byte-length")

        self._buffer += data
        frames: list[Frame] = []

        while True:
            frame = self._take_one()
            if frame is None:
                break
            frames.append(frame)

        if len(self._buffer) > _MAX_BUFFER:
            # Nothing in a very large buffer produced a frame, so it is not going to. Keeping it
            # would only grow memory and delay recovery.
            self.desyncs += 1
            self.dropped_bytes += len(self._buffer)
            self._buffer.clear()

        return frames

    def _take_one(self) -> Frame | None:
        """Extract the next frame, discarding leading rubbish. None if more data is needed."""
        while True:
            start = self._buffer.find(HEADER)
            if start == -1:
                # No header anywhere: the whole buffer is noise.
                self.dropped_bytes += len(self._buffer)
                self._buffer.clear()
                return None
            if start > 0:
                self.dropped_bytes += start
                del self._buffer[:start]

            if len(self._buffer) < 2:
                return None

            length = self._buffer[1]
            if length < MIN_FRAME_LENGTH:
                # Not a length byte. This 0x7B was payload data.
                self._drop_one()
                continue

            if len(self._buffer) < length:
                # The head candidate is incomplete. Normally that just means the rest of the frame
                # has not arrived yet, so we wait. But a `{` inside a payload followed by a large
                # byte fakes a long frame, and waiting for it would swallow every real frame behind
                # it until the buffer cap fires. So: if a complete, correctly checksummed frame is
                # already sitting further along, the candidate was a phantom — skip to the real one.
                real = self._scan_for_valid_frame()
                if real is None:
                    return None
                self.dropped_bytes += real
                del self._buffer[:real]
                continue

            candidate = bytes(self._buffer[:length])
            if xor_all(candidate) == 0:
                del self._buffer[:length]
                return Frame(candidate)

            # Checksum failed. Drop exactly one byte — never `length` — because this 0x7B was
            # almost certainly a `{` inside a payload and the real frame starts further along.
            self._drop_one()

    def _scan_for_valid_frame(self) -> int | None:
        """Return the offset of a complete, valid frame later in the buffer, if there is one.

        Used only to decide whether the candidate at the head of the buffer is a phantom. Searching
        from offset 1 means a genuine partial frame is never abandoned in favour of something inside
        its own unreceived payload.
        """
        offset = 1
        while (offset := self._buffer.find(HEADER, offset)) != -1:
            length = self._buffer[offset + 1] if offset + 1 < len(self._buffer) else 0
            if (
                MIN_FRAME_LENGTH <= length <= len(self._buffer) - offset
                and xor_all(bytes(self._buffer[offset : offset + length])) == 0
            ):
                return offset
            offset += 1
        return None

    def _drop_one(self) -> None:
        """Discard a single byte and count it."""
        self.dropped_bytes += 1
        del self._buffer[:1]

    @property
    def pending(self) -> int:
        """Bytes currently buffered, awaiting the rest of their frame."""
        return len(self._buffer)

    def reset(self) -> None:
        """Forget any buffered bytes. Call this when a connection is re-established."""
        self._buffer.clear()
        self._checked_first_byte = False
