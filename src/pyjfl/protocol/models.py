"""Types for the JFL `0x7B` protocol: enums, capability table, value objects and packets.

Every raw byte the panel sends becomes one of these before anything else looks at it, so that no
part of the integration outside `protocol/` has to know a bit position. Sources are cited per
symbol; the cached facts live in `docs/protocol/`.

Nothing here performs I/O or imports Home Assistant. See `docs/protocol/status-frame.md` for the
frame these types describe.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, StrEnum, unique
from typing import Final

# ---------------------------------------------------------------------------------------------
# Command bytes
# ---------------------------------------------------------------------------------------------


@unique
class Cmd(IntEnum):
    """Command bytes. Source: `docs/protocol/commands.md`.

    Panel-initiated commands (`CONNECTION`, `EVENT`, `KEEP_ALIVE`) arrive unsolicited and must be
    acknowledged promptly — the panel times our replies out and retransmits.
    """

    CONNECTION = 0x21
    """Panel identifies itself, 102 bytes. Carries the serial that keys everything else."""

    EVENT = 0x24
    """Contact ID event, 24 bytes. Acknowledge even when decoding fails, or it repeats forever."""

    AUTH = 0x37
    """Password-authenticated family. Carries lockout risk: see `CommandAck.WRONG_PASSWORD`."""

    KEEP_ALIVE = 0x40
    LOGIN = 0x43
    READ_PROGRAMMING = 0x44
    WRITE_PROGRAMMING = 0x45
    PROGRAMMING_CHECKSUM = 0x4C
    """Returns KP, which changes when and only when the programming changes."""

    STATUS = 0x4D
    """Periodic status refresh. ActiveNet polls this about every 12.5 s."""

    ARM = 0x4E
    DISARM = 0x4F
    PGM_ON = 0x50
    PGM_OFF = 0x51
    BYPASS = 0x52
    ARM_STAY = 0x53
    ARM_AWAY = 0x54
    SET_DATETIME = 0x55
    STATUS_USER = 0x56
    """User-requested status refresh. Same reply as `STATUS`."""

    READ_KEYPADS = 0x47
    """Reads the enrolled keypad / bus-module inventory. Decoded partially — see
    `docs/protocol/keypads-and-modules.md`."""

    READ_EVENTS = 0x48
    """Downloads the event buffer, paged by event serial number. Each record is 14 bytes. Fully
    decoded on 2026-08-09 — see `docs/protocol/event-buffer.md`."""

    READ_WIRELESS = 0x59
    MONITOR_STATUS = 0x93
    ROUTING_ENVELOPE = 0xAF
    """**Not a panel command.** ActiveNet's internal web-UI-to-server envelope; a panel never sees
    it. Recognised only so a capture can be read. See `docs/protocol/programming.md`."""


FENCE_PARTITION: Final = 0x63
"""Partition 99. The panel models the electric fence as a pseudo-partition with this number."""


@unique
class ArmMode(StrEnum):
    """The three ways the panel can be armed. Source: the panel manual, §3.2-3.4.

    These are three genuinely different operations, not three names for one, and the keypad offers
    all three whenever a partition is disarmed:

    * `TOTAL` (`0x4E`) — the ordinary arm. **The panel refuses it while a zone is open**: *"não é
      possível armar normal com zonas abertas"*.
    * `STAY` (`0x53`) — perimeter only. The zones carrying the *zona stay* attribute are inhibited
      so someone can stay inside without setting the alarm off.
    * `AWAY` (`0x54`) — arm **with** open zones. The panel bypasses whatever is open and restores
      each zone to normal as it closes. This is why an arm is sometimes followed by event `1573`.

    JFL's "away" is therefore a *forced* arm, not Home Assistant's "armed away". The mapping to the
    Home Assistant features is in `alarm_control_panel.py`, and the reasoning is recorded in
    `docs/development/entity-map.md`.

    **The panel does not report which of `TOTAL` and `AWAY` was used.** `PART[i]` reads `0x02` for
    both, and both emit event `3407`. Only `STAY` is distinguishable, as `0x03`.
    """

    TOTAL = "total"
    STAY = "stay"
    AWAY = "away"


@unique
class AuthFunc(IntEnum):
    """Functions of the authenticated `0x37` family. Source: `docs/protocol/commands.md`.

    Prefer the unauthenticated path wherever it works: it needs no password and cannot lock the
    panel out. The 2026-08-08 capture proved every operation this integration needs is available
    there, so this family is a diagnostic fallback, not the main road.
    """

    ARM_DISARM = 0xC1
    BYPASS = 0xC3
    PGM = 0xC7
    """The PDF's §5 heading says `0xC7` but its example frame says `0xC3`. The heading is
    self-consistent with the rest of the function list, so `0xC7` is used. Unresolved — see
    `docs/protocol/discrepancies.md`."""

    ARM_STAY = 0xCB


@unique
class CommandAck(IntEnum):
    """Replies to the authenticated `0x37` family — the only commands that acknowledge at all.

    Source: `docs/protocol/commands.md`. Path-A commands answer with a full status frame instead.
    """

    ACK = 0xBE
    INVALID_PACKET = 0xA0
    """Checksum error. Ours to fix, not the user's."""

    WRONG_PASSWORD = 0xA1
    """**Stop immediately.** Five of these lock remote access at the panel until someone performs a
    valid keypad operation. There must be no retry loop anywhere near this family — AGENTS.md §6."""

    INVALID_COMMAND = 0xA2
    NO_PERMISSION = 0xA8
    """Check address 300 TECLA3-6, and the user's attributes at 301-398."""

    NOT_PROGRAMMED = 0xA9
    BLOCKED = 0xAA
    """Already locked out by five wrong passwords."""

    FUNCTION_ABSENT = 0xAB
    """This model has no such function, e.g. an Active 8 Ultra has no electric fence."""


@unique
class LoginResult(IntEnum):
    """Result byte of the `0x43` login reply."""

    REJECTED = 0x00
    ACCEPTED = 0x01


# ---------------------------------------------------------------------------------------------
# Panel models
# ---------------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ModelSpec:
    """What a panel model can have. Source: `docs/protocol/models.md` and AGENTS.md §0.

    These are **ceilings, not truth**. What actually exists comes from the panel: partitions from
    their state bytes being non-zero, zones from the zone nibble, the fence from `ELET != 0x00`.
    The table only caps the ranges, because reading beyond a model's real size is how you end up
    creating thirty-two entities for a twelve-zone panel.
    """

    name: str
    partitions: int
    zones: int
    pgms: int
    has_fence: bool
    verified_on_hardware: bool = False
    """True only for models someone has actually tested. Never claim otherwise — AGENTS.md §0."""

    @property
    def is_module(self) -> bool:
        """True for the M-300 radio modules, which have PGMs and inputs but no partitions."""
        return self.partitions == 0


MODELS: Final[dict[int, ModelSpec]] = {
    0xA0: ModelSpec("Active 32 Duo", 4, 32, 4, has_fence=True, verified_on_hardware=True),
    0xA1: ModelSpec("Active 20 Ultra / 20 GPRS", 2, 22, 4, has_fence=True),
    0xA2: ModelSpec("Active 8 Ultra", 2, 12, 0, has_fence=False),
    0xA3: ModelSpec("Active 20 Ethernet", 2, 22, 4, has_fence=True),
    0xA4: ModelSpec("Active 100 Bus", 16, 99, 16, has_fence=True),
    0xA5: ModelSpec("Active 20 Bus", 2, 32, 16, has_fence=True),
    0xA6: ModelSpec("Active Full 32", 4, 32, 16, has_fence=False),
    0xA7: ModelSpec("Active 20", 2, 32, 4, has_fence=True),
    0xA8: ModelSpec("Active 8W", 2, 32, 4, has_fence=True),
    0x4B: ModelSpec("M-300+", 0, 0, 4, has_fence=False),
    0x5D: ModelSpec("M-300 Flex", 0, 0, 2, has_fence=False),
}
"""The eleven models the old integration supported, all of which this one must support too.

Only `0xA0` has been validated against real hardware. `0xA8` is doubly uncertain: ActiveNet places
the Active 8W on the `0x7A` protocol generation, which this package does not implement. See
`docs/protocol/discrepancies.md`.
"""

UNKNOWN_MODEL: Final = ModelSpec("Unknown JFL panel", 16, 99, 16, has_fence=True)
"""Permissive fallback for an unlisted model byte.

**An unknown model must never raise.** The old integration leaves its `MODELO` variable unbound for
an unlisted byte, which raises `UnboundLocalError` and kills the listener thread — a panel the
author never saw takes the whole integration down. Degrading to "assume everything exists" means
entities still appear and the user can report the byte.
"""


def spec_for(model_byte: int) -> ModelSpec:
    """Return the capabilities of *model_byte*, falling back permissively. Never raises."""
    return MODELS.get(model_byte, UNKNOWN_MODEL)


# ---------------------------------------------------------------------------------------------
# Value objects
# ---------------------------------------------------------------------------------------------

_ALARM_BIT: Final = 0x80
"""Bit 7 flags "in alarm" in both `PART[i]` and `ELET`. Mask it off to read the arm state."""


@dataclass(frozen=True, slots=True)
class PartitionState:
    """One partition's state byte, `PART[i]` at offsets 14-29.

    Source: `docs/protocol/status-frame.md`::

        0x00 not programmed      0x01 disarmed      0x02 armed AWAY      0x03 armed STAY
        bit 7 set = in alarm

    The old integration reads these at offset 13, so its partition 1 is actually the PGM byte.
    """

    raw: int

    @property
    def programmed(self) -> bool:
        """False when the partition does not exist on this installation. Create no entity for it."""
        return self.raw != 0x00

    @property
    def mode(self) -> int:
        """The arm state with the alarm flag masked off: 0, 1 disarmed, 2 away, 3 stay."""
        return self.raw & ~_ALARM_BIT

    @property
    def armed(self) -> bool:
        """True when armed in either mode."""
        return self.mode in (0x02, 0x03)

    @property
    def armed_stay(self) -> bool:
        """True when armed in stay (perimeter) mode."""
        return self.mode == 0x03

    @property
    def armed_away(self) -> bool:
        """True when fully armed."""
        return self.mode == 0x02

    @property
    def disarmed(self) -> bool:
        """True when programmed and disarmed."""
        return self.mode == 0x01

    @property
    def triggered(self) -> bool:
        """True when this partition is in alarm, armed or not."""
        return bool(self.raw & _ALARM_BIT)


@dataclass(frozen=True, slots=True)
class PartitionPermissions:
    """`P-PART[i]` at offsets 88-103. Source: `docs/protocol/status-frame.md`.

    **This is state-dependent, not a capability.** The 2026-08-08 capture read `0x0B` for partition
    1 while disarmed and `0x1F` while armed. Deriving an entity's `supported_features` from it would
    make Home Assistant's buttons appear and disappear on their own; derive those from `ModelSpec`
    and use this only to validate a call at the moment it is made.
    """

    raw: int

    @property
    def may_disarm(self) -> bool:
        """Bit 0: the monitoring connection may disarm."""
        return bool(self.raw & 0x01)

    @property
    def may_arm(self) -> bool:
        """Bit 1: the monitoring connection may arm."""
        return bool(self.raw & 0x02)

    @property
    def may_arm_stay(self) -> bool:
        """Bit 2: stay arming is permitted."""
        return bool(self.raw & 0x04)

    @property
    def may_arm_away(self) -> bool:
        """Bit 3: away arming is permitted."""
        return bool(self.raw & 0x08)

    @property
    def ready(self) -> bool:
        """True when the partition has no open zones and can be armed."""
        return bool(self.raw & 0x10)


@dataclass(frozen=True, slots=True)
class FenceState:
    """The electric fence, `ELET` at offset 30. Source: `docs/protocol/fence.md`.

    ::

        0x00 not programmed          0x01 disarmed          0x02 armed
        0x81 disarmed, in alarm      0x82 armed, in alarm
        0x04 disarmed, not ready     0x84 disarmed, ready, in alarm   (0x93 reply only)

    `0x00` means **the fence is not configured on this panel**, which is not the same as disarmed.
    The old integration collapses the byte to a boolean and treats `0x00` as "no fence", which is
    why its fence sensor is meaningless — and it reads `SELET` from offset 54 of the connection
    frame, inside the account field, where it always finds `0x00`.
    """

    raw: int

    @property
    def present(self) -> bool:
        """False when no fence is configured. Create no entity at all in that case."""
        return self.raw != 0x00

    @property
    def armed(self) -> bool:
        """True when the energiser is armed."""
        return self.mode == 0x02

    @property
    def disarmed(self) -> bool:
        """True when the fence exists and is disarmed, ready or not."""
        return self.mode in (0x01, 0x04)

    @property
    def triggered(self) -> bool:
        """True when the fence is in alarm. A cut wire stays triggered and never restores."""
        return bool(self.raw & _ALARM_BIT)

    @property
    def ready(self) -> bool:
        """False for `0x04`, "disarmed and not ready", seen only in the `0x93` reply."""
        return self.mode != 0x04

    @property
    def mode(self) -> int:
        """The state with the alarm flag masked off."""
        return self.raw & ~_ALARM_BIT


@dataclass(frozen=True, slots=True)
class FencePermissions:
    """`P-ELET` at offset 86. Source: `docs/protocol/fence.md`.

    Note the arm bit is **bit 3, not bit 1** — it mirrors the `ARM_AWAY` position in `P-PART`.
    When a bit is clear the command returns `0xA8`; tell the user which address to check rather
    than failing silently: address 300 TECLA3/TECLA4, and "Opera eletrificador" at 301-398.
    """

    raw: int

    @property
    def may_disarm(self) -> bool:
        """Bit 0: the monitoring connection may disarm the energiser."""
        return bool(self.raw & 0x01)

    @property
    def may_arm(self) -> bool:
        """Bit 3, not bit 1: it mirrors the ARM_AWAY position in `P-PART`."""
        return bool(self.raw & 0x08)


@unique
class ZoneStatus(IntEnum):
    """A zone nibble from `ZONA`, offsets 31-80. Source: `docs/protocol/status-frame.md`.

    Two zones share a byte, **high nibble first**. Note `SHORT_CIRCUIT` and `TAMPER` are 4 and 5
    here; the legacy `0xB3` protocol numbers them the other way round.
    """

    DISABLED = 0x0
    BYPASSED = 0x1
    """A **manual** bypass. An auto-bypassed zone keeps reporting its physical state, so this
    nibble alone cannot tell you a zone was auto-anulled — track events 1570 and 1573 for that."""

    TRIGGERED = 0x2
    NOT_COMMUNICATING = 0x3
    SHORT_CIRCUIT = 0x4
    TAMPER = 0x5
    LOW_BATTERY = 0x6
    OPEN = 0x7
    CLOSED = 0x8

    @property
    def exists(self) -> bool:
        """False when the zone is not in use on this installation."""
        return self is not ZoneStatus.DISABLED

    @property
    def is_open(self) -> bool:
        """True when the sensor is physically open, including while triggered."""
        return self in (ZoneStatus.OPEN, ZoneStatus.TRIGGERED)

    @property
    def is_fault(self) -> bool:
        """True for states that need the user's attention rather than describing an opening."""
        return self in (
            ZoneStatus.NOT_COMMUNICATING,
            ZoneStatus.SHORT_CIRCUIT,
            ZoneStatus.TAMPER,
            ZoneStatus.LOW_BATTERY,
        )


@dataclass(frozen=True, slots=True)
class ZoneState:
    """One zone: its number, its nibble, and whether it may be bypassed."""

    number: int
    status: ZoneStatus
    may_bypass: bool = False
    """From `P-INIB`, which is **LSB-first** contrary to the specification. See
    `docs/protocol/discrepancies.md`: read the documented way, it offers bypass on wrong zones."""


@unique
class ProblemFlag(IntEnum):
    """A trouble bit from `PROB[5]`, offsets 81-85. Source: `docs/protocol/status-frame.md`.

    The value is the flat bit index: `byte_index * 8 + bit`, bit 0 first.
    """

    # PROB byte 1
    WIRELESS_LOW_BATTERY = 0
    SENSOR_SUPERVISION = 1
    AUXILIARY_OUTPUT = 2
    TAMPER = 3
    DHCP = 4
    NETWORK_CABLE = 5
    CELLULAR_MODULE = 6
    SMS = 7
    # PROB byte 2
    ETHERNET = 8
    GPRS = 9
    TELEPHONE_LINE = 10
    SHORT = 11
    KEYPAD = 12
    SIREN = 13
    BATTERY = 14
    AC_MAINS = 15
    # PROB byte 3
    BATTERY_REVERSED = 16
    DESTINATION_IP_2 = 17
    DESTINATION_IP_1 = 18
    DNS_SERVER = 19
    KEYPAD_AC = 20
    SIREN_SUPERVISION = 21
    WIRELESS_PASSWORD = 22
    WIRELESS_AUTHENTICATION = 23
    # PROB byte 4
    SSID_NOT_FOUND = 24
    IP_CONFLICT = 25
    BUS = 26
    DDNS = 27
    NOTIFICATION = 28
    ETHERNET_MODULE = 29
    SIGNAL_LEVEL = 30
    SIM_CARD = 31


@dataclass(frozen=True, slots=True)
class Problems:
    """The five `PROB` bytes as a set of flags."""

    active: frozenset[ProblemFlag] = frozenset()

    @property
    def any(self) -> bool:
        """True when the panel is reporting at least one trouble."""
        return bool(self.active)

    def __contains__(self, flag: ProblemFlag) -> bool:
        """Allow `ProblemFlag.AC_MAINS in status.problems`."""
        return flag in self.active


# ---------------------------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------------------------


@unique
class EventKind(StrEnum):
    """Classification of a Contact ID code, for routing an event to the right entity.

    A string enum so the value can go straight into a Home Assistant event payload without a
    conversion table on the far side.
    """

    ALARM = "alarm"
    ALARM_RESTORE = "alarm_restore"
    ARM = "arm"
    DISARM = "disarm"
    FENCE_ALARM = "fence_alarm"
    """The fence has no codes of its own — these four exist because it reports the *ordinary* arm,
    disarm and alarm codes with partition 99. Without them "armed" on a panel-wide event entity is
    ambiguous: the electric fence being switched on and the house being armed look identical, which
    is exactly the confusion this split removes. See `classify()`."""

    FENCE_ALARM_RESTORE = "fence_alarm_restore"
    FENCE_ARM = "fence_arm"
    FENCE_DISARM = "fence_disarm"
    BYPASS = "bypass"
    BYPASS_RESTORE = "bypass_restore"
    TROUBLE = "trouble"
    TROUBLE_RESTORE = "trouble_restore"
    PANIC = "panic"
    MEDICAL = "medical"
    FIRE = "fire"
    TAMPER = "tamper"
    TEST = "test"
    SYSTEM = "system"
    UNKNOWN = "unknown"


@unique
class ZoneAlert(StrEnum):
    """A lasting condition of one zone that the **status frame cannot express**.

    A zone's state is a single nibble, so it can say `OPEN` or it can say `LOW_BATTERY`, never both.
    A wireless sensor whose battery is dying reports `6` while it is closed and `7` the moment
    somebody walks past it — and the low battery has not gone away, it has been overwritten by a
    more urgent fact.

    Contact ID does not have that problem: `1384` and `3384` are a matched pair that bracket the
    condition, independently of whatever the zone is physically doing. So these three conditions are
    tracked from the **events**, latched until their restore code arrives, and merged with the
    nibble rather than replaced by it. See `contact_id.ZONE_ALERTS`.
    """

    LOW_BATTERY = "low_battery"
    """`1384` / `3384` — a wireless sensor's battery. Also nibble `6`."""

    SUPERVISION = "supervision"
    """`1381` / `3381` — the panel has stopped hearing from the sensor. Also nibble `3`."""

    TAMPER = "tamper"
    """`1383` / `3383` — somebody is interfering with the sensor. Also nibble `5`."""


@unique
class EventSubject(StrEnum):
    """What the three-character field after the partition refers to.

    The same field carries a zone number for an alarm and a user number for an arm, and the only
    way to know which is the code. The 2026-08-08 capture also showed it encodes *origin* for
    remote operations: `099` is the monitoring connection, `000` the mobile app.
    """

    ZONE = "zone"
    USER = "user"
    NONE = "none"


# ---------------------------------------------------------------------------------------------
# Decoded packets
# ---------------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ConnectionInfo:
    """The `0x21` connection frame, 102 bytes. Source: `docs/protocol/commands.md`.

    The serial at `raw[4:14]` is the panel's identity: ActiveNet keys its panel list by it and
    rebinds only that panel's socket on a reconnect, which is what makes one listener serving many
    panels correct rather than merely convenient.
    """

    serial: str
    model_byte: int
    firmware: str
    mac: str = ""
    imei: str = ""
    partition_count: int = 0
    signal: int = 0
    """`STATUS[52]` byte 1, absolute offset 49. Meaningful only on a panel with a cellular module;
    an Ethernet-only panel reports `0x00`. See `docs/protocol/commands.md`."""

    hardware_version: str = ""
    """The board revision, e.g. *1.0*. **Not in this frame** — the `0x21` connection frame does not
    carry it; the `0x43` login reply does (see `LoginInfo.hardware_version`). Kept here as `""` so a
    single device-info builder can read one field regardless of which frame supplied it."""

    fence: FenceState = field(default_factory=lambda: FenceState(0x00))
    partitions: tuple[PartitionState, ...] = ()

    @property
    def spec(self) -> ModelSpec:
        """The capability ceiling for this panel's model. Never raises for an unknown byte."""
        return spec_for(self.model_byte)


@dataclass(frozen=True, slots=True)
class KeepAlive:
    """The `0x40` keep-alive. Answer with the interval in minutes, 1-20."""

    seq: int


@dataclass(frozen=True, slots=True)
class PanelEvent:
    """A `0x24` Contact ID event, 24 bytes.

    Events are the only signal for things that change no status byte at all — panic, notably, which
    is why the integration exposes `event` entities rather than polling for them.

    `counter` must be echoed verbatim in the acknowledgement, and the event must be acknowledged
    **even when decoding fails**, or the panel retransmits it indefinitely.
    """

    account: str
    code: str
    partition: str
    subject: str
    """Zone number, user number or origin, depending on `code`. See `EventSubject`."""

    counter: bytes
    """Kept as raw bytes, not text: it is **binary**, not ASCII like the fields around it, and the
    acknowledgement must echo it verbatim. Converting it to a string and back is a way to get that
    wrong, and the panel would retransmit forever."""

    fence: FenceState = field(default_factory=lambda: FenceState(0x00))
    """`SPART` at offset 21 carries the fence state, giving a second independent signal."""

    problem: int = 0
    seq: int = 0

    @property
    def is_fence(self) -> bool:
        """True when this event concerns the electric fence, which reports as partition 99."""
        return self.partition == "99"


@dataclass(frozen=True, slots=True)
class PanelStatus:
    """The status frame, the reply to `0x4D`/`0x56` and to every path-A command.

    Source: `docs/protocol/status-frame.md`. Firmware 7.60 sends 127 bytes rather than the
    documented 123; the extra bytes are at the tail and every documented offset still holds.

    **This is not the final truth after a command.** Arming returned a frame still showing zone 9
    open; the panel auto-bypassed it a second later and announced that only via an event. Re-read
    the status roughly 600 ms and 2 s after any command.
    """

    programming_checksum: bytes
    battery_volts: float
    pgm: int
    """PGMs 1-8, **LSB is PGM 1** — the opposite order to `P-INIB`."""

    pgm_high: int = 0
    """PGMs 9-16, at offset 117. The old integration reads 116, the last `P-INIB` byte."""

    partitions: tuple[PartitionState, ...] = ()
    partition_permissions: tuple[PartitionPermissions, ...] = ()
    fence: FenceState = field(default_factory=lambda: FenceState(0x00))
    fence_permissions: FencePermissions = field(default_factory=lambda: FencePermissions(0x00))
    zones: tuple[ZoneState, ...] = ()
    problems: Problems = field(default_factory=Problems)
    pgm_permissions: int = 0
    """`P-PGM` at offset 87: PGMs 1-8, **LSB is PGM 1**."""

    pgm_permissions_high: int = 0
    """`P-PGM2` at offset 118: PGMs 9-16."""

    siren: int = 0
    """`PA_SIR` at offset 120. Documented as reserved; it is not — it tracks the siren."""

    updating: bool = False
    """`ATUALIZ`: the panel is busy updating and its other bytes may be stale."""

    clock: str = ""
    seq: int = 0

    def pgm_on(self, number: int) -> bool:
        """Return whether PGM *number* (1-16) is on."""
        return self._pgm_bit(number, self.pgm, self.pgm_high)

    def pgm_permitted(self, number: int) -> bool:
        """Return whether the panel lets a monitoring connection operate PGM *number*.

        `P-PGM`/`P-PGM2` use the same bit order as the state bytes. A clear bit means the command
        comes back as `0xA9` — the PGM is either not programmed or not carrying a user-operable
        function (12 or 13 at addresses 821-824).
        """
        return self._pgm_bit(number, self.pgm_permissions, self.pgm_permissions_high)

    @staticmethod
    def _pgm_bit(number: int, low: int, high: int) -> bool:
        """Read PGM *number*'s bit out of a low/high byte pair — **LSB is PGM 1**."""
        if 1 <= number <= 8:
            return bool(low & (1 << (number - 1)))
        if 9 <= number <= 16:
            return bool(high & (1 << (number - 9)))
        raise ValueError(f"PGM out of range: {number}")

    @property
    def bypassed_zones(self) -> frozenset[int]:
        """The zones the panel currently reports as **manually** bypassed.

        This is what makes `0x52` safe to use: the command replaces the whole bitmap, so changing
        one zone means sending every zone that should stay inhibited — and this is the panel's own
        present-tense answer to which those are, rather than a set remembered from an earlier call.

        Auto-bypassed zones are deliberately absent. Nibble `1` appears only for a manual bypass
        (the panel keeps reporting an auto-anulled zone's physical state), and an auto-bypass is not
        in the manual bitmap either, so it cannot be clobbered by writing one.
        """
        return frozenset(zone.number for zone in self.zones if zone.status is ZoneStatus.BYPASSED)


@dataclass(frozen=True, slots=True)
class MonitorStatus:
    """The 57-byte reply to `0x93`, the monitoring-station view."""

    accounts: tuple[str, ...] = ()
    fence: FenceState = field(default_factory=lambda: FenceState(0x00))
    partitions: tuple[PartitionState, ...] = ()
    signal: int = 0
    seq: int = 0


@dataclass(frozen=True, slots=True)
class LoginInfo:
    """The `0x43` login reply.

    ActiveNet logs in with `SENHA = FF FF FF` as `TP = 0x04` (Programador) and the panel answers
    `RESULT = 0x01`. **No panel password is involved anywhere in the operating command set** — which
    is what removed the lockout hazard from this project's design.
    """

    result: LoginResult
    model_byte: int = 0
    firmware: str = ""
    serial: str = ""
    hardware_version: str = ""
    """The board revision, decoded from the reply's tail. **This is where it lives** — the `0x21`
    connection frame does not carry it. On the captured panel the tail reads `54 03 31 30`, whose
    ASCII digits `"10"` the app shows as *1.0*. See `docs/protocol/observed-frames.md`."""

    seq: int = 0

    @property
    def accepted(self) -> bool:
        """True when the panel accepted the login."""
        return self.result is LoginResult.ACCEPTED


@dataclass(frozen=True, slots=True)
class CommandResponse:
    """The acknowledgement to an authenticated `0x37` command."""

    ack: CommandAck
    seq: int = 0

    @property
    def ok(self) -> bool:
        """True only for an explicit ACK; every other value is a refusal."""
        return self.ack is CommandAck.ACK

    @property
    def locks_panel_out(self) -> bool:
        """True when this reply means remote access is, or is about to be, blocked.

        On the first `WRONG_PASSWORD` the caller must stop, set a blocked flag and refuse further
        authenticated commands until the user re-enters the password. Five of them block remote
        operation at the panel until someone uses the keypad. AGENTS.md §6.
        """
        return self.ack in (CommandAck.WRONG_PASSWORD, CommandAck.BLOCKED)


WIRELESS_PER_PAGE: Final = 0x08
"""Records per page in the `0x59` wireless inventory, and the byte the request carries."""

EVENTS_PER_PAGE: Final = 0x08
"""Records per page in the `0x48` event buffer. The request carries it and the reply echoes it;
every page in the 2026-08-09 download was eight. See `docs/protocol/event-buffer.md`."""


@dataclass(frozen=True, slots=True)
class ProgrammingBlock:
    """A `0x44` reply: a slice of the panel's programming address space.

    ::

        7B LL SEQ 44 | AH AL N | KP1 KP2 | <N data bytes> | K

    The reply **echoes the selector verbatim**, so it can be matched to its request without relying
    on the sequence byte — which matters when reading the full map, because that is thirty-odd
    requests in flight against a link that is also carrying the status poll.

    ⚠️ `data` is raw programming, and depending on the address it may contain **user access codes**,
    account numbers or telephone numbers. Parse it with `protocol.programming`, whose user parser
    never returns a code, and never log it.
    """

    address: int
    count: int
    checksum: bytes
    """`KP`, the same programming checksum the status frame carries at offsets 4-5. It changes when,
    and only when, the programming changes — so it tells a cached copy it has gone stale."""

    data: bytes
    seq: int = 0

    @property
    def end(self) -> int:
        """The first address *after* this block."""
        return self.address + self.count

    def covers(self, address: int, length: int = 1) -> bool:
        """Whether this block contains the whole of *length* bytes starting at *address*."""
        return self.address <= address and address + length <= self.end


@unique
class SignalQuality(IntEnum):
    """The wireless link quality, as the low nibble of `0x59` record offset 15.

    **The scale was confirmed on 2026-08-09**, when a full inventory was captured against the
    panel's own UI and all nine devices matched: `4` = *Excelente*, `3` = *Muito bom*, `2` = *Bom*.
    Values `0` and `1` were never observed on this installation; they are the extrapolated bottom of
    the same ordinal scale (no signal / weak) and are marked as such. See
    `docs/protocol/programming.md`.
    """

    NONE = 0
    """Not observed — the extrapolated bottom of the scale (no signal)."""

    WEAK = 1
    """Not observed — extrapolated. The app's *Ruim*, one below *Bom*."""

    GOOD = 2
    """*Bom* — confirmed against the UI."""

    VERY_GOOD = 3
    """*Muito bom* — confirmed against the UI."""

    EXCELLENT = 4
    """*Excelente* — confirmed against the UI."""


WIRELESS_MODELS: Final[dict[int, str]] = {
    0xB0: "IRPET-520 DUO",
    0xB1: "SL-220 DUO",
    0xB2: "IRD-650 DUO",
    0xB4: "SL-320 DUO",
    0xB5: "DSE-830i DUO+",
    0xBA: "SL-320 DUO+",
}
"""Wireless detector model keyed by the **high byte of its serial number**.

**Confirmed against the panel's UI on 2026-08-09**, all nine enrolled sensors matched: the family is
in the serial's top byte, not in any record field. Six families are known; the "+" variant carries a
different byte from its base (`0xB4` SL-320 DUO vs `0xBA` SL-320 DUO+), so this is a lookup, not an
arithmetic rule. An unknown byte resolves to `None` rather than a guess. See
`docs/protocol/programming.md`."""


@dataclass(frozen=True, slots=True)
class WirelessDevice:
    """One record of the `0x59` wireless inventory. Source: `docs/protocol/programming.md`.

    ::

        01 B2 05 AF 2A 0E 40 00 09 08 26 17 19 30 00 04
        │  └── serial ─┘ │  │  │  └──── last transmission ──┘  │  └── repeater(hi) + signal(lo)
        └── slot        zone │ state                        low battery
                             firmware (4.0)

    **The whole record was decoded on 2026-08-09**, against a full inventory captured while the
    panel's UI displayed each field. All nine devices matched: the serial's high byte gives the
    model (`WIRELESS_MODELS`), offset 6 the firmware, offset 14 the low-battery flag, and the low
    nibble of offset 15 the confirmed signal scale (`SignalQuality`). See
    `docs/protocol/programming.md`.
    """

    slot: int
    serial: int
    zone: int
    open: bool
    """Offset 7. Exactly one of the nine captured records read `0x01`, and it was the one zone the
    status frame and the panel's UI both showed as open."""

    last_seen: str
    """`DD/MM/YY HH:MM:SS` from six BCD bytes, or empty if the field is malformed."""

    repeater: int
    """High nibble of offset 15. Two records read `1`, and the UI reported exactly two devices
    arriving "via repetidor 1". `0` means a direct link."""

    link: int
    """Low nibble of offset 15 — the raw signal nibble. Prefer `signal`, which names the confirmed
    ordinal scale; this stays exposed so a value outside the known range is still visible."""

    raw: bytes = b""

    firmware: str = ""
    """Offset 6 as `major.minor` nibbles — `0x40` reads *4.0*. **All nine devices read `0x40`**, so
    the *format* (a nibble pair) is inferred from the single value the app labels "4.0"; a device on
    a different firmware would confirm or refute it."""

    low_battery: bool = False
    """Offset 14. `0x00` on every captured device, matching the UI's "Bateria fraca: Não" for all of
    them. A non-zero value is read as a low battery; the exact encoding of *how* low is untested."""

    @property
    def present(self) -> bool:
        """False for an empty slot, which the panel fills with `0xFF`."""
        return self.serial not in (0x00000000, 0xFFFFFFFF)

    @property
    def signal(self) -> SignalQuality:
        """The link quality on the confirmed ordinal scale — see `SignalQuality`.

        An out-of-range nibble clamps to `NONE` rather than raising, so a future firmware reporting
        a fifth level cannot take a whole inventory down.
        """
        try:
            return SignalQuality(self.link)
        except ValueError:
            return SignalQuality.NONE

    @property
    def model(self) -> str | None:
        """The detector model from the serial's high byte, or `None` if the byte is unknown.

        `None`, never a guess: shipping a wrong model name onto a zone's device page is worse than
        shipping none, because it reads as certain.
        """
        return WIRELESS_MODELS.get((self.serial >> 24) & 0xFF)


@dataclass(frozen=True, slots=True)
class WirelessInventory:
    """One page of the `0x59` reply."""

    devices: tuple[WirelessDevice, ...] = ()
    seq: int = 0


INSTALLER_USER: Final = 99
"""User `99` is the installer (INSTALADOR). Users `0` and `1` are the master and the second user."""

EVENT_RECORD_SIZE: Final = 14
"""One `0x48` event record: serial(4) + Contact ID(2) + subject(1) + partition(1) + BCD time(6)."""


@dataclass(frozen=True, slots=True)
class EventRecord:
    """One 14-byte record of the `0x48` event buffer, decoded in full.

    **Fully decoded 2026-08-09.** ::

        00 00 35 01 | 13 81 | 15 | 01 | 21 03 26 15 50 23
        └─ serial ─┘  code    │    │    └── DD MM YY HH MM SS (BCD) ──┘
                              │    partition (0x63 = 99 = fence)
                              zone / user / channel

    Source: `docs/protocol/event-buffer.md`. Confirmed over 1073 records: every `code` is a valid
    Contact ID, the serial increases monotonically, and fence events carry `partition == 99`. The
    `subject` is a zone number, a user number or a channel depending on the code — the same
    ambiguity Contact ID has everywhere, resolved by the code (see `EventSubject`).
    """

    serial: int
    """Monotonic 32-bit event index, big-endian. The paging cursor: a client asks for the records
    after the highest serial it already holds."""

    contact_id: str
    """The four Contact ID digits as text, e.g. `"1381"`. Two BCD bytes; kept as text because the
    leading digit is a qualifier (`1` new / `3` restore), not a magnitude."""

    subject: int
    """Zone, user or channel number — a raw byte. `0` when the code names none (fence events)."""

    partition: int
    """Partition the event belongs to. `99` (`0x63`) is the fence — see `FENCE_PARTITION`."""

    timestamp: str
    """`DD/MM/YY HH:MM:SS`, six BCD bytes, or empty if malformed."""

    @property
    def is_fence(self) -> bool:
        """Whether this event belongs to the electric fence (partition 99)."""
        return self.partition == FENCE_PARTITION


@dataclass(frozen=True, slots=True)
class EventBuffer:
    """One page of the `0x48` event-buffer download. The panel returns eight records per page."""

    records: tuple[EventRecord, ...] = ()
    seq: int = 0


@dataclass(frozen=True, slots=True)
class UnknownPacket:
    """A frame this package does not decode.

    Returned rather than dropped: an undecoded frame that reaches the coordinator can be logged at
    debug with its bytes, which is how the next undocumented command gets found. Dropping it
    silently is how the old integration hides them.
    """

    cmd: int
    payload: bytes
    seq: int = 0


Packet = (
    ConnectionInfo
    | KeepAlive
    | PanelEvent
    | PanelStatus
    | MonitorStatus
    | LoginInfo
    | CommandResponse
    | ProgrammingBlock
    | WirelessInventory
    | EventBuffer
    | UnknownPacket
)
"""Anything `decode()` can return."""
