"""The panel's programming address space: where things are, and how to read them.

Source: `docs/protocol/programming.md`, recovered by capturing ActiveNet reading a real Active 32
Duo (firmware 7.60) on 2026-08-08. **No JFL PDF documents any of this.**

Three things shape the whole module.

**The programming is a flat 16-bit address space, not numbered blocks.** `0x44` takes a big-endian
start address and a byte count, and the proof is that ActiveNet's 39 reads tile the space
contiguously — each request starting exactly where the previous one ended. So a caller can ask for
*one record* instead of a window, which is what makes reading a single zone's name cheap.

**Every name is nine bytes padded with `0xFF`.** Not NUL, not spaces. A parser that strips the wrong
byte gets names with `ÿÿ` on the end.

**This space holds secrets.** Every user's access code sits at offset 9 of their record, and the
account numbers, the site name and the monitoring telephone numbers are all in here in clear.
`UserRecord` therefore exposes `has_code: bool` and **never the code itself** — redaction at the
point of parsing, so that no downstream diagnostics dump or log line can leak one by omission.
AGENTS.md §4.

> **These addresses are from an Active 32 Duo.** A panel with a different zone or user count almost
> certainly moves the later tables. Nothing here should be trusted for another model without a
> capture — see `MEMORY_MAP` and the note in `docs/protocol/programming.md`.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, unique
from typing import Final

from .models import WIRELESS_MODELS

NAME_PAD: Final = 0xFF
"""Names are padded with `0xFF`: a nine-byte field holding "Ana" is `41 6E 61 FF FF FF FF FF FF`."""

NAME_LENGTH: Final = 9
MAX_READ: Final = 0x70
"""The largest byte count observed in a `0x44` request, and the most ActiveNet ever asks for.

Treated as a hard ceiling rather than a preference: nothing has ever asked the panel for more, so
nothing knows what it does with a larger count.
"""


# ---------------------------------------------------------------------------------------------
# Where things live
# ---------------------------------------------------------------------------------------------

PARTITION_NAMES_BASE: Final = 0x006F
PARTITION_RECORD_SIZE: Final = NAME_LENGTH
"""Just the name. **The flag byte is one leading byte for the whole region, not one per record.**

`docs/protocol/programming.md` described it the other way round, and the fixture proves otherwise:
`01 | "Interno"+FF FF | "Externo"+FF FF | …` decodes cleanly only as a single leading byte followed
by four bare nine-byte names. The arithmetic confirms it — ActiveNet read exactly `0x25` = 37 bytes
here, and `1 + 4 * 9 = 37`. Read it as ten-byte records and every partition after the first loses
its first character."""

REGION_FLAG_SIZE: Final = 1
"""The leading byte that precedes the records in the partition-name and PGM regions."""

ACCOUNTS_BASE: Final = 0x0100
PGM_BASE: Final = 0x01BF
PGM_RECORD_SIZE: Final = 16
"""A 9-byte name + 7 attribute bytes, after the region's one leading byte.

Same shape as the partition names, and the same arithmetic check: ActiveNet read `0x41` = 65 bytes,
and `1 + 4 * 16 = 65`."""

USER_BASE: Final = 0x0580
USER_RECORD_SIZE: Final = 16
"""A 9-byte name + a **3-byte access code** + 4 attribute bytes. See the module docstring."""

ZONE_BASE: Final = 0x1000
ZONE_RECORD_SIZE: Final = 16
"""A 9-byte name + 7 attribute bytes."""

WIRELESS_BASE: Final = 0x1800
WIRELESS_RECORD_SIZE: Final = 8
"""A 4-byte big-endian serial + the zone number + 3 spare bytes, in the **programming table**.

Not to be confused with `INVENTORY_RECORD_SIZE`: the `0x59` inventory reports the same devices with
sixteen bytes of live data each."""

INVENTORY_RECORD_SIZE: Final = 16
"""One record of the `0x59` **inventory** reply: slot, serial, zone, state, last transmission, link.

Twice the size of a programming-table record for the same device, which is an easy thing to confuse
and produces an `IndexError` at best."""

HOLIDAYS_BASE: Final = 0x0000
HOLIDAY_RECORD_SIZE: Final = 2
"""One holiday is two BCD bytes, `DD MM`. **Confirmed 2026-08-09**: the region opens with the
panel's eight programmed holidays as recognisable Brazilian dates (`01/01`, `21/04`, `01/05`,
`07/09`, `12/10`, `02/11`, `15/11`, `25/12`), and adding a ninth in ActiveNet wrote its `DD MM` into
slot 9."""

MAX_ZONES: Final = 32
MAX_USERS: Final = 98
MAX_PGMS: Final = 4
MAX_PARTITIONS: Final = 4
MAX_WIRELESS: Final = 32
MAX_HOLIDAYS: Final = 16
"""Sixteen holiday slots. Unused slots read `01 01`, indistinguishable from a real New-Year
holiday — the panel keeps no separate "used" flag, so a trailing run of `01/01` is *probably*
empty, not certain."""


def zone_address(number: int) -> int:
    """Return where zone *number*'s 16-byte record starts. 1-based."""
    return ZONE_BASE + (number - 1) * ZONE_RECORD_SIZE


def user_address(number: int) -> int:
    """Return where user *number*'s 16-byte record starts. 1-based."""
    return USER_BASE + (number - 1) * USER_RECORD_SIZE


def pgm_address(number: int) -> int:
    """Return where PGM *number*'s 16-byte record starts. 1-based.

    Offset by the region's single leading byte — see `PGM_RECORD_SIZE`.
    """
    return PGM_BASE + REGION_FLAG_SIZE + (number - 1) * PGM_RECORD_SIZE


def partition_address(number: int) -> int:
    """Return where partition *number*'s 9-byte name starts. 1-based.

    Offset by the region's single leading byte — see `PARTITION_RECORD_SIZE`.
    """
    return PARTITION_NAMES_BASE + REGION_FLAG_SIZE + (number - 1) * PARTITION_RECORD_SIZE


def wireless_address(slot: int) -> int:
    """Return where wireless slot *slot*'s 8-byte record starts. 1-based."""
    return WIRELESS_BASE + (slot - 1) * WIRELESS_RECORD_SIZE


# ---------------------------------------------------------------------------------------------
# Reading names
# ---------------------------------------------------------------------------------------------


def decode_name(data: bytes) -> str:
    """Decode a fixed-width, `0xFF`-padded name field.

    Latin-1 rather than ASCII, because the panel accepts accented characters and a strict ASCII
    decode would raise on somebody's "Cozinha" spelled with a cedilla. Trailing padding and
    whitespace are stripped; an all-padding field is an empty string, which is how "this record has
    no name" is expressed.
    """
    return data.split(bytes([NAME_PAD]))[0].decode("latin-1", "replace").strip()


# ---------------------------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------------------------


ZONE_TYPE_NAMES: Final[dict[int, str]] = {
    0: "Imediata",
    1: "Temporizada 1",
    2: "Temporizada 2",
    3: "Seguidora",
    4: "24 horas",
    # 5 and 6 are *not* Ronda and 24 horas pânico. See the gap below — they are unknown.
    9: "24 horas tamper",
}
"""Zone-type label for the low nibble of attribute byte 0, in **JFL's own words**.

The panel has **exactly nine** zone types: the programmer app's `Tipo` dropdown
(`docs/referencia/imagens/tipos-zonas.png`) and the panel manual §8.1.1-8.1.9 list the same nine in
the same order, and the author confirmed the list is complete. *Desabilitada* is the first of them
and is **not** a value here — a disabled zone is expressed by the whole attribute byte reading
`0x00`, which is why the enabled types start at 0.

**Every entry above is anchored to a labelled write or a real zone**, from the 2026-08-09 session
(`docs/captures/2026-08-09-differential.md`):

| Value | Label | How it is known |
|---|---|---|
| 0 | Imediata | zone 11 was asked for *Imediata* and did not move: it already read 0 |
| 1 | Temporizada 1 | zone 12's edit, and zone 17 displays it while storing 1 |
| 2 | Temporizada 2 | zone 20 displays it while storing 2 — in the backup image and on screen |
| 3 | Seguidora | zone 13's edit |
| 4 | 24 horas | zone 14's edit |
| 9 | 24 horas tamper | zone 22 set to the list's last entry wrote `0x19` |

> ⚠️ **The value space is not a dense index of the list, and that is the finding.** Five labels map
> to 0-4 in order, and then the ninth and last jumps to **9**. So two codes exist between them that
> the app never offers, and **the two labels without a value are *Ronda* and *24 horas pânico***.
> Which of 5, 6, 7 or 8 each of them is cannot be derived from a gap — a straight index is exactly
> the hypothesis the `9` disproves. They stay out until a labelled read pins them, and a zone on an
> unknown value reports `zone_type_index` and no name. A wrong type name is a confident falsehood
> about what a detector does. ADR-0013; the two-minute procedure is in `BACKLOG.md`.
>
> ⚠️ Corrected 2026-08-10: this table previously ran 0-7 straight down the list, which put
> *24 horas tamper* at 7 — where the panel's own write proves it is 9 — and shipped *Ronda* and
> *24 horas pânico* as 5 and 6 on no evidence at all. Three of its eight labels were wrong.
>
> ⚠️ Corrected 2026-08-09: this table previously had *Ronda* at 4 and *24 horas* at 5. The app lists
> them the other way round.
"""

CHIME_MASK: Final = 0x40
"""Attribute byte 3, bit 6 — the zone's *Chime* (doorbell) flag.

**Confirmed 2026-08-09**: marking Chime on zone 21 in ActiveNet flipped attribute byte 3 from `0x21`
to `0x61`, exactly this bit and no other."""

ALLOWS_BYPASS_MASK: Final = 0x01
"""Attribute byte 3, bit 0 — *Permite inibir*: whether this zone may be bypassed at all.

**Confirmed 2026-08-09 (labelled differential).** Turning *Permite Inibir* off on zone 20 moved
attribute byte 3 from `0x11` to `0x10` — exactly this bit. It is the one zone attribute with a free
independent cross-check: the status frame's `P-INIB` bitmap answers the same question, and the two
structures agree on the captured panel."""

ZONE_PARTITION_MASK: Final = 0x0F
"""Attribute byte 4, low nibble — the **partitions this zone belongs to**, as a bitmap.

`0x01` = A, `0x02` = B, `0x04` = C, `0x08` = D.

**Confirmed 2026-08-09 (labelled differential), and it settles two long-open questions.** Assigning
zone 8 to partition B alone moved its attribute byte 4 from `0x01` to `0x02`; assigning zone 9 to
partitions A *and* B moved it to `0x03`; zone 10 was left alone as the control cell and stayed
`0x01`. So **a zone can belong to more than one partition** — the author's open question — and the
answer was never in the `0x1640` table, which reads all zero on this panel and is not this field.
Nine sprints' worth of "needs a multi-partition capture" resolves to this nibble."""

STAY_MASK: Final = 0x10
"""Attribute byte 4, bit 4 — *Stay*: the zone is ignored when the partition is armed at home.

**Confirmed 2026-08-09**: setting *Stay* on zone 16 moved attribute byte 4 from `0x01` to `0x11`.
Corroborated by the pristine backup, where the already-`0x11` zones are exactly the interior
detectors (`I Cozinha`, `I Sala`) — which is what a Stay zone is for."""

SMART_MASK: Final = 0x20
"""Attribute byte 4, bit 5 — *Inteligente*: the zone must trip twice inside the smart-zone timer.

**Confirmed 2026-08-09**: setting it on zone 17 moved attribute byte 4 from `0x01` to `0x21`."""

AUTO_BYPASS_MASK: Final = 0x80
"""Attribute byte 4, bit 7 — *Auto anulável*: the panel bypasses this zone by itself if it is open
at arming time, instead of refusing to arm.

**Confirmed 2026-08-09**: setting it on zone 18 moved attribute byte 4 from `0x01` to `0x81`."""

SILENT_MASK: Final = 0x40
"""Attribute byte 4, bit 6 — *Silenciosa*: the zone alarms without sounding the siren.

**Confirmed 2026-08-09 (session 2)**: ticking it on zone 26 moved attribute byte 4 from `0x01` to
`0x41`. It had been predicted from the checkbox order on the programmer screen and is now measured,
which is the order this project prefers: predict, then test."""

SIREN_PULSED_MASK: Final = 0x04
"""Attribute byte 3, bit 2 — *Sirene intermitente*: this zone drives a pulsing siren, not a steady
one.

**Confirmed 2026-08-09 (session 2)**: ticking it on zone 22 moved attribute byte 3 `0x11` to
`0x15`."""

OPEN_DOOR_MASK: Final = 0x80
"""Attribute byte 3, bit 7 — *Porta aberta*: the zone feeds the open-door timer rather than alarming
immediately.

**Confirmed 2026-08-09 (session 2)**: ticking it on zone 23 moved attribute byte 3 `0x11` to
`0x91`."""

SENSITIVITY_MASK: Final = 0x38
"""Attribute byte 3, bits 3-5 — the zone's *Sensibilidade*, one-hot.

**Fully confirmed 2026-08-09 (session 2).** The programmer offers three levels and each was pinned
to a bit: *Média* `0x10` (read off zone 17, which displays *Média* and stores `0x11`), *Máxima*
`0x20` (setting it on zone 24 moved `0x11` → `0x21`) and *Mínima* `0x08` (zone 25, `0x11` → `0x09`).

One-hot rather than a two-bit number, so an unrecognised combination is possible in principle and
reads as `None` rather than as a wrong level."""


@unique
class ZoneSensitivity(IntEnum):
    """How sensitive a zone's detector is set to be, as the programmer offers it.

    The values are the raw bits, not an ordinal, because that is what the panel stores — but they
    happen to sort in the right order, so `min(...)` and comparisons behave as a reader expects.
    """

    MINIMUM = 0x08
    MEDIUM = 0x10
    MAXIMUM = 0x20


@dataclass(frozen=True, slots=True)
class ZoneRecord:
    """One zone's programming: its name, whether it is in use, and its option bytes.

    The seven attribute bytes (record bytes 9-15) decode as far as the 2026-08-09 differential
    reached — `docs/protocol/programming.md` has the full table:

    | Attr byte | Record byte | Meaning | Confidence |
    |---|---|---|---|
    | 0 | 9 | `0x00` = disabled; else enabled, **low nibble = type** | location confirmed |
    | 3 | 12 | **Permite inibir** `0x01`, sensitivity `0x38`, **Chime** `0x40` | bypass + Chime ✅ |
    | 4 | 13 | **partitions** (low nibble), **Stay** `0x10`, **Inteligente** `0x20`, `0x40`
      unlabelled, **Auto anulável** `0x80` | confirmed 2026-08-09 |
    | 1,2,5,6 | 10,11,14,15 | `0xFF` on every record seen — padding | — |
    """

    number: int
    name: str
    attributes: bytes

    @property
    def enabled(self) -> bool:
        """Whether the zone is in use on this installation.

        **Attribute byte 0 `== 0x00` means disabled**, and this is the one option byte verified
        against an independent source: on the captured panel the zones reading `0x00` are exactly
        the complement of the ones the status frame's `P-INIB` grants bypass to. Two unrelated
        structures agreeing on the same nine zones is not a coincidence.
        """
        return bool(self.attributes) and self.attributes[0] != 0x00

    @property
    def zone_type_index(self) -> int | None:
        """The low nibble of attribute byte 0 — the zone's type index.

        `None` for a disabled zone (whole byte `0x00`) or a truncated record. The nibble's
        *location* is confirmed; the label for each value is a hypothesis in `ZONE_TYPE_NAMES`.
        """
        if not self.enabled:
            return None
        return self.attributes[0] & 0x0F

    @property
    def chime(self) -> bool:
        """Whether the zone rings the keypad chime when it opens. **Confirmed** — `CHIME_MASK`."""
        return len(self.attributes) > 3 and bool(self.attributes[3] & CHIME_MASK)

    @property
    def allows_bypass(self) -> bool:
        """Whether the zone may be bypassed. **Confirmed** — `ALLOWS_BYPASS_MASK`.

        The status frame's `P-INIB` answers the same question for the panel as a whole, and stays
        the authority at runtime; this is the same fact read from the programming, which is what
        lets a bypass switch explain *why* a zone has none.
        """
        return len(self.attributes) > 3 and bool(self.attributes[3] & ALLOWS_BYPASS_MASK)

    @property
    def partitions(self) -> tuple[int, ...]:
        """The partitions this zone belongs to, 1-based and ascending. **Confirmed** 2026-08-09.

        Empty for a truncated record, and empty — not `(1,)` — for a zone assigned to no partition
        at all, because "belongs nowhere" is a real state and defaulting it to partition A would
        silently place a detector in an area it does not protect. See `ZONE_PARTITION_MASK`.
        """
        if len(self.attributes) <= 4:
            return ()
        bitmap = self.attributes[4] & ZONE_PARTITION_MASK
        return tuple(n for n in range(1, MAX_PARTITIONS + 1) if bitmap & (1 << (n - 1)))

    @property
    def sensitivity(self) -> ZoneSensitivity | None:
        """The zone's programmed sensitivity, or `None` if the field holds no known level.

        `None` is the honest answer for an unrecognised bit pattern: the field is one-hot with three
        defined values, and reporting an unexpected combination as "minimum" would be a guess about
        a detector's behaviour. See `SENSITIVITY_MASK`.
        """
        if len(self.attributes) <= 3:
            return None
        try:
            return ZoneSensitivity(self.attributes[3] & SENSITIVITY_MASK)
        except ValueError:
            return None

    @property
    def siren_pulsed(self) -> bool:
        """Whether this zone drives a pulsing siren — *Sirene intermitente*."""
        return len(self.attributes) > 3 and bool(self.attributes[3] & SIREN_PULSED_MASK)

    @property
    def open_door(self) -> bool:
        """Whether this zone feeds the open-door timer — *Porta aberta*."""
        return len(self.attributes) > 3 and bool(self.attributes[3] & OPEN_DOOR_MASK)

    @property
    def silent(self) -> bool:
        """Whether this zone alarms without the siren — *Silenciosa*. See `SILENT_MASK`."""
        return len(self.attributes) > 4 and bool(self.attributes[4] & SILENT_MASK)

    @property
    def stay(self) -> bool:
        """Whether the zone is ignored in *arm home*. **Confirmed** — `STAY_MASK`."""
        return len(self.attributes) > 4 and bool(self.attributes[4] & STAY_MASK)

    @property
    def smart(self) -> bool:
        """Whether the zone must trip twice to alarm — *Inteligente*. See `SMART_MASK`."""
        return len(self.attributes) > 4 and bool(self.attributes[4] & SMART_MASK)

    @property
    def auto_bypass(self) -> bool:
        """Whether the panel self-bypasses this zone when arming. See `AUTO_BYPASS_MASK`."""
        return len(self.attributes) > 4 and bool(self.attributes[4] & AUTO_BYPASS_MASK)


@dataclass(frozen=True, slots=True)
class PartitionRecord:
    """One partition's name."""

    number: int
    name: str


@unique
class PgmFunction(IntEnum):
    """What a PGM output does. Source: the panel manual §18.1, addresses 821-824.

    **Confirmed against JFL's own programmer app on 2026-08-09**, screen by screen — see
    `docs/referencia/activenet-programmer/`. The app showed PGM 1 as *"Armar/desarmar o
    eletrificador"* and PGM 2 as *"Aciona junto com o arme da partição A"*, and the captured record
    reads 18 and 6 in attribute byte 5. Two panels' worth of agreement in one screenshot.

    Only `USER_RETAINED` and `USER_PULSED` are operable from a monitoring connection, which is what
    `P-PGM` reports. Everything else is the panel doing its own job.
    """

    DISABLED = 0
    WITH_SIREN = 1
    SIREN_PARTITION_B = 2
    SIREN_PARTITION_C = 3
    SIREN_PARTITION_D = 4
    WITH_FULL_ARM = 5
    WITH_PARTITION_A_ARM = 6
    WITH_PARTITION_B_ARM = 7
    WITH_PARTITION_C_ARM = 8
    WITH_PARTITION_D_ARM = 9
    ON_TROUBLE = 10
    SCHEDULED = 11
    """On and off at the times in this record's own `on_at` / `off_at` fields."""

    USER_RETAINED = 12
    USER_PULSED = 13
    PATROL_OK = 14
    PATROL_FAILED = 15
    ANY_ZONE_ALARM = 16
    ZONE_1_ALARM = 17
    ELECTRIC_FENCE = 18
    """⚠️ **This output *is* the energiser's switch.** ADR-0007."""

    ZONE_2_ALARM = 19
    ZONE_3_ALARM = 20
    ZONE_4_ALARM = 21
    PANIC = 22
    ZONE_24H_ALARM = 23
    ZONE_1_OPENING = 24
    ELECTRIC_FENCE_SILENT = 25
    """The Active 20's silent energiser: same job, no siren on a fence alarm."""

    @property
    def drives_fence(self) -> bool:
        """Whether an output on this function switches the electric fence.

        **Both variants**, because 25 is an energiser too — anything detecting "which PGM drives the
        fence" that checked only for 18 would miss every Active 20.
        """
        return self in (PgmFunction.ELECTRIC_FENCE, PgmFunction.ELECTRIC_FENCE_SILENT)

    @property
    def user_operable(self) -> bool:
        """Whether a monitoring connection can switch this output at all."""
        return self in (PgmFunction.USER_RETAINED, PgmFunction.USER_PULSED)


PGM_FUNCTION_LABELS: Final[dict[int, str]] = {
    0: "Desabilitada",
    1: "Aciona junto com a sirene",
    2: "Sirene para partição 2",
    3: "Sirene para partição 3",
    4: "Sirene para partição 4",
    5: "Aciona junto com o arme total",
    6: "Aciona junto com o arme da partição 1",
    7: "Aciona junto com o arme da partição 2",
    8: "Aciona junto com o arme da partição 3",
    9: "Aciona junto com o arme da partição 4",
    10: "Aciona quando houver problema no sistema",
    11: "Aciona e desaciona no horário programado",
    12: "Com retenção acionada pelo usuário",
    13: "Sem retenção acionada pelo usuário",
    14: "Aciona sem retenção quando ronda ok",
    15: "Aciona sem retenção na falha de ronda",
    16: "Aciona sem retenção no disparo da zona",
    17: "Aciona no disparo da zona 1",
    18: "Aciona para armar e desarmar o eletrificador",
    19: "Aciona no disparo da zona 2",
    20: "Aciona no disparo da zona 3",
    21: "Aciona no disparo da zona 4",
    22: "Aciona no pânico",
    23: "Aciona no disparo zona 24 horas",
    24: "Aciona junto com abertura da zona 1",
    25: "Aciona para armar e desarmar o eletrificador (silencioso)",
}
"""The function of a PGM output, in **JFL's own words**.

Transcribed verbatim from the programmer app's `Configuração` dropdown on 2026-08-09, which numbers
every entry itself — `00 - Desabilitada` through `24 - Aciona junto com abertura da zona 1` — so the
stored byte and the label are the same number and there is nothing to infer. Kept in Portuguese
because it is the vendor's own vocabulary and an installer will be reading it next to the app.

Value **25** is not in the Active 32 Duo's list; it is the Active 20's silent energiser, and its
wording here is descriptive rather than transcribed.

⚠️ Function **18** (and 25) *is* the electric fence's power supply — see `PgmFunction.drives_fence`.
"""


def decode_pgm_duration(raw: int) -> int:
    """Decode a PGM's activation time to **seconds**. Source: the panel manual §18.2.

    **The scale is not linear and must never be shown as one**: `1`-`200` counts *minutes* and
    `201`-`255` counts *seconds* minus 200. So `202` is two seconds and `2` is two minutes — a
    hundred and twenty times longer, from two adjacent numbers.

    Verified against the programmer app: the captured panel reads `0xCA` (202) on the fence PGM and
    `0xC9` (201) on the next, and the app showed them as 2 seconds and 1 second.
    """
    if raw > 200:
        return raw - 200
    return raw * 60


def decode_bcd_time(hour: int, minute: int) -> str:
    """Decode a BCD `HH MM` pair to `HH:MM`, or an empty string if either half is not BCD."""
    if (hour >> 4) > 9 or (hour & 0x0F) > 9 or (minute >> 4) > 9 or (minute & 0x0F) > 9:
        return ""
    return f"{(hour >> 4) * 10 + (hour & 0x0F):02d}:{(minute >> 4) * 10 + (minute & 0x0F):02d}"


@dataclass(frozen=True, slots=True)
class PgmRecord:
    """One PGM output's programming — **fully decoded**.

    ::

        "PGM 1"      | 00 00 | 00 00 | CA | 12 | FF
        9-byte name    on      off     dur  fn   unused

    | Byte | Field |
    |---|---|
    | 9-10 | Time the output switches **on**, BCD `HH MM` — only used by `SCHEDULED` |
    | 11-12 | Time it switches **off**, BCD `HH MM` |
    | 13 | Activation duration, in the manual's own scale — see `decode_pgm_duration` |
    | 14 | **Function**, `PgmFunction` |
    | 15 | `0xFF` on every record seen |

    **Confirmed field by field against JFL's programmer app on 2026-08-09.** The captured panel's
    PGM 1 decodes as *fence, 2 seconds, 00:00-00:00* and PGM 4 as *scheduled, 2 seconds,
    17:45-22:00*, which is exactly what the app displayed. Sprint 6 had reported this record as
    undecodable, on a capture where no PGM function had ever been varied; one screenshot settled it.
    """

    number: int
    name: str
    attributes: bytes

    @property
    def function(self) -> PgmFunction | None:
        """What this output does, or `None` for a value no firmware documents.

        `None` rather than raising: a firmware that grows a twenty-seventh function must not take
        the whole programming read down with it.
        """
        if len(self.attributes) < 6:
            return None
        try:
            return PgmFunction(self.attributes[5])
        except ValueError:
            return None

    @property
    def duration_seconds(self) -> int:
        """How long the output stays on when its function is a pulsed one."""
        return decode_pgm_duration(self.attributes[4]) if len(self.attributes) > 4 else 0

    @property
    def on_at(self) -> str:
        """`HH:MM` this output switches on, for `SCHEDULED`. Empty when unset."""
        return decode_bcd_time(*self.attributes[:2]) if len(self.attributes) > 1 else ""

    @property
    def off_at(self) -> str:
        """`HH:MM` this output switches off, for `SCHEDULED`. Empty when unset."""
        return decode_bcd_time(*self.attributes[2:4]) if len(self.attributes) > 3 else ""

    @property
    def drives_fence(self) -> bool:
        """⚠️ Whether this output switches the electric fence — function 18 or 25.

        **This is what Sprints 4 and 6 could not answer**, and the reason the panel's settings ask
        the user "which PGM drives the fence". With the function decoded, that option becomes an
        override rather than the only source. ADR-0007.
        """
        function = self.function
        return function is not None and function.drives_fence


@dataclass(frozen=True, slots=True)
class UserPermissions:
    """What one user is allowed to do, decoded from the four attribute bytes of their record.

    **Fully mapped on 2026-08-09**, from the programmer's own checkbox list reconciled against three
    real users' bytes and two labelled differentials. The layout is not one contiguous bitmap, which
    is why reading it "in order" produces nonsense:

    | Record byte | Bits |
    |---|---|
    | 12 | `0x01` patrol · `0x02` **operate the electric fence** |
    | 13 | `0x01` disarm · `0x02` forced arm · `0x04` bypass zones ·
      `0x08`-`0x40` operate PGM 1-4 · `0x80` remote access |
    | 14 | `0x80` schedule tasks |
    | 15 | low nibble — **arm** partitions A/B/C/D |

    Note that *arming* is per partition while *disarming* is a single permission, which is the
    panel's own asymmetry and not a decoding artefact.

    ⚠️ **No access code is here, and none can be.** The code is three bytes earlier in the record and
    `parse_users` discards it — AGENTS.md §4.
    """

    arm_partitions: tuple[int, ...]
    """Which partitions this user may arm, 1-based and ascending."""

    disarm: bool
    forced_arm: bool
    """*Armar Away* — arming with open zones, which the panel bypasses until they close."""

    bypass_zones: bool
    pgms: tuple[int, ...]
    """Which PGM outputs this user may operate, 1-based and ascending."""

    remote_access: bool
    """*Acesso SMS/Tel./App.* — whether this user may operate the panel remotely at all."""

    operate_fence: bool
    """⭐ Whether this user may arm and disarm the electric fence."""

    patrol: bool
    schedule_tasks: bool

    @classmethod
    def decode(cls, attributes: bytes) -> UserPermissions:
        """Decode the four attribute bytes. Missing bytes read as "not permitted"."""

        def byte(index: int) -> int:
            return attributes[index] if len(attributes) > index else 0

        first, second, third, fourth = byte(0), byte(1), byte(2), byte(3)
        return cls(
            arm_partitions=tuple(
                n for n in range(1, MAX_PARTITIONS + 1) if fourth & (1 << (n - 1))
            ),
            disarm=bool(second & 0x01),
            forced_arm=bool(second & 0x02),
            bypass_zones=bool(second & 0x04),
            pgms=tuple(n for n in range(1, MAX_PGMS + 1) if second & (0x08 << (n - 1))),
            remote_access=bool(second & 0x80),
            operate_fence=bool(first & 0x02),
            patrol=bool(first & 0x01),
            schedule_tasks=bool(third & 0x80),
        )


@dataclass(frozen=True, slots=True)
class UserRecord:
    """One user's programming, **with the access code deliberately absent**.

    The code is three BCD bytes at offset 9 of the record. It is read only far enough to answer "is
    one set?", and then discarded. Nothing downstream can leak what it was never given — which is
    the point: a diagnostics dump that forgot to redact a field cannot expose a code that is not in
    the object. AGENTS.md §4.
    """

    number: int
    name: str
    has_code: bool
    attributes: bytes

    @property
    def permissions(self) -> UserPermissions:
        """What this user is allowed to do. See `UserPermissions`."""
        return UserPermissions.decode(self.attributes)


@dataclass(frozen=True, slots=True)
class HolidayRecord:
    """One holiday date, `DD MM` in BCD. **Confirmed 2026-08-09** — see `HOLIDAY_RECORD_SIZE`."""

    index: int
    day: int
    month: int

    @property
    def formatted(self) -> str:
        """`DD/MM`, or an empty string for a malformed (non-BCD) slot."""
        if not (1 <= self.day <= 31 and 1 <= self.month <= 12):
            return ""
        return f"{self.day:02d}/{self.month:02d}"


@dataclass(frozen=True, slots=True)
class WirelessRecord:
    """One slot of the wireless device table at `0x1800`.

    Cross-validates against the `0x59` inventory slot for slot — the serial and the zone match on
    all nine devices in the capture — which is what makes both structures trustworthy.
    """

    slot: int
    serial: int
    zone: int
    spare: bytes

    @property
    def present(self) -> bool:
        """False for an empty slot, which the panel fills with `0xFF`."""
        return self.serial not in (0x00000000, 0xFFFFFFFF)

    @property
    def model(self) -> str | None:
        """The detector's model family, or `None` for a serial from an unknown family.

        **The family is the serial's high byte** — it is not a field of any record, which is why
        Sprint 0 concluded "the model is not in the record" and was right about the record while
        being wrong about the table. Confirmed against the panel's UI on all nine enrolled sensors
        (`WIRELESS_MODELS`).

        The value matters here rather than only in the `0x59` inventory because *this* table is read
        by an ordinary programming read, while the inventory needs the panel to be asked separately
        — so a zone's device page can name the detector without one.
        """
        if not self.present:
            return None
        return WIRELESS_MODELS.get((self.serial >> 24) & 0xFF)


# ---------------------------------------------------------------------------------------------
# Parsing a block of the address space
# ---------------------------------------------------------------------------------------------


def _record_at(data: bytes, base_address: int, address: int, size: int, index: int) -> bytes | None:
    """Slice record *index* out of *data*, which begins at *base_address*. `None` if not covered."""
    offset = address + index * size - base_address
    if offset < 0 or offset + size > len(data):
        return None
    return data[offset : offset + size]


def parse_zones(data: bytes, address: int) -> list[ZoneRecord]:
    """Return every complete zone record inside *data*, which was read from *address*.

    Partial records at either end are skipped rather than guessed at: a read that starts mid-record
    would otherwise produce a zone named from the tail of its neighbour.
    """
    return [
        ZoneRecord(number, decode_name(raw[:NAME_LENGTH]), raw[NAME_LENGTH:])
        for number in range(1, MAX_ZONES + 1)
        if (raw := _record_at(data, address, ZONE_BASE, ZONE_RECORD_SIZE, number - 1)) is not None
    ]


def parse_partitions(data: bytes, address: int) -> list[PartitionRecord]:
    """Return every complete partition name inside *data*."""
    return [
        PartitionRecord(number, decode_name(raw))
        for number in range(1, MAX_PARTITIONS + 1)
        if (
            raw := _record_at(
                data,
                address,
                PARTITION_NAMES_BASE + REGION_FLAG_SIZE,
                PARTITION_RECORD_SIZE,
                number - 1,
            )
        )
        is not None
    ]


def parse_pgms(data: bytes, address: int) -> list[PgmRecord]:
    """Return every complete PGM record inside *data*."""
    return [
        PgmRecord(number, decode_name(raw[:NAME_LENGTH]), raw[NAME_LENGTH:])
        for number in range(1, MAX_PGMS + 1)
        if (
            raw := _record_at(
                data, address, PGM_BASE + REGION_FLAG_SIZE, PGM_RECORD_SIZE, number - 1
            )
        )
        is not None
    ]


def parse_users(data: bytes, address: int) -> list[UserRecord]:
    """Return every complete user record inside *data*, **without their access codes**.

    The three code bytes are inspected only to decide `has_code` — an unset code reads `FF FF FF`,
    the same padding the rest of the space uses — and are never stored or returned.
    """
    records: list[UserRecord] = []
    for number in range(1, MAX_USERS + 1):
        raw = _record_at(data, address, USER_BASE, USER_RECORD_SIZE, number - 1)
        if raw is None:
            continue
        code = raw[NAME_LENGTH : NAME_LENGTH + 3]
        records.append(
            UserRecord(
                number=number,
                name=decode_name(raw[:NAME_LENGTH]),
                has_code=any(byte != NAME_PAD for byte in code),
                attributes=raw[NAME_LENGTH + 3 :],
            )
        )
    return records


def parse_wireless(data: bytes, address: int) -> list[WirelessRecord]:
    """Return every complete wireless-table record inside *data*."""
    return [
        WirelessRecord(
            slot=slot,
            serial=int.from_bytes(raw[:4], "big"),
            zone=raw[4],
            spare=raw[5:],
        )
        for slot in range(1, MAX_WIRELESS + 1)
        if (raw := _record_at(data, address, WIRELESS_BASE, WIRELESS_RECORD_SIZE, slot - 1))
        is not None
    ]


def parse_holidays(data: bytes, address: int) -> list[HolidayRecord]:
    """Return every complete holiday slot inside *data*, read from *address*.

    Each slot is two BCD bytes, `DD MM`. A slot with a non-BCD byte still returns a record — with a
    day or month out of range, so `HolidayRecord.formatted` reads empty — rather than being dropped,
    because a gap in the list would misalign every slot after it.
    """
    records: list[HolidayRecord] = []
    for index in range(1, MAX_HOLIDAYS + 1):
        raw = _record_at(data, address, HOLIDAYS_BASE, HOLIDAY_RECORD_SIZE, index - 1)
        if raw is None:
            continue
        records.append(
            HolidayRecord(
                index=index,
                day=(raw[0] >> 4) * 10 + (raw[0] & 0x0F),
                month=(raw[1] >> 4) * 10 + (raw[1] & 0x0F),
            )
        )
    return records


# ---------------------------------------------------------------------------------------------
# Timers, schedules and the global option bytes
# ---------------------------------------------------------------------------------------------


TIMERS_BASE: Final = 0x0120
"""The ten timers, one byte each, in the order the programmer app lists them.

**Confirmed 2026-08-09 by a labelled differential**: every timer was set to a distinct, recognisable
value in ActiveNet and the write compared against the restore of the same block, so each byte is
identified by the value that landed in it rather than by its position alone."""

AUTOTEST_UNIT_MASK: Final = 0x80
"""Bit 7 of the autotest byte selects the unit; the value is the low seven bits.

**Confirmed 2026-08-09**: the interval went from `0x18` (24, the default) to `0xF8` — the unit
dropdown changed *and* the value became 120, and both moved in the one byte."""


@dataclass(frozen=True, slots=True)
class TimerSettings:
    """The panel's ten programmable timers, in real units.

    Units are **not** uniform and that is the trap this class exists to absorb: entry, exit and the
    smart-zone timer are in seconds, while open-door, mains-loss and line-loss are in minutes, and
    the autotest interval carries its unit in a bit. Reading them all as one unit produces plausible
    numbers that are wrong by a factor of sixty.

    `None` means the timer is disabled — the panel writes `0xFF`, which is not "255 seconds".
    """

    entry_1_seconds: int | None
    entry_2_seconds: int | None
    exit_1_seconds: int | None
    exit_2_seconds: int | None
    open_door_minutes: int | None
    smart_zone_seconds: int | None
    ac_loss_minutes: int | None
    line_loss_minutes: int | None
    autotest_interval: int | None
    autotest_in_minutes: bool
    """True when the autotest interval is expressed in minutes rather than hours."""


def _timer(raw: int) -> int | None:
    """Return a timer byte, or `None` for the panel's `0xFF` disabled marker."""
    return None if raw == 0xFF else raw


def parse_timers(data: bytes, address: int) -> TimerSettings | None:
    """Decode the nine timer bytes at `TIMERS_BASE`. `None` if *data* does not cover them.

    Byte-for-byte confirmations, each from the value the operator typed into ActiveNet:
    `0x0120` entry 1 (45 s), `0x0121` entry 2 (90 s), `0x0122` exit 1 (55 s), `0x0123` exit 2
    (unchanged, 120 s), `0x0124` open door (7 min), `0x0125` smart zone (30 s), `0x0126` mains loss
    (2 min), `0x0127` line loss (unchanged), `0x0128` autotest (value + unit bit).
    """
    offset = TIMERS_BASE - address
    if offset < 0 or offset + 9 > len(data):
        return None
    block = data[offset : offset + 9]
    return TimerSettings(
        entry_1_seconds=_timer(block[0]),
        entry_2_seconds=_timer(block[1]),
        exit_1_seconds=_timer(block[2]),
        exit_2_seconds=_timer(block[3]),
        open_door_minutes=_timer(block[4]),
        smart_zone_seconds=_timer(block[5]),
        ac_loss_minutes=_timer(block[6]),
        line_loss_minutes=_timer(block[7]),
        autotest_interval=None if block[8] == 0xFF else block[8] & ~AUTOTEST_UNIT_MASK,
        autotest_in_minutes=bool(block[8] != 0xFF and block[8] & AUTOTEST_UNIT_MASK),
    )


GLOBAL_ZONE_OPTIONS_ADDRESS: Final = 0x0507
"""The global zone-option bits — the ones that apply to the panel, not to one zone.

**Confirmed 2026-08-09 by a labelled differential.** Three checkboxes were changed in one *Enviar*
and exactly three bits moved in this byte, which is what makes the one that matters unambiguous:
*Habilita zonas duplas* was the only option turned **off**, so it is the only **cleared** bit."""

END_OF_LINE_RESISTOR_MASK: Final = 0x01
"""*Zonas com resistor de fim de linha*. **Confirmed 2026-08-09 (session 2)** by elimination made
rigorous: the byte held exactly two bits and the screen held exactly two ticked boxes, one of which
was already known to be zone doubling."""

SIREN_ON_SHORT_MASK: Final = 0x02
"""*Dispara a sirene com curto de zona e alarme desarmado*.

**Confirmed 2026-08-09 (session 2)**: ticking it alone moved `0x05` → `0x07`. This is the bit that
had been indistinguishable from `WIRED_TAMPER_MASK` since both were turned on in one send — one
labelled tick separated the pair."""

WIRED_TAMPER_MASK: Final = 0x08
"""*Reconhecimento de tamper de zona com fio* — the other half of that pair, by elimination."""

ZONE_DOUBLING_MASK: Final = 0x04
"""*Habilita zonas duplas* — whether the panel splits each terminal into two zones.

**This is the flag Sprint 8.1 was blocked on**, because it changes how many zones the panel really
has: an Active 32 Duo reaches 32 zones from 16 terminals only with doubling on, and reports 16
without it. Cross-check on the captured panel: the bit is set, and the panel does have 32 zones.

~~The other two bits cannot be told apart.~~ **Separated 2026-08-09 (session 2)** — see
`SIREN_ON_SHORT_MASK`. The byte is now fully mapped."""


@dataclass(frozen=True, slots=True)
class GlobalZoneOptions:
    """The panel-wide zone options at `GLOBAL_ZONE_OPTIONS_ADDRESS`."""

    raw: int

    @property
    def zone_doubling(self) -> bool:
        """Whether zone doubling is enabled — see `ZONE_DOUBLING_MASK`."""
        return bool(self.raw & ZONE_DOUBLING_MASK)

    @property
    def end_of_line_resistor(self) -> bool:
        """Whether wired zones use an end-of-line resistor — `END_OF_LINE_RESISTOR_MASK`."""
        return bool(self.raw & END_OF_LINE_RESISTOR_MASK)

    @property
    def siren_on_short(self) -> bool:
        """Whether a shorted zone sounds the siren while disarmed — `SIREN_ON_SHORT_MASK`."""
        return bool(self.raw & SIREN_ON_SHORT_MASK)

    @property
    def wired_tamper(self) -> bool:
        """Whether wired-zone tamper is recognised — `WIRED_TAMPER_MASK`."""
        return bool(self.raw & WIRED_TAMPER_MASK)


def parse_global_zone_options(data: bytes, address: int) -> GlobalZoneOptions | None:
    """Decode the global zone-option byte. `None` if *data* does not cover it."""
    offset = GLOBAL_ZONE_OPTIONS_ADDRESS - address
    if offset < 0 or offset >= len(data):
        return None
    return GlobalZoneOptions(raw=data[offset])


AUTO_ARM_SCHEDULE_ADDRESS: Final = 0x0150
"""The first auto-arm schedule's start time, two BCD bytes `HH MM`.

**Located 2026-08-09**: setting *início autoarme* to 06:30 for partition A wrote `06 30` into these
two bytes, which had been `00 00`. The *encoding* is therefore confirmed; what is **not** confirmed
is the layout of the other two schedules or which byte selects the partition, because only one
schedule was changed. Documented, not parsed beyond this pair."""


def parse_auto_arm_time(data: bytes, address: int) -> tuple[int, int] | None:
    """Decode the first auto-arm schedule's `HH:MM`. `None` if absent, unset or not BCD."""
    offset = AUTO_ARM_SCHEDULE_ADDRESS - address
    if offset < 0 or offset + 2 > len(data):
        return None
    hour = (data[offset] >> 4) * 10 + (data[offset] & 0x0F)
    minute = (data[offset + 1] >> 4) * 10 + (data[offset + 1] & 0x0F)
    if not (0 <= hour <= 23 and 0 <= minute <= 59) or (hour == 0 and minute == 0):
        return None
    return hour, minute


# ---------------------------------------------------------------------------------------------
# Planning a read
# ---------------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ReadRequest:
    """One `0x44` request: where to start, and how many bytes to ask for."""

    address: int
    count: int

    @property
    def end(self) -> int:
        """The first address *after* this request."""
        return self.address + self.count


def plan_read(address: int, length: int, *, chunk: int = MAX_READ) -> list[ReadRequest]:
    """Split a range into requests the panel will accept, none larger than `MAX_READ`.

    Requests tile contiguously, exactly as ActiveNet's do — which is both what the panel expects and
    what makes the reassembled bytes a plain concatenation.
    """
    if length <= 0:
        raise ValueError(f"cannot read {length} bytes")
    if not 0 < chunk <= MAX_READ:
        raise ValueError(f"chunk must be 1-{MAX_READ}, got {chunk}")
    return [
        ReadRequest(address + offset, min(chunk, length - offset))
        for offset in range(0, length, chunk)
    ]


REGIONS: Final[dict[str, tuple[int, int]]] = {
    # name -> (start address, length). Only the regions this integration can currently parse; the
    # rest of the space is mapped in `docs/protocol/programming.md` and left for a later sprint.
    "partition_names": (
        PARTITION_NAMES_BASE,
        REGION_FLAG_SIZE + MAX_PARTITIONS * PARTITION_RECORD_SIZE,
    ),
    "pgms": (PGM_BASE, REGION_FLAG_SIZE + MAX_PGMS * PGM_RECORD_SIZE),
    "users": (USER_BASE, MAX_USERS * USER_RECORD_SIZE),
    "zones": (ZONE_BASE, MAX_ZONES * ZONE_RECORD_SIZE),
    "wireless": (WIRELESS_BASE, MAX_WIRELESS * WIRELESS_RECORD_SIZE),
    "holidays": (HOLIDAYS_BASE, MAX_HOLIDAYS * HOLIDAY_RECORD_SIZE),
    "timers": (TIMERS_BASE, 0x34),
    # Long enough to reach the auto-arm time at 0x0150 as well, which is why it is not just the
    # nine timer bytes: one region read costs the same as one, and two would cost two.
    "zone_options": (GLOBAL_ZONE_OPTIONS_ADDRESS - 7, 9),
    # The block ActiveNet writes as a unit is 0x0500+9; the option byte sits at its offset 7.
}
"""The regions worth reading, and what a full read has to cover.

**Deliberately not the whole address space.** Reading everything means 39 round trips on a link that
is also carrying the status poll and the keypad bus; reading these five means the integration knows
the names, the users and the wireless inventory, which is all anything downstream currently asks
for.
"""


def plan_region(region: str) -> list[ReadRequest]:
    """Return the requests that cover one named region of `REGIONS`."""
    address, length = REGIONS[region]
    return plan_read(address, length)
