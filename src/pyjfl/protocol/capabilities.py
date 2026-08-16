"""What a panel can actually do, merged from the three sources that know.

The author's standing requirement is that the integration **detect** what a panel has rather than
assume an Active 32 Duo: not every panel has four partitions, thirty-two zones or an energiser, and
one that has none of them must produce exactly the entities for what it has.

Three sources answer that, and they are ranked — a later one overrides an earlier one:

| | Source | Answers |
|---|---|---|
| 1 | `ModelSpec` from the `0x21` model byte | the **ceiling**: the most partitions/zones/PGMs |
| 2 | the status frame | what is **in use**: `ELET != 0x00`, a zone nibble that is not `DISABLED` |
| 3 | the **programming** | what things **are**: which PGM drives the fence, zone types, names |

This object is the one place those three are combined, so that no platform reasons about the model
table on its own — which is what the diagnostics `capabilities` block, the switch platform and the
PGM-function detection all read from now.

**Pure**: standard library plus the rest of `protocol`, no Home Assistant, no I/O. It takes the
already-decoded packets and records and returns a plain description, so it can be unit-tested at any
model byte without a socket or a panel.

> **What this deliberately does not yet detect.** "Habilita zonas duplas" (reference screen 3)
> halves a doubling panel's real zone count, and its programming address is **not known** — it needs
> a differential capture, which is in `BACKLOG.md`. Until then `zones` is the model ceiling and the
> hook is `_doubling_cap`, so wiring it up later is one method, not a redesign.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .models import ModelSpec, PanelStatus

if TYPE_CHECKING:
    from collections.abc import Mapping

    from .programming import GlobalZoneOptions, PgmRecord

NO_FENCE_PGM = 0
"""The `fence_pgm` setting's "none / unknown" value. Mirrored from `const` to keep this pure."""


@dataclass(frozen=True, slots=True)
class JflCapabilities:
    """A merged, source-ranked view of what one panel can do.

    Built with :meth:`detect`. Every field is already resolved — a platform reads ``pgms`` rather
    than ``spec.pgms``, so the day zone doubling or a bus expander changes a count, it changes here
    and nowhere else.
    """

    model: ModelSpec
    """Kept for its name and its `verified_on_hardware` flag, not for its counts — those are the
    fields below, which are the counts *after* status and programming have had their say."""

    partitions: int
    """How many partitions can exist. The model ceiling; the status frame decides which of them are
    actually programmed, and that stays the platforms' job because it is state, not capability."""

    zones: int
    """How many zones can exist. The model ceiling today — see the module note on zone doubling."""

    pgms: int
    """How many PGM outputs the model has."""

    has_fence: bool
    """Whether an electric fence exists. `ELET != 0x00` once a status frame has arrived, and the
    model's own answer before then — a panel whose model has no energiser never grows a fence
    entity, and one that has the capability but reads `0x00` has no fence *configured* and gets none
    either."""

    detected_fence_pgm: int | None
    """Which PGM output drives the energiser, read from the programming — or `None` when the
    programming has not been read, or names no such output. This is what Sprints 4 and 6 could not
    answer and screenshots of JFL's programmer app settled: a PGM on function 18 (or 25, the Active
    20's silent energiser) *is* the fence's power. See `PgmRecord.drives_fence` and ADR-0011."""

    zone_doubling: bool | None
    """Whether the panel splits each terminal into two zones — `None` until the programming is read.

    Read from the programming (`GlobalZoneOptions.zone_doubling`), decoded 2026-08-09. `None` and
    `True` both mean "assume the model's full zone count": the ceiling is the safe answer when the
    truth is unknown, because hiding a real detector is worse than showing an unused one."""

    @classmethod
    def detect(
        cls,
        model: ModelSpec,
        status: PanelStatus | None = None,
        pgms: Mapping[int, PgmRecord] | None = None,
        zone_options: GlobalZoneOptions | None = None,
    ) -> JflCapabilities:
        """Merge the three sources into one description.

        *status* is `None` before the panel's first status frame, and *pgms* and *zone_options* are
        `None` until a programming read has run — all three are the normal early state, not an
        error, so each degrades to the model's own answer rather than raising.
        """
        has_fence = status.fence.present if status is not None else model.has_fence
        detected = cls._detect_fence_pgm(pgms or {})
        doubling = zone_options.zone_doubling if zone_options is not None else None
        return cls(
            model=model,
            partitions=model.partitions,
            zones=cls._doubling_cap(model, doubling),
            pgms=model.pgms,
            has_fence=has_fence,
            detected_fence_pgm=detected,
            zone_doubling=doubling,
        )

    @staticmethod
    def _detect_fence_pgm(pgms: Mapping[int, PgmRecord]) -> int | None:
        """Return the lowest-numbered PGM whose function drives the fence, or `None`.

        Lowest-numbered so the answer is stable if two outputs are mis-programmed to the same
        function; a real installation has one, and the fence's own commands remain the way to
        operate it either way.
        """
        return next(
            (number for number, record in sorted(pgms.items()) if record.drives_fence),
            None,
        )

    @staticmethod
    def _doubling_cap(model: ModelSpec, doubling: bool | None) -> int:
        """Return the real zone count, halving it when zone doubling is known to be **off**.

        *Habilita zonas duplas* (reference screen 3) lets an Active 32 Duo reach 32 zones from 16
        terminals; with it off the panel has 16. Its address was decoded on 2026-08-09 —
        `GLOBAL_ZONE_OPTIONS_ADDRESS` bit `ZONE_DOUBLING_MASK` — so this can finally be answered
        from the panel instead of assumed.

        Two deliberate conservatisms. `None` (programming never read) keeps the ceiling rather than
        halving on a guess, because hiding a real detector is the worse error. And a model whose
        zone count is odd is left alone: halving is only meaningful where the ceiling is twice a
        terminal count, and a panel that does not work that way would lose a zone to integer
        division.
        """
        if doubling is False and model.zones % 2 == 0:
            return model.zones // 2
        return model.zones

    def effective_fence_pgm(self, configured: int) -> int | None:
        """Return the PGM to treat as the fence's power: the setting if given, else what was found.

        **The user's setting wins on purpose.** They may know something the programming does not — a
        relay wired downstream of an output whose function reads as something else — so a configured
        value is never silently overridden by detection. `0` means "none / I don't know", which is
        when detection gets to speak. See ADR-0011.
        """
        if configured:
            return configured
        return self.detected_fence_pgm

    def drives_fence(self, number: int, configured: int) -> bool:
        """Whether PGM *number* is the one that switches the energiser, honouring the override."""
        return self.effective_fence_pgm(configured) == number

    def fence_pgm_conflict(self, configured: int) -> int | None:
        """Return the detected PGM when it **disagrees** with a non-zero user setting, else `None`.

        A disagreement is not resolved silently: the setting is honoured (see `effective_fence_pgm`)
        and the detected value is surfaced as a repair issue instead, because one of the two is
        wrong and only the user can say which.
        """
        if (
            configured
            and self.detected_fence_pgm is not None
            and configured != self.detected_fence_pgm
        ):
            return self.detected_fence_pgm
        return None
