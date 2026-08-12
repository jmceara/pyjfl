"""Capability detection: the merge of the model table, the status frame and the programming.

Author: Jonis Maurin Ceará <jmceara AT gmail.com>
Based on the code developed by Carlos Jose Fernandes,
available at https://github.com/fernac03/JFL_ACTIVE

Sprint 8, tasks 8.1 and 8.2. The author's requirement is that the integration **detect** what a
panel has rather than assume an Active 32 Duo — a panel with one partition, no fence and no PGMs
must resolve to exactly those. And the headline of 8.2: a programming read now names the PGM that
drives the electric fence on its own, which is what Sprints 4 and 6 could not do.

Pure and offline: `JflCapabilities` takes already-decoded records and returns a description, so
each model byte is exercised here without a socket or a panel.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from pyjfl.protocol import (
    FenceState,
    GlobalZoneOptions,
    JflCapabilities,
    PanelStatus,
    PgmRecord,
    spec_for,
)


def _pgm(number: int, function: int) -> PgmRecord:
    """A PGM record whose attribute byte 5 carries *function*, the rest padding."""
    return PgmRecord(number, f"PGM {number}", bytes([0, 0, 0, 0, 0xCA, function, 0xFF]))


def _status(fence: int) -> PanelStatus:
    """A minimal status frame carrying just the `ELET` byte this test cares about."""
    return PanelStatus(
        programming_checksum=b"\x00\x00", battery_volts=13.0, pgm=0, fence=FenceState(fence)
    )


# --- 8.1: the ceiling from the model, before anything else has spoken ---------------------------


def test_a_full_house_panel_reports_everything() -> None:
    """The Active 32 Duo: four partitions, thirty-two zones, four PGMs and a fence."""
    caps = JflCapabilities.detect(spec_for(0xA0))
    assert (caps.partitions, caps.zones, caps.pgms) == (4, 32, 4)
    assert caps.has_fence is True


def test_a_panel_with_no_fence_and_no_pgms() -> None:
    """The Active 8 Ultra (`0xA2`): two partitions, no PGM outputs, no energiser.

    A panel like this must never grow a fence entity or a PGM switch — the count being zero is what
    stops the switch platform creating any, and `has_fence` being false stops the fence one.
    """
    caps = JflCapabilities.detect(spec_for(0xA2))
    assert caps.pgms == 0, "no PGM switches can be created"
    assert caps.has_fence is False, "and no fence entity"
    assert caps.partitions == 2


def test_a_module_has_no_partitions() -> None:
    """The M-300+ (`0x4B`) is a reporting module: PGMs and inputs, but nothing to arm."""
    caps = JflCapabilities.detect(spec_for(0x4B))
    assert caps.partitions == 0, "so no alarm_control_panel is ever created"
    assert caps.pgms == 4
    assert caps.has_fence is False


def test_the_status_frame_overrides_the_model_on_the_fence() -> None:
    """`ELET != 0x00` is the real test for a fence, not the model's capability.

    An Active 32 Duo *can* have a fence, but one whose `ELET` reads `0x00` has none configured and
    must get no fence entity. Source 2 beats source 1.
    """
    has_a_model_fence = spec_for(0xA0)
    assert JflCapabilities.detect(has_a_model_fence, _status(0x00)).has_fence is False
    assert JflCapabilities.detect(has_a_model_fence, _status(0x01)).has_fence is True


def test_an_unknown_model_degrades_permissively() -> None:
    """An unlisted byte must not raise; it assumes the maximum so entities still appear."""
    caps = JflCapabilities.detect(spec_for(0xEE))
    assert caps.partitions > 0
    assert caps.pgms > 0


# --- 8.2: detecting the PGM that drives the electric fence --------------------------------------


def test_the_fence_pgm_is_detected_from_the_programming() -> None:
    """Function 18 *is* the energiser's power. This is what Sprints 4 and 6 could not answer."""
    pgms = {1: _pgm(1, 18), 2: _pgm(2, 6), 3: _pgm(3, 0), 4: _pgm(4, 11)}
    caps = JflCapabilities.detect(spec_for(0xA0), _status(0x01), pgms)
    assert caps.detected_fence_pgm == 1


def test_the_silent_energiser_is_detected_too() -> None:
    """Function 25 is the Active 20's silent energiser. Checking only 18 would miss every one."""
    caps = JflCapabilities.detect(spec_for(0xA1), _status(0x01), {2: _pgm(2, 25)})
    assert caps.detected_fence_pgm == 2


def test_no_fence_pgm_when_none_carries_the_function() -> None:
    """A panel whose PGMs are gate, light and siren detects no energiser output."""
    pgms = {1: _pgm(1, 12), 2: _pgm(2, 1), 3: _pgm(3, 11)}
    assert JflCapabilities.detect(spec_for(0xA0), _status(0x01), pgms).detected_fence_pgm is None


def test_nothing_is_detected_before_a_programming_read() -> None:
    """The status frame carries PGM states but never functions — detection needs the programming."""
    assert JflCapabilities.detect(spec_for(0xA0), _status(0x01)).detected_fence_pgm is None


def test_the_lowest_numbered_output_wins_if_two_are_misprogrammed() -> None:
    """A real installation has one; a stable answer beats an arbitrary one on a clash."""
    pgms = {3: _pgm(3, 18), 1: _pgm(1, 18)}
    assert JflCapabilities.detect(spec_for(0xA0), _status(0x01), pgms).detected_fence_pgm == 1


# --- 8.2: the user's setting is an override, never overridden -----------------------------------


def test_the_user_setting_wins_over_detection() -> None:
    """A configured value is honoured even against the programming: the user may know more."""
    caps = JflCapabilities.detect(spec_for(0xA0), _status(0x01), {1: _pgm(1, 18)})
    assert caps.effective_fence_pgm(configured=3) == 3, "the setting, not the detected 1"
    assert caps.effective_fence_pgm(configured=0) == 1, "0 means 'none set', so detection speaks"


def test_a_disagreement_is_reported_not_resolved() -> None:
    """When setting and programming disagree, the setting stands and the clash is surfaced."""
    caps = JflCapabilities.detect(spec_for(0xA0), _status(0x01), {1: _pgm(1, 18)})
    assert caps.fence_pgm_conflict(configured=3) == 1, "the detected value, for the repair issue"
    assert caps.fence_pgm_conflict(configured=1) is None, "agreement is not a conflict"
    assert caps.fence_pgm_conflict(configured=0) is None, "nothing set is not a conflict"


def test_drives_fence_honours_the_override() -> None:
    """The per-PGM question the switch asks: is *this* output the fence's, given the setting."""
    caps = JflCapabilities.detect(spec_for(0xA0), _status(0x01), {1: _pgm(1, 18)})
    # Nothing configured: the detected output drives the fence.
    assert caps.drives_fence(1, configured=0) is True
    assert caps.drives_fence(2, configured=0) is False
    # Configured to 3: the setting wins, so 3 drives it and the detected 1 does not.
    assert caps.drives_fence(3, configured=3) is True
    assert caps.drives_fence(1, configured=3) is False


class TestZoneDoubling:
    """The zone count follows *Habilita zonas duplas* once the programming has been read.

    Sprint 8.1 shipped with this deliberately unanswered — the flag's address was unknown, and
    halving a zone count on a guess deletes real detectors. The 2026-08-09 labelled differential
    located it (`GLOBAL_ZONE_OPTIONS_ADDRESS` bit `ZONE_DOUBLING_MASK`), so it can now be detected
    rather than assumed, which is the standing requirement for this whole sprint.
    """

    def test_an_unread_panel_keeps_the_model_ceiling(self) -> None:
        """`None` means "not read yet", and the ceiling is the safe answer to an unknown."""
        caps = JflCapabilities.detect(spec_for(0xA0), _status(0x01))
        assert caps.zone_doubling is None
        assert caps.zones == 32

    def test_doubling_on_keeps_the_full_count(self) -> None:
        """32 zones from 16 terminals — the captured panel's own configuration."""
        caps = JflCapabilities.detect(
            spec_for(0xA0), _status(0x01), zone_options=GlobalZoneOptions(raw=0x05)
        )
        assert caps.zone_doubling is True
        assert caps.zones == 32

    def test_doubling_off_halves_the_count(self) -> None:
        """With doubling off an Active 32 Duo is a sixteen-zone panel, and must show sixteen."""
        caps = JflCapabilities.detect(
            spec_for(0xA0), _status(0x01), zone_options=GlobalZoneOptions(raw=0x01)
        )
        assert caps.zone_doubling is False
        assert caps.zones == 16

    def test_an_odd_zone_ceiling_is_never_halved(self) -> None:
        """The Active 100 Bus has 99 zones, which is not a doubled terminal count.

        Halving it would invent a 49-zone panel and silently drop fifty real zones, so the rule is
        deliberately narrow: only an even ceiling, which is the only shape doubling can produce.
        """
        caps = JflCapabilities.detect(spec_for(0xA4), zone_options=GlobalZoneOptions(raw=0x00))
        assert caps.zones == 99
