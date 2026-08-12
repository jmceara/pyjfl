"""The panel's own backup image, as a whole-space regression fixture.

Author: Jonis Maurin Ceará <jmceara AT gmail.com>
Based on the code developed by Carlos Jose Fernandes,
available at https://github.com/fernac03/JFL_ACTIVE

ActiveNet's *Backup* command writes a **flat image of the entire programming address space** —
addresses `0x0000` to `0x1DFF`, 7680 bytes, no header and no framing, despite the `.xml`
extension its dialog suggests. `docs/captures/raw/panel-programming-backup-2026-08-09.bin` is
one such image, taken from the author's Active 32 Duo on 2026-08-09, before the differential
capture began.

It is worth a test module of its own for a reason no captured frame can match: **it is the whole
space at one instant, in the panel's own words.** Every parser in `protocol/programming.py` can be
run against it end to end, at its real address, with no framing in the way — so an address-map
mistake shows up here as a wrong name or an impossible date rather than as silence.

The labelled decode these assertions come from is `docs/captures/2026-08-09-differential.md`.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Final

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from pyjfl.protocol import (
    GlobalZoneOptions,
    UserPermissions,
    ZoneSensitivity,
    parse_auto_arm_time,
    parse_global_zone_options,
    parse_holidays,
    parse_partitions,
    parse_pgms,
    parse_timers,
    parse_users,
    parse_wireless,
    parse_zones,
)
from pyjfl.protocol.programming import (
    GLOBAL_ZONE_OPTIONS_ADDRESS,
    PARTITION_NAMES_BASE,
    TIMERS_BASE,
    USER_BASE,
)

IMAGE_PATH: Final = (
    Path(__file__).parent.parent
    / "docs"
    / "captures"
    / "raw"
    / "panel-programming-backup-2026-08-09.bin"
)

IMAGE_SIZE: Final = 0x1E00
"""7680 bytes. The image is the address space, so an offset *is* an address — which is what makes
every assertion below readable as "at address X the panel holds Y"."""


@pytest.fixture(scope="module")
def image() -> bytes:
    """The backup image, or a skip when the raw capture is not present.

    Skipped rather than failed on purpose: `docs/captures/raw/` is non-redacted and must be strippe
    from any public mirror (ADR-0014), so a checkout without it is a supported state, not a broken
    one.
    """
    if not IMAGE_PATH.exists():
        pytest.skip("raw capture not present in this checkout — see docs/captures/raw/README.md")
    return IMAGE_PATH.read_bytes()


def test_the_image_is_the_whole_address_space(image: bytes) -> None:
    """The file is exactly the programming space, with no header of its own."""
    assert len(image) == IMAGE_SIZE


def test_partition_names_land_at_their_documented_address(image: bytes) -> None:
    """The address map is right if the names come out whole rather than shifted by one."""
    records = parse_partitions(image, 0)
    assert [record.name for record in records] == ["Interno", "Externo", "PART. C", "PART. D"]


def test_the_partition_count_is_the_regions_leading_byte(image: bytes) -> None:
    """`0x006F` holds the count as a direct value — one partition on this panel."""
    assert image[PARTITION_NAMES_BASE] == 1


class TestZoneAttributes:
    """The zone attribute bits decoded by the 2026-08-09 labelled differential."""

    def test_every_zone_is_in_partition_a(self, image: bytes) -> None:
        """The panel had one partition, so every zone's bitmap must read exactly `(1,)`.

        This is the assertion that would have caught the old reading of attribute byte 4. Any
        mis-decode — an off-by-one into the padding, the wrong nibble — produces empty tuples or
        partitions that do not exist on a single-partition panel.
        """
        zones = parse_zones(image, 0)
        assert len(zones) == 32
        assert {zone.partitions for zone in zones} == {(1,)}

    def test_stay_is_set_on_the_interior_detectors(self, image: bytes) -> None:
        """Zones 10 and 13 are the panel's two `I …` (interior) zones, and both carry Stay.

        Independent corroboration of the differential: the bit was identified by setting *Stay* on
        zone 16 and watching attribute byte 4 go `0x01` → `0x11`, and the zones that already read
        `0x11` turn out to be exactly the ones a Stay flag is for.
        """
        zones = {zone.number: zone for zone in parse_zones(image, 0)}
        assert [n for n, zone in zones.items() if zone.stay] == [10, 13]
        assert zones[10].name == "I Cozinha"
        assert zones[13].name == "I Sala"

    def test_auto_bypass_is_set_on_the_two_zones_that_carry_it(self, image: bytes) -> None:
        """Zones 20 and 21 read `0x81` — `AUTO_BYPASS_MASK` plus partition A."""
        zones = {zone.number: zone for zone in parse_zones(image, 0)}
        assert [n for n, zone in zones.items() if zone.auto_bypass] == [20, 21]

    def test_chime_is_off_everywhere_in_the_pristine_image(self, image: bytes) -> None:
        """The Chime set on zone 21 during the capture was undone by the restore this image is of.

        Worth asserting rather than assuming: it is what makes this image a *baseline*. If Chime
        read set here, the image would be a post-edit snapshot and every other assertion in this
        module would be measuring the wrong instant.
        """
        assert not any(zone.chime for zone in parse_zones(image, 0))

    def test_every_enabled_zone_allows_bypass(self, image: bytes) -> None:
        """`P-INIB`'s free cross-check, read from the other structure.

        The status frame grants bypass to exactly the enabled zones on this panel, and attribute
        byte 3 bit 0 says the same thing from the programming — two unrelated structures agreeing.
        """
        zones = [zone for zone in parse_zones(image, 0) if zone.enabled]
        assert zones
        assert all(zone.allows_bypass for zone in zones)


class TestGlobalOptions:
    """The panel-wide options, including the flag Sprint 8.1 was blocked on."""

    def test_zone_doubling_is_enabled(self, image: bytes) -> None:
        """The captured panel has 32 zones from 16 terminals, so doubling must read on.

        The cross-check that makes `ZONE_DOUBLING_MASK` more than a guess: the bit was identified
        as the only *cleared* one in a write where the other two options were switched on, and the
        value it holds on this panel agrees with the zone count the panel actually reports.
        """
        options = parse_global_zone_options(image, 0)
        assert options == GlobalZoneOptions(raw=image[GLOBAL_ZONE_OPTIONS_ADDRESS])
        assert options is not None
        assert options.zone_doubling is True

    def test_the_option_byte_is_out_of_range_of_a_short_read(self, image: bytes) -> None:
        """A read that does not reach the byte returns `None`, never a byte from somewhere else."""
        assert parse_global_zone_options(image[:0x0500], 0) is None


class TestTimers:
    """The ten timers, in the units the panel really stores them in."""

    def test_the_pristine_timers_match_the_programmer_app(self, image: bytes) -> None:
        """Entry/exit in seconds, open-door and mains-loss in minutes, autotest in hours."""
        timers = parse_timers(image, 0)
        assert timers is not None
        assert timers.entry_1_seconds == 60
        assert timers.exit_1_seconds == 60
        assert timers.exit_2_seconds == 120
        assert timers.smart_zone_seconds == 60
        assert timers.open_door_minutes == 5
        assert timers.ac_loss_minutes == 1
        assert timers.autotest_interval == 24
        assert timers.autotest_in_minutes is False

    def test_a_disabled_timer_reads_none_rather_than_255(self, image: bytes) -> None:
        """Entry 2 is `0xFF` on this panel, which is *off* and emphatically not 255 seconds."""
        timers = parse_timers(image, 0)
        assert timers is not None
        assert timers.entry_2_seconds is None

    def test_the_timer_block_is_where_the_map_says(self, image: bytes) -> None:
        """Parsed from its own address, the result is identical — the map, not luck."""
        assert parse_timers(image[TIMERS_BASE : TIMERS_BASE + 0x34], TIMERS_BASE) == parse_timers(
            image, 0
        )

    def test_the_auto_arm_time_is_unset_in_the_pristine_image(self, image: bytes) -> None:
        """`00 00` is "no auto-arm", not midnight, which is why the parser rejects it."""
        assert parse_auto_arm_time(image, 0) is None


class TestRecordsAcrossTheWholeSpace:
    """Every other parser, run at its real address against the real image."""

    def test_the_pgm_functions_are_the_ones_the_programmer_app_showed(self, image: bytes) -> None:
        """PGM 1 = 18 (the energiser), 2 = 6, 3 = 0, 4 = 11 — and only PGM 1 drives the fence."""
        pgms = {pgm.number: pgm for pgm in parse_pgms(image, 0)}
        assert [pgms[n].function for n in (1, 2, 3, 4)] == [18, 6, 0, 11]
        assert [n for n, pgm in pgms.items() if pgm.drives_fence] == [1]

    def test_the_holidays_are_brazilian_public_holidays(self, image: bytes) -> None:
        """Eight recognisable dates decode from BCD — the sanity check on the whole block."""
        holidays = parse_holidays(image, 0)
        assert [holiday.formatted for holiday in holidays[:8]] == [
            "01/01",
            "21/04",
            "01/05",
            "07/09",
            "12/10",
            "02/11",
            "15/11",
            "25/12",
        ]

    def test_the_wireless_table_matches_the_captured_inventory(self, image: bytes) -> None:
        """Nine enrolled devices, and each serial sits on the zone the `0x59` inventory reported."""
        present = [record for record in parse_wireless(image, 0) if record.present]
        assert len(present) == 9
        assert {record.serial: record.zone for record in present} == {
            2986716970: 14,
            2970003720: 18,
            3019905069: 11,
            3120601985: 20,
            2970003705: 9,
            3036975733: 21,
            2970003665: 16,
            2953220096: 10,
            2970003684: 17,
        }

    def test_no_access_code_survives_the_user_parser(self, image: bytes) -> None:
        """The image holds every code in clear; `parse_users` must carry none of them out.

        This is the strongest possible form of that test, because the input genuinely contains the
        codes — a fixture with them already stripped could not tell a working contract from a
        vacuous one. AGENTS.md §4.
        """
        users = parse_users(image, 0)
        named = [user for user in users if user.name and not user.name.startswith("USUA.")]
        assert [user.name for user in named[:3]] == ["Jonis", "Priscila", "Paulo"]
        assert any(user.has_code for user in users)
        for user in users:
            assert "code" not in set(user.__slots__)
            base = USER_BASE + (user.number - 1) * 16
            code = image[base + 9 : base + 12]
            if code != b"\xff\xff\xff":
                assert code not in user.attributes


class TestSessionTwoDecode:
    """Fields closed by the 2026-08-10 labelled capture, checked against the pristine image.

    The capture itself proved each bit by moving it; these assertions prove the *parsers* read the
    same bits back out of a real panel image, which is the half a differential cannot check.
    """

    def test_sensitivity_reads_the_three_programmed_levels(self, image: bytes) -> None:
        """Every enabled zone has a level, and the two wireless infrared zones sit at maximum."""
        zones = {zone.number: zone for zone in parse_zones(image, 0) if zone.enabled}
        assert all(zone.sensitivity is not None for zone in zones.values())
        assert [n for n, z in zones.items() if z.sensitivity is ZoneSensitivity.MAXIMUM] == [10, 21]
        assert zones[17].sensitivity is ZoneSensitivity.MEDIUM, "zone 17 displays Média in the app"

    def test_silent_is_set_on_exactly_the_zone_that_carries_it(self, image: bytes) -> None:
        """Zone 15 reads `0x41` in the pristine image — partition A plus *Silenciosa*.

        Independent corroboration of the capture, which found the bit by ticking it on zone 26: one
        real zone already had it. The other two attributes decoded in the same session appear
        nowhere here, which is what makes the capture positives meaningful — the bits are not
        simply set everywhere.
        """
        zones = parse_zones(image, 0)
        assert [z.number for z in zones if z.silent] == [15]
        assert not any(z.siren_pulsed for z in zones)
        assert not any(z.open_door for z in zones)

    def test_the_global_option_byte_is_fully_mapped(self, image: bytes) -> None:
        """`0x05` on this panel: end-of-line resistors and zone doubling on, the other two off."""
        options = parse_global_zone_options(image, 0)
        assert options is not None
        assert options.end_of_line_resistor is True
        assert options.zone_doubling is True
        assert options.siren_on_short is False
        assert options.wired_tamper is False

    def test_a_household_user_decodes_the_permissions_the_app_shows(self, image: bytes) -> None:
        """User record 3 is `Paulo`, whose screen shows exactly this set.

        This is the assertion that would catch the layout being read as one contiguous bitmap: the
        permissions live in three non-adjacent bytes, and arming is per partition while disarming is
        a single flag.
        """
        users = {user.number: user for user in parse_users(image, 0)}
        paulo = users[3].permissions
        assert users[3].name == "Paulo"
        assert paulo.arm_partitions == (1, 2, 3, 4)
        assert paulo.disarm is True
        assert paulo.bypass_zones is True
        assert paulo.operate_fence is True
        assert paulo.forced_arm is False
        assert paulo.pgms == ()
        assert paulo.remote_access is False
        assert paulo.patrol is False
        assert paulo.schedule_tasks is False

    def test_an_unused_slot_has_only_the_default_permissions(self, image: bytes) -> None:
        """An untouched user may arm every partition and disarm, and nothing else."""
        users = {user.number: user for user in parse_users(image, 0)}
        spare = users[30].permissions
        assert spare.arm_partitions == (1, 2, 3, 4)
        assert spare.disarm is True
        assert spare.operate_fence is False
        assert spare.schedule_tasks is False

    def test_no_permission_decode_can_leak_a_code(self, image: bytes) -> None:
        """`UserPermissions` is built from the attribute bytes only — the code is never in scope."""
        users = parse_users(image, 0)
        assert all(isinstance(user.permissions, UserPermissions) for user in users)
        assert "code" not in UserPermissions.__annotations__
