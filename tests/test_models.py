"""Value objects, the model table and the bit positions they hide.

Author: Jonis Maurin Ceará <jmceara AT gmail.com>
Based on the code developed by Carlos Jose Fernandes,
available at https://github.com/fernac03/JFL_ACTIVE

Sprint 1 task 1.2. Most of these assert a single bit position, which is the point: every one of them
is a place the old integration or the specification gets it wrong, and none would be caught by a
test written casually.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from pyjfl.protocol.models import (
    MODELS,
    UNKNOWN_MODEL,
    AuthFunc,
    Cmd,
    CommandAck,
    FencePermissions,
    FenceState,
    PartitionPermissions,
    PartitionState,
    ProblemFlag,
    ZoneStatus,
    spec_for,
)

# --- the fence ---------------------------------------------------------------------------------


def test_fence_armed_and_triggered() -> None:
    """Sprint 1 task 1.2 acceptance criterion, verbatim."""
    assert FenceState(0x82).armed
    assert FenceState(0x82).triggered


@pytest.mark.parametrize(
    ("raw", "present", "armed", "triggered"),
    [
        (0x00, False, False, False),  # not programmed
        (0x01, True, False, False),  # disarmed
        (0x02, True, True, False),  # armed
        (0x81, True, False, True),  # disarmed, in alarm
        (0x82, True, True, True),  # armed, in alarm
        (0x04, True, False, False),  # disarmed, not ready (0x93 reply only)
        (0x84, True, False, True),  # disarmed, ready, in alarm (0x93 reply only)
    ],
)
def test_fence_state_table(raw: int, present: bool, armed: bool, triggered: bool) -> None:
    """Every documented value, including the two only the 0x93 reply produces."""
    state = FenceState(raw)
    assert (state.present, state.armed, state.triggered) == (present, armed, triggered)


def test_absent_fence_is_not_the_same_as_disarmed() -> None:
    """`0x00` means no fence is configured, and no entity should be created.

    The old integration collapses this byte to a boolean and treats `0x00` as "no fence", which is
    why its fence sensor is meaningless.
    """
    assert not FenceState(0x00).present
    assert not FenceState(0x00).armed
    assert not FenceState(0x00).disarmed
    assert FenceState(0x01).present


def test_fence_not_ready_is_still_disarmed() -> None:
    assert FenceState(0x04).disarmed
    assert not FenceState(0x04).ready
    assert FenceState(0x01).ready


def test_fence_arm_permission_is_bit_3_not_bit_1() -> None:
    """docs/protocol/fence.md: `P-ELET` mirrors the ARM_AWAY position in `P-PART`.

    `0x09` is what the real panel reported: bit 0 disarm + bit 3 arm, both permitted.
    """
    permissions = FencePermissions(0x09)
    assert permissions.may_disarm
    assert permissions.may_arm
    assert not FencePermissions(0x03).may_arm, "bit 1 must not be read as the arm permission"


# --- partitions --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "programmed", "armed", "stay", "triggered"),
    [
        (0x00, False, False, False, False),
        (0x01, True, False, False, False),
        (0x02, True, True, False, False),
        (0x03, True, True, True, False),
        (0x81, True, False, False, True),
        (0x82, True, True, False, True),
        (0x83, True, True, True, True),
    ],
)
def test_partition_state_table(
    raw: int, programmed: bool, armed: bool, stay: bool, triggered: bool
) -> None:
    state = PartitionState(raw)
    assert state.programmed is programmed
    assert state.armed is armed
    assert state.armed_stay is stay
    assert state.triggered is triggered


def test_partition_permissions_are_state_dependent_not_capabilities() -> None:
    """The real panel read `0x0B` disarmed and `0x1F` armed for the same partition.

    Recorded as a test so nobody later derives `supported_features` from it — the buttons would
    appear and disappear on their own. See docs/protocol/commands.md.
    """
    disarmed = PartitionPermissions(0x0B)
    armed = PartitionPermissions(0x1F)
    assert disarmed.may_arm and disarmed.may_arm_away
    assert not disarmed.ready
    assert armed.ready
    assert disarmed.raw != armed.raw


# --- zones -------------------------------------------------------------------------------------


def test_zone_status_values_match_the_current_protocol_not_the_legacy_one() -> None:
    """4 is a short circuit and 5 a tamper. The legacy `0xB3` protocol numbers them the reverse."""
    assert ZoneStatus.SHORT_CIRCUIT == 0x4
    assert ZoneStatus.TAMPER == 0x5


def test_a_triggered_zone_still_counts_as_open() -> None:
    assert ZoneStatus.TRIGGERED.is_open
    assert ZoneStatus.OPEN.is_open
    assert not ZoneStatus.CLOSED.is_open


def test_fault_states_are_distinguished_from_openings() -> None:
    """These become a separate `problem` binary_sensor — see docs/development/entity-map.md.

    Conflating them would make "open" mean five different things.
    """
    assert ZoneStatus.NOT_COMMUNICATING.is_fault
    assert ZoneStatus.LOW_BATTERY.is_fault
    assert not ZoneStatus.OPEN.is_fault
    assert not ZoneStatus.BYPASSED.is_fault


def test_disabled_zone_does_not_exist() -> None:
    assert not ZoneStatus.DISABLED.exists
    assert ZoneStatus.CLOSED.exists


# --- the model table ---------------------------------------------------------------------------


def test_all_eleven_models_are_present() -> None:
    """AGENTS.md §0 requires parity with the old integration from Sprint 1 onwards."""
    assert len(MODELS) == 11
    assert set(MODELS) == {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0x4B, 0x5D}


def test_only_the_active_32_duo_claims_hardware_validation() -> None:
    """AGENTS.md §0: never claim a model is verified when it is not."""
    verified = [byte for byte, spec in MODELS.items() if spec.verified_on_hardware]
    assert verified == [0xA0]


@pytest.mark.parametrize("model_byte", [0xFE, 0x00, 0xFF, 0x99])
def test_an_unknown_model_never_raises_and_degrades_permissively(model_byte: int) -> None:
    """The old integration raises `UnboundLocalError` here and kills its listener thread."""
    spec = spec_for(model_byte)
    assert spec is UNKNOWN_MODEL
    assert spec.zones == 99
    assert spec.has_fence


def test_models_without_a_fence_are_marked_so() -> None:
    """An Active 8 Ultra has no fence and no PGM; commands return `0xAB`."""
    assert not MODELS[0xA2].has_fence
    assert MODELS[0xA2].pgms == 0
    assert not MODELS[0xA6].has_fence


def test_the_m300_modules_have_no_partitions() -> None:
    assert MODELS[0x4B].is_module
    assert MODELS[0x5D].is_module
    assert not MODELS[0xA0].is_module


# --- command bytes -----------------------------------------------------------------------------


def test_command_bytes_match_the_captured_frames() -> None:
    """Every one of these was observed on the wire on 2026-08-08."""
    assert Cmd.ARM == 0x4E
    assert Cmd.DISARM == 0x4F
    assert Cmd.PGM_ON == 0x50
    assert Cmd.PGM_OFF == 0x51
    assert Cmd.BYPASS == 0x52
    assert Cmd.STATUS == 0x4D


def test_the_wrong_password_reply_is_flagged_as_a_lockout_risk() -> None:
    """AGENTS.md §6: stop after the first `0xA1`. There must be no retry loop near this family."""
    assert CommandAck.WRONG_PASSWORD == 0xA1
    assert CommandAck.BLOCKED == 0xAA
    assert AuthFunc.ARM_DISARM == 0xC1


def test_problem_flags_are_flat_bit_indices() -> None:
    """`byte_index * 8 + bit`, bit 0 first, so a decoder can iterate without a lookup table."""
    assert ProblemFlag.WIRELESS_LOW_BATTERY == 0
    assert ProblemFlag.SMS == 7
    assert ProblemFlag.ETHERNET == 8
    assert ProblemFlag.AC_MAINS == 15
    assert ProblemFlag.SIM_CARD == 31
