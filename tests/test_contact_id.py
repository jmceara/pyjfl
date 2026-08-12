"""The Contact ID table.

Author: Jonis Maurin Ceará <jmceara AT gmail.com>
Based on the code developed by Carlos Jose Fernandes,
available at https://github.com/fernac03/JFL_ACTIVE

Sprint 1 task 1.5. The table was recovered from a PDF whose columns `pdftotext` misaligns, so the
tests that matter are the ones checking it against independent sources: the old integration's
84-entry table, and the frames the panel actually sent on 2026-08-08.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from pyjfl.protocol.contact_id import (
    CODES,
    UNKNOWN_CODE,
    classify,
    is_fence,
    lookup,
    subject_of,
)
from pyjfl.protocol.decode import decode
from pyjfl.protocol.frames import Frame
from pyjfl.protocol.models import EventKind, EventSubject, PanelEvent

OLD_TABLE = Path(__file__).parent / "data" / "legacy_contact_id.yaml"
"""The original integration's event table, kept as reference data. See `tests/data/README.md`."""


# --- the acceptance criterion --------------------------------------------------------------------


def test_1130_is_a_zone_alarm() -> None:
    """Sprint 1 task 1.5 acceptance, first half."""
    entry = lookup("1130")
    assert entry.kind is EventKind.ALARM
    assert entry.subject is EventSubject.ZONE


def test_3401_with_partition_99_is_a_fence_arm() -> None:
    """Sprint 1 task 1.5 acceptance, second half.

    The fence has no codes of its own — it arms with the ordinary code and partition `99`. A code
    alone can never identify it, which is why the partition is a separate check.
    """
    assert classify("3401") is EventKind.ARM
    assert is_fence("99")
    assert not is_fence("01")


# --- checked against the old table ---------------------------------------------------------------


def _old_codes() -> set[str]:
    text = OLD_TABLE.read_text(encoding="utf-8")
    return {match.group(1) for match in re.finditer(r"^\s+(\d{4}):", text, re.M)}


def test_no_code_from_the_old_table_was_lost() -> None:
    """The old `contact_id.yaml` has 84 correct entries and every one must survive.

    docs/protocol/discrepancies.md names it as the source to trust — unlike `Develop-2.0`'s map,
    which invents codes `1101`-`1109`.
    """
    missing = _old_codes() - set(CODES)
    assert not missing, f"lost codes from the old table: {sorted(missing)}"


def test_the_missing_codes_were_added() -> None:
    """Sprint 1 listed seven. Recovering the manual's table turned up an eighth, `1346`."""
    assert {"1123", "1139", "1305", "1312", "1346", "1412", "1417", "1419"} <= set(CODES)


def test_the_invented_develop_2_codes_are_absent() -> None:
    """`1101`-`1109` do not exist in JFL's table. See docs/protocol/discrepancies.md."""
    assert not [code for code in CODES if code.startswith("110") and code != "1100"]


# --- checked against the hardware capture ---------------------------------------------------------


def test_1123_is_the_audible_panic() -> None:
    """One of two rows that independently confirm the table's column alignment.

    The capture recorded that *Pânico Audível* sounds the siren while the other three panics are
    silent, and `1123` is the code it emitted.
    """
    assert lookup("1123").description == "Audible panic"
    assert lookup("1123").kind is EventKind.PANIC


def test_3407_is_a_remote_arm() -> None:
    """The other confirming row: this is what the fence emitted when armed from ActiveNet."""
    assert lookup("3407").kind is EventKind.ARM
    assert lookup("3407").restore == "1407"


def test_the_captured_fence_event_classifies_correctly(
    load_frame: Callable[[str], bytes],
) -> None:
    """End to end, from captured bytes to a routing decision."""
    event = decode(Frame(load_frame("event-fence-1.hex")))
    assert isinstance(event, PanelEvent)
    assert classify(event.code) is EventKind.ARM
    assert is_fence(event.partition)
    assert subject_of(event.code) is EventSubject.USER
    assert event.subject == "099", "099 is the monitoring connection, 000 the mobile app"

    # With the partition, the same code says which device it was. Without it, a panel-wide event
    # entity reads "Armed" for a fence being switched on — which is what the lab showed on
    # 2026-08-08 and what the fence event kinds exist to fix.
    assert classify(event.code, event.partition) is EventKind.FENCE_ARM


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("3401", EventKind.FENCE_ARM),
        ("3407", EventKind.FENCE_ARM),
        ("1401", EventKind.FENCE_DISARM),
        ("1407", EventKind.FENCE_DISARM),
        ("1130", EventKind.FENCE_ALARM),
        ("3130", EventKind.FENCE_ALARM_RESTORE),
    ],
)
def test_partition_99_relabels_the_four_codes_the_fence_shares(
    code: str, expected: EventKind
) -> None:
    """The fence has no codes of its own — only partition 99 tells these apart."""
    assert classify(code, "99") is expected
    assert classify(code, "01") is not expected


def test_partition_99_leaves_every_other_code_alone() -> None:
    """A trouble on partition 99 means what a trouble means anywhere. Do not invent a fence name."""
    assert classify("1301", "99") is EventKind.TROUBLE
    assert classify("1602", "99") is EventKind.TEST
    assert classify("1120", "99") is EventKind.PANIC
    assert classify("9999", "99") is EventKind.UNKNOWN


def test_the_captured_zone_alarm_classifies_correctly(
    load_frame: Callable[[str], bytes],
) -> None:
    """The real alarm that went off during the capture."""
    event = decode(Frame(load_frame("event-zone-alarm-1130.hex")))
    assert isinstance(event, PanelEvent)
    assert classify(event.code) is EventKind.ALARM
    assert not is_fence(event.partition)
    assert subject_of(event.code) is EventSubject.ZONE


def test_the_captured_autobypass_event(load_frame: Callable[[str], bytes]) -> None:
    """`1570` is how the panel announced auto-bypassing zone 9 — the zone nibble did not show it."""
    event = decode(Frame(load_frame("event-autobypass-1570.hex")))
    assert isinstance(event, PanelEvent)
    assert classify(event.code) is EventKind.BYPASS
    assert subject_of(event.code) is EventSubject.ZONE


# --- structure ------------------------------------------------------------------------------------


def test_an_unknown_code_never_raises() -> None:
    """It must still be acknowledged, or the panel retransmits it forever."""
    assert lookup("9999") is UNKNOWN_CODE
    assert lookup("") is UNKNOWN_CODE
    assert classify("9999") is EventKind.UNKNOWN


def test_every_restore_reference_resolves() -> None:
    """A dangling restore code would silently break pairing in the UI."""
    dangling = {
        entry.code: entry.restore
        for entry in CODES.values()
        if entry.restore and entry.restore not in CODES
    }
    assert not dangling


def test_every_entry_knows_what_its_subject_field_means() -> None:
    """Getting this wrong reports zone 10 as user 10."""
    for entry in CODES.values():
        assert isinstance(entry.subject, EventSubject)


def test_zone_events_carry_a_zone_and_arm_events_carry_a_user() -> None:
    """A spot check on the split that matters most for routing."""
    assert subject_of("1130") is EventSubject.ZONE
    assert subject_of("1570") is EventSubject.ZONE
    assert subject_of("3407") is EventSubject.USER
    assert subject_of("1401") is EventSubject.USER
    assert subject_of("1602") is EventSubject.NONE


def test_translation_keys_are_stable_and_unique() -> None:
    """These become keys in `translations/*.json`, so they must not collide."""
    keys = [entry.translation_key for entry in CODES.values()]
    assert len(set(keys)) == len(keys)
    assert lookup("1130").translation_key == "event_1130"


@pytest.mark.parametrize("code", sorted(CODES))
def test_every_entry_has_an_english_description(code: str) -> None:
    """AGENTS.md §1: English is the project language; pt-BR comes from the translation files."""
    entry = CODES[code]
    assert entry.description
    assert entry.description[0].isupper()
    assert not re.search(r"[ãõçáéíóúâêô]", entry.description, re.I)
