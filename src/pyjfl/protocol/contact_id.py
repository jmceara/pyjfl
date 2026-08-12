"""The Contact ID event table.

Author: Jonis Maurin Ceará <jmceara AT gmail.com>
Based on the code developed by Carlos Jose Fernandes,
available at https://github.com/fernac03/JFL_ACTIVE

Source: `docs/protocol/contact-id.md`, recovered from §29 of
`docs/referencia/MANUAL-ACTIVE-8-20-32-Grande.pdf` and cross-checked against the old integration's
`contact_id.yaml` and the 2026-08-08 hardware capture.

Descriptions are in English because that is the project language (AGENTS.md §1). The Portuguese the
user sees comes from `translations/pt-BR.json` via `translation_key`, not from here.

Two facts shape the whole module:

* **The subject field means different things per code** — a zone for `1130`, a user for `3407` — and
  the only way to know which is the code. So each entry records it.
* **A code alone never tells you it is the electric fence.** The fence uses ordinary codes with
  partition `99`. Use `classify()`, which takes the partition too.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from .models import EventKind, EventSubject, ZoneAlert

FENCE_PARTITION_TEXT: Final = "99"
"""The fence reports as partition 99 with otherwise ordinary codes."""


@dataclass(frozen=True, slots=True)
class ContactIdCode:
    """One Contact ID code: what it means, how to route it, and what its field refers to."""

    code: str
    description: str
    kind: EventKind
    subject: EventSubject
    restore: str | None = None
    """The code that cancels this one, where the manual defines one."""

    @property
    def translation_key(self) -> str:
        """Key for `translations/*.json`, e.g. `event_1130`."""
        return f"event_{self.code}"


def _entry(
    code: str,
    description: str,
    kind: EventKind,
    subject: EventSubject = EventSubject.NONE,
    restore: str | None = None,
) -> tuple[str, ContactIdCode]:
    """Build one table row."""
    return code, ContactIdCode(code, description, kind, subject, restore)


_ZONE = EventSubject.ZONE
_USER = EventSubject.USER

CODES: Final[dict[str, ContactIdCode]] = dict(
    [
        # --- alarms -----------------------------------------------------------------------------
        # These four are the panic family. None of them changes a single status byte, which is the
        # reason this integration exposes `event` entities rather than polling for state.
        _entry("1100", "Medical emergency", EventKind.MEDICAL, _USER),
        _entry("1110", "Fire", EventKind.FIRE, _USER),
        _entry("1120", "Panic", EventKind.PANIC, _USER),
        _entry("1121", "Duress", EventKind.PANIC, _USER),
        _entry("1122", "Silent panic", EventKind.PANIC, _USER),
        # Verified on hardware: this is the only panic that sounds the siren.
        _entry("1123", "Audible panic", EventKind.PANIC, _USER),
        # The fence alarm is this code with partition 99 and zone "000". A cut wire stays triggered
        # and never restores; a brief spark alarms and restores at once.
        _entry("1130", "Zone alarm", EventKind.ALARM, _ZONE, "3130"),
        _entry("3130", "Zone alarm restored", EventKind.ALARM_RESTORE, _ZONE),
        _entry("1134", "Open door alarm", EventKind.ALARM, _ZONE, "3134"),
        _entry("3134", "Open door alarm restored", EventKind.ALARM_RESTORE, _ZONE),
        _entry("1137", "Zone tamper alarm", EventKind.TAMPER, _ZONE, "3137"),
        _entry("3137", "Zone tamper alarm restored", EventKind.TROUBLE_RESTORE, _ZONE),
        _entry("1139", "Zone motion inactivity", EventKind.TROUBLE, _ZONE, "3139"),
        _entry("3139", "Zone motion restored", EventKind.TROUBLE_RESTORE, _ZONE),
        # --- panel troubles ---------------------------------------------------------------------
        _entry("1300", "Auxiliary output trouble", EventKind.TROUBLE, restore="3300"),
        _entry("3300", "Auxiliary output restored", EventKind.TROUBLE_RESTORE),
        _entry("1301", "AC power lost", EventKind.TROUBLE, restore="3301"),
        _entry("3301", "AC power restored", EventKind.TROUBLE_RESTORE),
        _entry("1302", "Panel battery trouble", EventKind.TROUBLE, restore="3302"),
        _entry("3302", "Panel battery restored", EventKind.TROUBLE_RESTORE),
        _entry("1305", "System reset", EventKind.SYSTEM),
        _entry("1306", "Programming changed", EventKind.SYSTEM, _USER),
        _entry("1311", "Battery dead", EventKind.TROUBLE),
        _entry("1312", "Bus short circuit", EventKind.TROUBLE, restore="3312"),
        _entry("3312", "Bus short circuit restored", EventKind.TROUBLE_RESTORE),
        _entry("1321", "Siren trouble", EventKind.TROUBLE, restore="3321"),
        _entry("3321", "Siren restored", EventKind.TROUBLE_RESTORE),
        _entry("1322", "Siren supervision trouble", EventKind.TROUBLE, restore="3322"),
        _entry("3322", "Siren supervision restored", EventKind.TROUBLE_RESTORE),
        _entry("1330", "Keypad trouble", EventKind.TROUBLE, restore="3330"),
        _entry("3330", "Keypad restored", EventKind.TROUBLE_RESTORE),
        _entry("1333", "PGM supervision trouble", EventKind.TROUBLE, restore="3333"),
        _entry("3333", "PGM supervision restored", EventKind.TROUBLE_RESTORE),
        _entry("1338", "Remote control low battery", EventKind.TROUBLE, restore="3338"),
        _entry("3338", "Remote control battery restored", EventKind.TROUBLE_RESTORE),
        _entry("1342", "Wireless keypad AC trouble", EventKind.TROUBLE, restore="3342"),
        _entry("3342", "Wireless keypad AC restored", EventKind.TROUBLE_RESTORE),
        _entry("1345", "Wireless keypad low battery", EventKind.TROUBLE, restore="3345"),
        _entry("3345", "Wireless keypad battery restored", EventKind.TROUBLE_RESTORE),
        _entry("1346", "Keypad tamper trouble", EventKind.TAMPER, restore="3346"),
        _entry("3346", "Keypad tamper restored", EventKind.TROUBLE_RESTORE),
        _entry("1351", "Telephone line trouble", EventKind.TROUBLE, restore="3351"),
        _entry("3351", "Telephone line restored", EventKind.TROUBLE_RESTORE),
        _entry("1360", "GPRS trouble", EventKind.TROUBLE, restore="3360"),
        _entry("3360", "GPRS restored", EventKind.TROUBLE_RESTORE),
        _entry("1361", "Ethernet trouble", EventKind.TROUBLE, restore="3361"),
        _entry("3361", "Ethernet restored", EventKind.TROUBLE_RESTORE),
        _entry("1362", "SMS trouble", EventKind.TROUBLE, restore="3362"),
        _entry("3362", "SMS restored", EventKind.TROUBLE_RESTORE),
        _entry("1363", "Cellular module trouble", EventKind.TROUBLE, restore="3363"),
        _entry("3363", "Cellular module restored", EventKind.TROUBLE_RESTORE),
        _entry("1364", "SIM card trouble", EventKind.TROUBLE, restore="3364"),
        _entry("3364", "SIM card restored", EventKind.TROUBLE_RESTORE),
        _entry("1366", "Ethernet module trouble", EventKind.TROUBLE, restore="3366"),
        _entry("3366", "Ethernet module restored", EventKind.TROUBLE_RESTORE),
        _entry("1369", "Network cable trouble", EventKind.TROUBLE, restore="3369"),
        _entry("3369", "Network cable restored", EventKind.TROUBLE_RESTORE),
        _entry("1370", "Zone short circuit", EventKind.TROUBLE, _ZONE, "3370"),
        _entry("3370", "Zone short circuit restored", EventKind.TROUBLE_RESTORE, _ZONE),
        _entry("1381", "Sensor supervision trouble", EventKind.TROUBLE, _ZONE, "3381"),
        _entry("3381", "Sensor supervision restored", EventKind.TROUBLE_RESTORE, _ZONE),
        _entry("1383", "Sensor tamper trouble", EventKind.TAMPER, _ZONE, "3383"),
        _entry("3383", "Sensor tamper restored", EventKind.TROUBLE_RESTORE, _ZONE),
        _entry("1384", "Wireless sensor low battery", EventKind.TROUBLE, _ZONE, "3384"),
        _entry("3384", "Wireless sensor battery restored", EventKind.TROUBLE_RESTORE, _ZONE),
        _entry("1391", "Panic device supervision trouble", EventKind.TROUBLE, restore="3391"),
        _entry("3391", "Panic device supervision restored", EventKind.TROUBLE_RESTORE),
        # --- access and system ------------------------------------------------------------------
        _entry("1410", "Remote programming access", EventKind.SYSTEM, _USER),
        _entry("1412", "User logged in via the app", EventKind.SYSTEM, _USER),
        _entry("1417", "New firmware available", EventKind.SYSTEM),
        _entry("1419", "User registered for notifications", EventKind.SYSTEM, _USER),
        # Five wrong passwords. AGENTS.md §6: remote access is now blocked at the panel until
        # someone performs a valid keypad operation.
        _entry("1421", "Access denied, five wrong passwords", EventKind.SYSTEM, _USER),
        _entry("1422", "PGM switched on by user", EventKind.SYSTEM, _USER, "3422"),
        _entry("3422", "PGM switched off by user", EventKind.SYSTEM, _USER),
        _entry("1429", "Patrol started", EventKind.SYSTEM, _USER, "1430"),
        _entry("1430", "Patrol ended", EventKind.SYSTEM, _USER),
        # Bypass. Note 1570 is a *manual* bypass and 1573 an automatic one; the zone nibble only
        # shows the manual case, so tracking these events is the only way to know about auto-bypass.
        _entry("1570", "Zone bypassed", EventKind.BYPASS, _ZONE),
        _entry("1573", "Zone auto-bypassed", EventKind.BYPASS, _ZONE),
        _entry("1602", "Periodic test", EventKind.TEST),
        _entry("1611", "Patrol OK", EventKind.TEST, _USER),
        _entry("1612", "Patrol failed", EventKind.TEST, _USER),
        _entry("1627", "Entered programming", EventKind.SYSTEM, _USER, "1628"),
        _entry("1628", "Left programming", EventKind.SYSTEM, _USER),
        # --- arming and disarming ---------------------------------------------------------------
        # Arm and arm-away are indistinguishable here: both emit 3407. The mode lives in PART[i].
        _entry("3401", "Armed", EventKind.ARM, _USER, "1401"),
        _entry("1401", "Disarmed", EventKind.DISARM, _USER),
        _entry("3403", "Auto-armed on schedule", EventKind.ARM, _USER, "1403"),
        _entry("1403", "Auto-disarmed on schedule", EventKind.DISARM, _USER),
        _entry("3404", "Auto-armed on no movement", EventKind.ARM, _USER),
        # Verified on hardware: this is what the fence emits when armed remotely, with
        # partition "99" and user "099".
        _entry("3407", "Armed remotely", EventKind.ARM, _USER, "1407"),
        _entry("1407", "Disarmed remotely", EventKind.DISARM, _USER),
        _entry("3408", "Quick armed", EventKind.ARM, _USER),
        _entry("3409", "Armed by remote control or LIGA input", EventKind.ARM, _USER, "1409"),
        _entry("1409", "Disarmed by remote control or LIGA input", EventKind.DISARM, _USER),
        _entry("3441", "Armed STAY", EventKind.ARM, _USER),
        _entry("3464", "Auto-arm deferred", EventKind.ARM, _USER),
    ]
)
"""Every code the panel can send, keyed by its four-character text form."""


UNKNOWN_CODE: Final = ContactIdCode("", "Unknown event", EventKind.UNKNOWN, EventSubject.NONE)
"""Returned for a code not in the table.

An unrecognised event must never raise and must never be dropped: it still has to be acknowledged,
or the panel retransmits it forever, and logging it at debug is how a code the manual omits gets
found.
"""


def lookup(code: str) -> ContactIdCode:
    """Return the table entry for *code*, or `UNKNOWN_CODE`. Never raises."""
    return CODES.get(code.strip(), UNKNOWN_CODE)


_FENCE_KINDS: Final[dict[EventKind, EventKind]] = {
    EventKind.ARM: EventKind.FENCE_ARM,
    EventKind.DISARM: EventKind.FENCE_DISARM,
    EventKind.ALARM: EventKind.FENCE_ALARM,
    EventKind.ALARM_RESTORE: EventKind.FENCE_ALARM_RESTORE,
}
"""How the four codes the fence shares with the rest of the panel are re-labelled for partition 99.

Only these four. A trouble or a test that happened to carry partition 99 means the same thing it
means anywhere else, and inventing a fence-specific name for it would say more than the panel did.
"""


def classify(code: str, partition: str = "") -> EventKind:
    """Classify an event, taking the partition into account.

    The electric fence has no codes of its own — it reports arming as `3401`, remote arming as
    `3407` and its alarm as `1130`, all with partition `99`. So a code alone cannot tell you whether
    an event concerns the fence, and any caller deciding what an event *means* needs both.

    Partition 99 therefore maps arm, disarm, alarm and alarm-restore onto their `FENCE_*`
    equivalents. Without that, an event entity covering the whole panel reports "Armed" when the
    electric fence was switched on and the house was never armed at all — which is precisely how the
    2026-08-08 lab session read. Every other code keeps its ordinary classification; use
    `is_fence()` when the question is only *which device*.
    """
    kind = lookup(code).kind
    if is_fence(partition):
        return _FENCE_KINDS.get(kind, kind)
    return kind


def is_fence(partition: str) -> bool:
    """Return whether an event's partition identifies it as the electric fence."""
    return partition.strip() == FENCE_PARTITION_TEXT


ZONE_ALERTS: Final[dict[str, tuple[ZoneAlert, bool]]] = {
    # code -> (which condition, does this code *set* it)
    "1384": (ZoneAlert.LOW_BATTERY, True),
    "3384": (ZoneAlert.LOW_BATTERY, False),
    "1381": (ZoneAlert.SUPERVISION, True),
    "3381": (ZoneAlert.SUPERVISION, False),
    "1383": (ZoneAlert.TAMPER, True),
    "3383": (ZoneAlert.TAMPER, False),
}
"""The six codes that bracket a lasting per-zone condition.

**These carry information the status frame physically cannot.** A zone's nibble holds one value, so
a sensor with a dying battery reports `6` while closed and `7` the moment somebody walks past it —
the low battery is not gone, it has been overwritten. The event pair is not overwritten by anything.

Only matched pairs are here. `1370`/`3370` (short circuit) is a wiring fault on a hard-wired zone,
which the nibble reports perfectly well and which no wireless sensor produces.
"""


def zone_alert(code: str) -> tuple[ZoneAlert, bool] | None:
    """Return the condition *code* sets or clears, or `None` if it is not one of the six."""
    return ZONE_ALERTS.get(code.strip())


def subject_of(code: str) -> EventSubject:
    """Return whether *code*'s three-character field is a zone, a user, or neither.

    Getting this wrong reports zone 10 as user 10. The 2026-08-08 capture also showed the field
    encodes *origin* for remote operations: `099` is the monitoring connection, `000` the app.
    """
    return lookup(code).subject
