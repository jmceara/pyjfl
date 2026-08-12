"""Shared pytest fixtures for the pyjfl test suite.

Author: Jonis Maurin Ceará <jmceara AT gmail.com>
Based on the code developed by Carlos Jose Fernandes,
available at https://github.com/fernac03/JFL_ACTIVE

This is the library's own conftest, not the integration's. JFL_ALARM's version spends most of its
length working around the fact that Home Assistant's test harness cannot be imported on Windows;
here there is no Home Assistant to work around, which is the clearest single sign that the split
was worth making.

The fixtures are real bytes observed on the wire against a live Active 32 Duo, stored as hex.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

FIXTURE_DIR = Path(__file__).parent / "fixtures"


def load_frame_bytes(name: str) -> bytes:
    """Return the bytes of the captured frame stored in `tests/fixtures/<name>`.

    Whitespace and `#` comments are stripped, so a fixture may be written either as one continuous
    string or spaced out and annotated. They are the ground truth: a parser that disagrees with a
    fixture is wrong, the fixture is not.
    """
    text = (FIXTURE_DIR / name).read_text(encoding="utf-8")
    stripped = "".join(
        token for line in text.splitlines() for token in line.split("#", 1)[0].split()
    )
    return bytes.fromhex(stripped)


@pytest.fixture
def load_frame() -> Callable[[str], bytes]:
    """Return a loader for the captured frames in `tests/fixtures/`."""
    return load_frame_bytes
