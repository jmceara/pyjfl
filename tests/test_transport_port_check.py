"""Tests for `check_port_available`.

Author: Jonis Maurin Ceará <jmceara AT gmail.com>
"""

from __future__ import annotations

import socket

import pytest

from pyjfl import check_port_available

LOOPBACK = "127.0.0.1"


def _free_port() -> int:
    """Claim an unused TCP port and release it again."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind((LOOPBACK, 0))
        return int(probe.getsockname()[1])


def test_check_port_available_passes_on_a_free_port() -> None:
    """A genuinely free port raises nothing."""
    port = _free_port()
    check_port_available(LOOPBACK, port)


def test_check_port_available_raises_when_already_bound() -> None:
    """A port held by another socket raises `OSError`, not something swallowed."""
    port = _free_port()
    with (
        socket.socket(socket.AF_INET, socket.SOCK_STREAM) as holder,
        pytest.raises(OSError),
    ):
        holder.bind((LOOPBACK, port))
        holder.listen(1)
        check_port_available(LOOPBACK, port)


def test_check_port_available_releases_the_probe(caplog: pytest.LogCaptureFixture) -> None:
    """The probe socket is released, so the same port can be bound again immediately after."""
    port = _free_port()
    check_port_available(LOOPBACK, port)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind((LOOPBACK, port))
