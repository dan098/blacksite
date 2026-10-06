from types import SimpleNamespace

import pytest

from lab import defender_update
from lab.vm import VMError


@pytest.mark.parametrize("state", ["inactive", "failed"])
def test_maintenance_checks_only_public_service(monkeypatch, state):
    commands = []

    def run(command, **kwargs):
        commands.append(command)
        return SimpleNamespace(stdout=state + "\n")

    monkeypatch.setattr(defender_update.subprocess, "run", run)
    defender_update._require_service_stopped()
    assert commands == [["systemctl", "--user", "is-active", "blacksite.service"]]


@pytest.mark.parametrize("state", ["active", "activating", ""])
def test_maintenance_fails_closed_for_unconfirmed_service_state(monkeypatch, state):
    monkeypatch.setattr(
        defender_update.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout=state),
    )
    with pytest.raises(VMError, match="blacksite.service"):
        defender_update._require_service_stopped()
