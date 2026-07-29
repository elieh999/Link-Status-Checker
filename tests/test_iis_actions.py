from __future__ import annotations

import platform
import subprocess

import pytest

import main

RUNNING_OUTPUT = "SERVICE_NAME: W3SVC\n        STATE              : 4  RUNNING\n"
STOPPED_OUTPUT = "SERVICE_NAME: W3SVC\n        STATE              : 1  STOPPED\n"
PENDING_OUTPUT = "SERVICE_NAME: W3SVC\n        STATE              : 2  START_PENDING\n"


def completed(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(args=["sc"], returncode=returncode, stdout=stdout, stderr=stderr)


@pytest.fixture(autouse=True)
def pretend_windows(monkeypatch):
    """run_iis_action bails out early off Windows, so the suite has to claim it."""
    monkeypatch.setattr(main.platform, "system", lambda: "Windows")
    # Never sleep for real while polling for a state change.
    monkeypatch.setattr(main.time, "sleep", lambda seconds: None)


def test_service_outside_the_allowlist_is_refused():
    result = main.run_iis_action("start", "SomeOtherService")
    assert result.success is False
    assert "allowlist" in result.message


def test_status_reports_the_parsed_state(monkeypatch):
    monkeypatch.setattr(main, "run_sc_command", lambda args, **kwargs: completed(stdout=RUNNING_OUTPUT))
    result = main.run_iis_action("status", "W3SVC")
    assert result.success is True
    assert "RUNNING" in result.message


def test_start_that_never_reaches_running_is_reported_as_a_failure(monkeypatch):
    """Regression: wait_for_service_state's return value was thrown away, so a
    service stuck in START_PENDING was still announced as "Service is running."

    Lying about this is the worst case for a monitoring tool: the operator walks
    away believing IIS came back up.
    """
    calls = []

    def fake_sc(args, **kwargs):
        calls.append(args)
        if args[0] == "start":
            return completed(stdout="START_PENDING")
        return completed(stdout=PENDING_OUTPUT)

    monkeypatch.setattr(main, "run_sc_command", fake_sc)
    monkeypatch.setattr(main, "wait_for_service_state", lambda *a, **k: False)

    result = main.run_iis_action("start", "W3SVC")
    assert result.success is False
    assert "running" in result.message.lower()
    assert "did not" in result.message.lower() or "not reach" in result.message.lower()


def test_start_that_does_reach_running_is_reported_as_success(monkeypatch):
    monkeypatch.setattr(main, "run_sc_command", lambda args, **kwargs: completed(stdout=RUNNING_OUTPUT))
    monkeypatch.setattr(main, "wait_for_service_state", lambda *a, **k: True)
    result = main.run_iis_action("start", "W3SVC")
    assert result.success is True
    assert result.message == "Service is running."


def test_restart_that_never_comes_back_up_is_reported_as_a_failure(monkeypatch):
    monkeypatch.setattr(main, "run_sc_command", lambda args, **kwargs: completed(stdout=STOPPED_OUTPUT))
    # Stop works, start never reaches RUNNING.
    states = {"STOPPED": True, "RUNNING": False}
    monkeypatch.setattr(main, "wait_for_service_state", lambda name, expected, **k: states[expected])

    result = main.run_iis_action("restart", "W3SVC")
    assert result.success is False
    assert "running" in result.message.lower()


def test_restart_reports_success_only_when_it_really_restarted(monkeypatch):
    monkeypatch.setattr(main, "run_sc_command", lambda args, **kwargs: completed(stdout=RUNNING_OUTPUT))
    monkeypatch.setattr(main, "wait_for_service_state", lambda *a, **k: True)
    result = main.run_iis_action("restart", "W3SVC")
    assert result.success is True
    assert result.message == "Service restarted and running."


def test_restart_that_cannot_stop_the_service_fails_early(monkeypatch):
    monkeypatch.setattr(
        main,
        "run_sc_command",
        lambda args, **kwargs: completed(stderr="Access is denied.", returncode=5),
    )
    result = main.run_iis_action("restart", "W3SVC")
    assert result.success is False
    assert "administrator" in result.message.lower()


def test_access_denied_gets_a_useful_message():
    assert "administrator" in main.friendly_service_error("[SC] OpenService FAILED 5: Access is denied.").lower()


def test_wait_for_service_state_gives_up_and_returns_false(monkeypatch):
    monkeypatch.setattr(main, "run_sc_command", lambda args, **kwargs: completed(stdout=STOPPED_OUTPUT))
    ticks = iter(range(0, 100))
    monkeypatch.setattr(main.time, "monotonic", lambda: next(ticks))
    assert main.wait_for_service_state("W3SVC", "RUNNING", timeout_seconds=3) is False


def test_wait_for_service_state_returns_true_once_the_state_matches(monkeypatch):
    monkeypatch.setattr(main, "run_sc_command", lambda args, **kwargs: completed(stdout=RUNNING_OUTPUT))
    assert main.wait_for_service_state("W3SVC", "RUNNING", timeout_seconds=3) is True


@pytest.mark.skipif(platform.system().lower() == "windows", reason="checks the non Windows guard")
def test_non_windows_is_refused_politely(monkeypatch):
    monkeypatch.setattr(main.platform, "system", lambda: "Linux")
    result = main.run_iis_action("status", "W3SVC")
    assert result.success is False
