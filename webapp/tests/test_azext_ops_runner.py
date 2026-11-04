"""The az extension runner sends the token on stdin and does not print it."""

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "azext_ops_runner",
    Path(__file__).resolve().parents[2] / "extension" / "azext_ase" / "ops_runner.py",
)
ops = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ops)

OpsError = ops.OpsError
blocks_from = ops.blocks_from
incident_from = ops.incident_from
incidents_from = ops.incidents_from
python_executable = ops.python_executable
redact = ops.redact
repo_root = ops.repo_root
run_ops = ops.run_ops

TOKEN = "header.payload.signature"
WEBAPP = Path("C:/repo/webapp")
PYTHON = Path("C:/repo/webapp/.venv/Scripts/python.exe")


class Completed:
    def __init__(self, code: int, stdout: str, stderr: str = "") -> None:
        self.returncode = code
        self.stdout = stdout
        self.stderr = stderr


def test_run_ops_hides_the_token_and_drops_secret_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BLOCK_API_KEY", "must-not-appear")
    seen = {}

    def fake_run(command, **kwargs):
        seen["command"] = command
        seen["input"] = kwargs["input"]
        seen["env"] = kwargs["env"]
        seen["shell"] = kwargs["shell"]
        seen["cwd"] = kwargs["cwd"]
        assert TOKEN not in command
        return Completed(0, json.dumps({"incidents": [{"number": "19"}]}))

    monkeypatch.setattr(ops.subprocess, "run", fake_run)
    payload = run_ops(
        PYTHON,
        WEBAPP,
        ["list"],
        TOKEN,
        "ae4654a2-8a96-431c-ad3d-176ae51ec9d8",
        "rg-ase-sentinel-poc",
        "log-ase-sentinel-poc",
        "/subscriptions/ae4654a2-8a96-431c-ad3d-176ae51ec9d8/resourceGroups/rg/providers/Microsoft.Network/applicationGatewayWebApplicationFirewallPolicies/waf",
    )
    assert payload["incidents"][0]["number"] == "19"
    assert seen["command"] == [str(PYTHON), "-m", "ase_sentinel_ops", "list"]
    assert seen["input"] == TOKEN + "\n"
    assert seen["shell"] is False
    assert seen["cwd"] == str(WEBAPP)
    assert "BLOCK_API_KEY" not in seen["env"]
    assert seen["env"]["AZURE_SUBSCRIPTION_ID"] == "ae4654a2-8a96-431c-ad3d-176ae51ec9d8"
    assert seen["env"]["SENTINEL_WORKSPACE_NAME"] == "log-ase-sentinel-poc"
    assert "must-not-appear" not in json.dumps(payload)


def test_run_ops_redacts_a_token_in_the_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(command, **kwargs):
        return Completed(3, json.dumps({"error": f"denied {TOKEN}"}), TOKEN)

    monkeypatch.setattr(ops.subprocess, "run", fake_run)
    with pytest.raises(OpsError) as raised:
        run_ops(PYTHON, WEBAPP, ["list"], TOKEN, "sub", "rg", "ws", "/subscriptions/s")
    assert str(raised.value) == "denied [redacted]"
    assert TOKEN not in str(raised.value)


def test_run_ops_timeout_has_no_token(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(ops.subprocess, "run", fake_run)
    with pytest.raises(OpsError) as raised:
        run_ops(PYTHON, WEBAPP, ["inventory"], TOKEN, "sub", "rg", "ws", "/subscriptions/s")
    assert str(raised.value) == "the operations command timed out"
    assert TOKEN not in str(raised.value)


def test_python_executable_uses_the_venv_or_the_configured_path(tmp_path: Path) -> None:
    webapp = tmp_path / "webapp"
    venv = webapp / ".venv" / "Scripts"
    venv.mkdir(parents=True)
    python = venv / "python.exe"
    python.write_text("", encoding="utf-8")
    assert python_executable(webapp, None) == python
    other = tmp_path / "other.exe"
    other.write_text("", encoding="utf-8")
    assert python_executable(webapp, str(other)) == other
    with pytest.raises(OpsError):
        python_executable(tmp_path / "empty", None)


def test_repo_root_uses_config_when_the_shell_is_elsewhere(tmp_path: Path) -> None:
    repo = tmp_path / "ase-sentinel-poc"
    (repo / "scripts").mkdir(parents=True)
    (repo / "profiles").mkdir()
    (repo / "scripts" / "ase.ps1").write_text("#", encoding="utf-8")
    (repo / "profiles" / "poc.json").write_text("{}", encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    assert repo_root(elsewhere, None, str(repo)) == repo
    assert repo_root(repo, None, None) == repo
    with pytest.raises(OpsError, match="ase.repo_root"):
        repo_root(elsewhere, None, str(tmp_path / "missing"))
    with pytest.raises(OpsError, match="az config set ase.repo_root"):
        repo_root(elsewhere, None, None)


def test_block_rows_keep_one_address_per_row() -> None:
    rows, gateway_error = blocks_from(
        {
            "gatewayError": "",
            "policies": [
                {
                    "name": "wafpol",
                    "rules": [{"name": "SentinelAutoBlock", "values": ["203.0.113.4", "203.0.113.5"]}],
                    "gateways": [{"name": "agw", "url": "http://203.0.113.20"}],
                }
            ],
        }
    )
    assert gateway_error == ""
    assert rows == [
        {"policy": "wafpol", "rule": "SentinelAutoBlock", "address": "203.0.113.4", "gateway": "http://203.0.113.20"},
        {"policy": "wafpol", "rule": "SentinelAutoBlock", "address": "203.0.113.5", "gateway": "http://203.0.113.20"},
    ]
    assert incidents_from({"incidents": []}) == []
    assert incident_from({"incident": {"id": "x"}})["id"] == "x"
    assert redact(f"see {TOKEN}", TOKEN) == "see [redacted]"
