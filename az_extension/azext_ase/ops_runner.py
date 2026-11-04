"""Run the read-only operations module with the bearer token on stdin."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

TOKEN_LIMIT = 16384
COMMAND_TIMEOUT_SECONDS = 180
_SECRET_ENV = (
    "BLOCK_API_KEY",
    "APP_SECRET",
    "DEV_LOGIN_PASSWORD",
    "AZURE_CLIENT_SECRET",
    "AZURE_CLIENT_CERTIFICATE_PATH",
    "AZURE_CLIENT_CERTIFICATE_PASSWORD",
)


class OpsError(Exception):
    """The operations command failed with a message that is safe to show."""


def redact(text: str, token: str) -> str:
    if token and token in text:
        return text.replace(token, "[redacted]")
    return text


def is_repo(path: Path) -> bool:
    return (path / "scripts" / "ase.ps1").is_file() and (path / "profiles" / "poc.json").is_file()


def repo_root(cwd: Path, env_value: str | None, configured_value: str | None) -> Path:
    """Find the PoC checkout. An explicit path must be valid."""

    if env_value:
        root = Path(env_value)
        if is_repo(root):
            return root
        raise OpsError(f"ASE_POC_ROOT does not contain the PoC repo: {root}")
    if configured_value:
        root = Path(configured_value)
        if is_repo(root):
            return root
        raise OpsError(f"ase.repo_root does not contain the PoC repo: {root}")
    for candidate in [cwd, *cwd.parents]:
        if is_repo(candidate):
            return candidate
    raise OpsError(
        "Could not find the PoC repo. Run this from ase-sentinel-poc, "
        "set ASE_POC_ROOT, or run az config set ase.repo_root=<path>."
    )


def python_executable(webapp: Path, configured: str | None) -> Path:
    if configured:
        path = Path(configured)
        if path.is_file():
            return path
        raise OpsError(f"Python not found: {path}")
    for parts in (("Scripts", "python.exe"), ("bin", "python")):
        candidate = webapp / ".venv" / Path(*parts)
        if candidate.is_file():
            return candidate
    raise OpsError("Set --python-path to a Python that can import this repo.")


def run_ops(
    python: Path,
    webapp: Path,
    args: list[str],
    token: str,
    subscription_id: str,
    resource_group: str,
    workspace_name: str,
    policy_id: str,
    timeout: int = COMMAND_TIMEOUT_SECONDS,
) -> dict:
    if not isinstance(token, str) or not token or any(character.isspace() for character in token):
        raise OpsError("an ARM token is required")
    if len(token) > TOKEN_LIMIT:
        raise OpsError("the ARM token is too long")
    env = os.environ.copy()
    for name in _SECRET_ENV:
        env.pop(name, None)
    env["AZURE_SUBSCRIPTION_ID"] = subscription_id
    env["AZURE_RESOURCE_GROUP"] = resource_group
    env["SENTINEL_WORKSPACE_NAME"] = workspace_name
    env["WAF_POLICY_RESOURCE_ID"] = policy_id
    previous = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(webapp) if not previous else str(webapp) + os.pathsep + previous
    command = [str(python), "-m", "ase_sentinel_ops", *args]
    try:
        completed = subprocess.run(
            command,
            cwd=str(webapp),
            env=env,
            input=token + "\n",
            text=True,
            capture_output=True,
            timeout=timeout,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise OpsError("the operations command timed out") from exc
    stdout = completed.stdout or ""
    stderr = redact(completed.stderr or "", token)
    try:
        payload = json.loads(stdout) if stdout.strip() else {}
    except json.JSONDecodeError as exc:
        detail = redact(stderr.strip() or stdout, token).strip()
        raise OpsError(detail or "the operations command returned invalid output") from exc
    if not isinstance(payload, dict):
        raise OpsError("the operations command returned invalid output")
    error = payload.get("error")
    if completed.returncode != 0 or error:
        message = error or stderr.strip() or f"the operations command exited {completed.returncode}"
        raise OpsError(redact(str(message), token))
    return payload


def incidents_from(payload: dict) -> list:
    incidents = payload.get("incidents")
    if not isinstance(incidents, list):
        raise OpsError("the operations command returned invalid output")
    return incidents


def incident_from(payload: dict) -> dict:
    incident = payload.get("incident")
    if not isinstance(incident, dict):
        raise OpsError("the operations command returned invalid output")
    return incident


def blocks_from(payload: dict) -> tuple[list[dict], str]:
    policies = payload.get("policies")
    if not isinstance(policies, list):
        raise OpsError("the operations command returned invalid output")
    gateway_error = payload.get("gatewayError") or ""
    if not isinstance(gateway_error, str):
        gateway_error = ""
    rows: list[dict] = []
    for policy in policies:
        if not isinstance(policy, dict):
            raise OpsError("the operations command returned invalid output")
        gateways = []
        for gateway in policy.get("gateways") or []:
            if isinstance(gateway, dict):
                gateways.append(str(gateway.get("url") or gateway.get("name") or ""))
        gateway_text = ", ".join(item for item in gateways if item)
        rules = policy.get("rules") or []
        if not isinstance(rules, list):
            raise OpsError("the operations command returned invalid output")
        for rule in rules:
            if not isinstance(rule, dict):
                raise OpsError("the operations command returned invalid output")
            values = rule.get("values") or []
            if not isinstance(values, list):
                raise OpsError("the operations command returned invalid output")
            if not values:
                rows.append(_block_row(policy, rule, "", gateway_text))
                continue
            for value in values:
                rows.append(_block_row(policy, rule, value, gateway_text))
    return rows, gateway_error


def _block_row(policy: dict, rule: dict, address, gateway_text: str) -> dict:
    return {
        "policy": policy.get("name") or "",
        "rule": rule.get("name") or "",
        "address": address,
        "gateway": gateway_text,
    }
