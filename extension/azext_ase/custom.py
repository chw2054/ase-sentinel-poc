import configparser
import os
import subprocess
from pathlib import Path

from azure.cli.core._config import GLOBAL_CONFIG_PATH
from azure.cli.core._profile import Profile
from azure.cli.core.azclierror import UnclassifiedUserFault
from knack.log import get_logger

from .ops_runner import (
    OpsError,
    blocks_from,
    incident_from,
    incidents_from,
    python_executable,
    repo_root,
    run_ops,
)

log = get_logger(__name__)


def run_diff(
    profile="poc",
    subscription_id=None,
    resource_group="rg-ase-sentinel-poc",
    location="eastus",
    name_prefix="ase-sentinel-poc",
    existing_waf_policy_name=None,
    deploy_test_waf=False,
):
    _run(
        "diff",
        profile,
        subscription_id,
        resource_group,
        location,
        name_prefix,
        existing_waf_policy_name,
        deploy_test_waf,
        apply=False,
    )


def run_deploy(
    profile="poc",
    subscription_id=None,
    resource_group="rg-ase-sentinel-poc",
    location="eastus",
    name_prefix="ase-sentinel-poc",
    existing_waf_policy_name=None,
    deploy_test_waf=False,
    apply=False,
):
    _run(
        "deploy",
        profile,
        subscription_id,
        resource_group,
        location,
        name_prefix,
        existing_waf_policy_name,
        deploy_test_waf,
        apply,
    )


def _run(
    action,
    profile,
    subscription_id,
    resource_group,
    location,
    name_prefix,
    existing_waf_policy_name,
    deploy_test_waf,
    apply,
):
    repo = _repo_root()
    script = repo / "scripts" / "ase.ps1"
    command = [
        "pwsh",
        "-NoProfile",
        "-File",
        str(script),
        action,
        "-Profile",
        profile,
        "-ResourceGroupName",
        resource_group,
        "-Location",
        location,
        "-NamePrefix",
        name_prefix,
    ]
    if subscription_id:
        command.extend(["-SubscriptionId", subscription_id])
    if existing_waf_policy_name:
        command.extend(["-ExistingWafPolicyName", existing_waf_policy_name])
    if deploy_test_waf:
        command.append("-DeployTestWaf")
    if apply:
        command.append("-Apply")
    log.info("Running %s", " ".join(command))
    completed = subprocess.run(command, cwd=str(repo), check=False)
    if completed.returncode != 0:
        raise UnclassifiedUserFault(f"scripts/ase.ps1 {action} exited {completed.returncode}")


def list_incidents(
    cmd,
    subscription_id,
    resource_group,
    workspace_name,
    waf_policy_resource_id,
    python_path=None,
):
    payload = _ops(
        cmd,
        ["list"],
        subscription_id,
        resource_group,
        workspace_name,
        waf_policy_resource_id,
        python_path,
    )
    return incidents_from(payload)


def show_incident(
    cmd,
    incident_id,
    subscription_id,
    resource_group,
    workspace_name,
    waf_policy_resource_id,
    python_path=None,
):
    payload = _ops(
        cmd,
        ["show", incident_id],
        subscription_id,
        resource_group,
        workspace_name,
        waf_policy_resource_id,
        python_path,
    )
    return incident_from(payload)


def list_blocks(
    cmd,
    subscription_id,
    resource_group,
    workspace_name,
    waf_policy_resource_id,
    python_path=None,
):
    payload = _ops(
        cmd,
        ["inventory"],
        subscription_id,
        resource_group,
        workspace_name,
        waf_policy_resource_id,
        python_path,
    )
    rows, gateway_error = blocks_from(payload)
    if gateway_error:
        log.warning(gateway_error)
    return rows


def _ops(cmd, args, subscription_id, resource_group, workspace_name, policy_id, python_path):
    repo = _repo_root()
    webapp = repo / "webapp"
    try:
        python = python_executable(webapp, python_path)
        return run_ops(
            python,
            webapp,
            args,
            _arm_token(cmd, subscription_id),
            subscription_id,
            resource_group,
            workspace_name,
            policy_id,
        )
    except OpsError as exc:
        raise UnclassifiedUserFault(str(exc)) from exc


def _arm_token(cmd, subscription_id: str) -> str:
    profile = Profile(cli_ctx=cmd.cli_ctx)
    creds, _, _ = profile.get_raw_token(
        subscription=subscription_id,
        resource="https://management.azure.com/",
    )
    token = creds[1]
    if not isinstance(token, str):
        raise OpsError("Azure CLI did not return an ARM token. Run az login.")
    return token


def _repo_root() -> Path:
    try:
        return repo_root(Path.cwd(), os.environ.get("ASE_POC_ROOT"), _configured_repo_root())
    except OpsError as exc:
        raise UnclassifiedUserFault(str(exc)) from exc


def _configured_repo_root() -> str | None:
    parser = configparser.ConfigParser(interpolation=None)
    parser.read(GLOBAL_CONFIG_PATH, encoding="utf-8")
    if not parser.has_option("ase", "repo_root"):
        return None
    value = parser.get("ase", "repo_root").strip()
    return value or None
