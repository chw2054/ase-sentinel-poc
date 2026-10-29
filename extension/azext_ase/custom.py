import os
import subprocess
from pathlib import Path

from azure.cli.core.azclierror import UnclassifiedUserFault
from knack.log import get_logger

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


def _repo_root() -> Path:
    configured = os.environ.get("ASE_POC_ROOT")
    if configured:
        root = Path(configured)
        if (root / "scripts" / "ase.ps1").is_file():
            return root
        raise UnclassifiedUserFault(f"ASE_POC_ROOT does not contain scripts/ase.ps1: {root}")
    cursor = Path.cwd()
    for candidate in [cursor, *cursor.parents]:
        if (candidate / "scripts" / "ase.ps1").is_file() and (candidate / "profiles" / "poc.json").is_file():
            return candidate
    raise UnclassifiedUserFault(
        "Could not find the PoC repo. Run this from ase-sentinel-poc, or set ASE_POC_ROOT."
    )
