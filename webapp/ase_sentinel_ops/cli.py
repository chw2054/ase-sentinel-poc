"""Read Sentinel incidents and one WAF policy from this machine.

The bearer token arrives on stdin, one line, and is never written to stdout,
stderr, or a log. This command does not call the operations Web App and does
not read BLOCK_API_KEY.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import TextIO

from app.config import Settings
from app.live import AzureCallError, Inventory, LiveIncident, SentinelAzure

_GUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.()-]{0,89}$")
_POLICY = re.compile(
    r"^/subscriptions/(?P<sub>[0-9a-fA-F-]{36})"
    r"/resourceGroups/(?P<rg>[A-Za-z0-9][A-Za-z0-9_.()-]{0,89})"
    r"/providers/Microsoft\.Network/applicationGatewayWebApplicationFirewallPolicies/"
    r"(?P<name>[A-Za-z0-9][A-Za-z0-9_.()-]{0,89})$",
    re.IGNORECASE,
)
_TOKEN_LIMIT = 16384


class UsageError(Exception):
    """The command line or the pinned resource settings cannot be used."""


def main(
    argv: list[str] | None = None,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    azure_factory=None,
) -> int:
    """Run one read command. Returns a process status, never raises to the host."""

    out = stdout or sys.stdout
    token = ""
    try:
        args = _parser().parse_args(argv)
        token = _read_token(stdin or sys.stdin)
        settings = resource_settings()
        if args.command == "show" and not _GUID.fullmatch(args.incident_id):
            raise UsageError("incident id must be a GUID")
        azure = (azure_factory or _azure)(settings, token)
        if args.command == "list":
            payload = {"incidents": [incident_payload(item) for item in azure.list_open()]}
        elif args.command == "show":
            payload = {"incident": incident_payload(azure.get(args.incident_id))}
        elif args.command == "inventory":
            payload = inventory_payload(azure.inventory())
        else:
            raise UsageError("unknown command")
    except UsageError as exc:
        _emit(out, {"error": _redact(str(exc), token)})
        return 2
    except AzureCallError as exc:
        _emit(out, {"error": _redact(str(exc), token)})
        return 3
    except Exception:
        _emit(out, {"error": "the Azure call failed"})
        return 3
    _emit(out, payload)
    return 0


def resource_settings() -> Settings:
    """Pinned subscription, resource group, workspace, and one WAF policy.

    BLOCK_API_KEY is ignored on purpose. Reads use the caller's token.
    """

    subscription = os.environ.get("AZURE_SUBSCRIPTION_ID", "").strip()
    resource_group = os.environ.get("AZURE_RESOURCE_GROUP", "").strip()
    workspace = os.environ.get("SENTINEL_WORKSPACE_NAME", "").strip()
    policy = _normalize_policy_id(os.environ.get("WAF_POLICY_RESOURCE_ID", "").strip())
    missing = [
        name
        for name, value in (
            ("AZURE_SUBSCRIPTION_ID", subscription),
            ("AZURE_RESOURCE_GROUP", resource_group),
            ("SENTINEL_WORKSPACE_NAME", workspace),
            ("WAF_POLICY_RESOURCE_ID", policy),
        )
        if not value
    ]
    if missing:
        raise UsageError("set " + ", ".join(missing))
    if not _GUID.fullmatch(subscription):
        raise UsageError("AZURE_SUBSCRIPTION_ID must be a GUID")
    if not _NAME.fullmatch(resource_group):
        raise UsageError("AZURE_RESOURCE_GROUP is not a resource group name")
    if not _NAME.fullmatch(workspace):
        raise UsageError("SENTINEL_WORKSPACE_NAME is not a workspace name")
    match = _POLICY.fullmatch(policy)
    if match is None or not _GUID.fullmatch(match.group("sub")):
        raise UsageError("WAF_POLICY_RESOURCE_ID must be one Application Gateway WAF policy id")
    if match.group("sub").casefold() != subscription.casefold():
        raise UsageError("WAF_POLICY_RESOURCE_ID is not in AZURE_SUBSCRIPTION_ID")
    if match.group("rg").casefold() != resource_group.casefold():
        raise UsageError("WAF_POLICY_RESOURCE_ID is not in AZURE_RESOURCE_GROUP")
    return Settings(
        app_env="local",
        subscription_id=subscription,
        resource_group=resource_group,
        workspace_name=workspace,
        waf_policy_id=policy,
        block_api_key="",
        secret="",
        dev_login_password="",
    )


def _normalize_policy_id(policy: str) -> str:
    """Drop a portal `/resource` prefix so the value is an ARM id."""

    marker = "/resource"
    if policy.casefold().startswith(marker + "/"):
        return policy[len(marker) :]
    return policy


def incident_payload(incident: LiveIncident) -> dict:
    return {
        "id": incident.id,
        "number": incident.number,
        "title": incident.title,
        "severity": incident.severity,
        "status": incident.status,
        "created": incident.created,
        "armId": incident.arm_id,
        "ips": list(incident.ips),
    }


def inventory_payload(inventory: Inventory) -> dict:
    return {
        "workspaceName": inventory.sentinel_name,
        "workspaceId": inventory.sentinel_id,
        "gatewayError": inventory.gateway_error,
        "policies": [
            {
                "name": policy.name,
                "resourceId": policy.resource_id,
                "rules": [{"name": rule.name, "values": list(rule.values)} for rule in policy.rules],
                "gateways": [{"name": gateway.name, "url": gateway.url} for gateway in policy.gateways],
            }
            for policy in inventory.policies
        ],
    }


def _azure(settings: Settings, token: str) -> SentinelAzure:
    return SentinelAzure(settings, token=lambda: token)


def _read_token(stdin: TextIO) -> str:
    line = stdin.readline()
    if line.endswith("\n"):
        line = line[:-1]
    if line.endswith("\r"):
        line = line[:-1]
    if not line or any(character.isspace() for character in line) or len(line) > _TOKEN_LIMIT:
        raise UsageError("a bearer token is required on stdin")
    return line


def _redact(text: str, token: str) -> str:
    if token:
        text = text.replace(token, "[redacted]")
    return text


def _emit(stdout: TextIO, payload: dict) -> None:
    json.dump(payload, stdout, ensure_ascii=False)
    stdout.write("\n")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ase_sentinel_ops", description="Read ASE Sentinel incidents and one WAF policy.")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list", help="List open Sentinel incidents and their IPv4 addresses.")
    show = commands.add_parser("show", help="Read one incident by its GUID.")
    show.add_argument("incident_id")
    commands.add_parser("inventory", help="List SentinelAutoBlock values on the pinned WAF policy.")
    return parser
