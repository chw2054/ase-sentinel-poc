"""Live operations pages. Sentinel is the queue and the WAF policy is the block list.

Block, add, and remove call the in-process engine with execution=enforce. That
one field writes a block-list rule even when AUTO_BLOCK_ENABLED is false.
The playbook posts the same engine at /api/SentinelWafAutoBlock.
Don't block only comments and closes the incident.
"""

from __future__ import annotations

import hmac
import ipaddress
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.api import install_errors
from app.auth import COOKIE, LOCAL_USERS, login_local, principal_from_request
from app.config import Settings
from app.ops import OpsError

INCIDENT_API = "2024-03-01"
POLICY_API = "2024-05-01"
MATCH_VALUES_PER_POLICY = 600
DECISION_ROLES = frozenset({"admin", "operator", "approver"})
TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


class AzureCallError(Exception):
    """A Sentinel or WAF call failed. The message never includes a key."""


@dataclass(frozen=True)
class GatewayView:
    name: str
    url: str


@dataclass(frozen=True)
class RuleView:
    name: str
    values: tuple[str, ...]


@dataclass(frozen=True)
class PolicyView:
    name: str
    resource_id: str
    rules: tuple[RuleView, ...]
    gateways: tuple[GatewayView, ...]

    @property
    def values(self) -> tuple[str, ...]:
        found: list[str] = []
        seen: set[str] = set()
        for rule in self.rules:
            for value in rule.values:
                if value not in seen:
                    seen.add(value)
                    found.append(value)
        return tuple(found)


@dataclass(frozen=True)
class Inventory:
    sentinel_name: str
    sentinel_id: str
    policies: tuple[PolicyView, ...]
    gateway_error: str = ""

    @property
    def addresses(self) -> set[str]:
        found: set[str] = set()
        for policy in self.policies:
            found.update(policy.values)
        return found


@dataclass(frozen=True)
class LiveIncident:
    id: str
    number: str
    title: str
    severity: str
    status: str
    created: str
    arm_id: str
    ips: tuple[str, ...]


class SentinelAzure:
    """ARM reads plus the in-process block engine. Page handlers do not PUT the WAF."""

    def __init__(
        self,
        settings: Settings,
        http: httpx.Client | None = None,
        token=None,
        block: Callable[[object], tuple[int, dict]] | None = None,
    ) -> None:
        self.settings = settings
        self.http = http or httpx.Client(timeout=30.0)
        self._token = token or _msi_token
        self.block = block or _engine_payload

    def list_open(self) -> list[LiveIncident]:
        # api-version has to travel in params. A URL that already has a query
        # string loses it when httpx is also given params.
        document = self._arm(
            "GET",
            self._incidents(),
            params={
                "api-version": INCIDENT_API,
                "$filter": "properties/status eq 'Active' or properties/status eq 'New'",
                "$top": "50",
            },
        )
        rows: list[LiveIncident] = []
        pages = 0
        while isinstance(document, dict) and pages < 3:
            pages += 1
            for item in document.get("value") or []:
                if not isinstance(item, dict):
                    continue
                incident = _incident(item)
                if incident.id:
                    rows.append(incident)
            nxt = document.get("nextLink")
            if not isinstance(nxt, str) or not nxt.startswith("https://management.azure.com/"):
                break
            document = self._arm("GET", nxt)
        enriched = []
        for incident in rows:
            enriched.append(_with_ips(incident, self.ips_for(incident.id)))
        enriched.sort(key=lambda item: item.created, reverse=True)
        return enriched

    def get(self, incident_id: str) -> LiveIncident:
        document = self._arm("GET", self._incidents() + "/" + incident_id + "?api-version=" + INCIDENT_API)
        incident = _incident(document)
        return _with_ips(incident, self.ips_for(incident_id))

    def ips_for(self, incident_id: str) -> tuple[str, ...]:
        document = self._arm(
            "POST",
            self._incidents() + "/" + incident_id + "/entities?api-version=" + INCIDENT_API,
            body={},
        )
        found: list[str] = []
        entities = document.get("entities") or document.get("value") or []
        for entity in entities:
            if not isinstance(entity, dict) or entity.get("kind") != "Ip":
                continue
            properties = entity.get("properties") or {}
            host = _host(properties.get("address") or properties.get("ipAddress"))
            if host and host not in found:
                found.append(host)
        return tuple(found)

    def inventory(self) -> Inventory:
        settings = self.settings
        sentinel_id = (
            "/subscriptions/"
            + settings.subscription_id
            + "/resourceGroups/"
            + settings.resource_group
            + "/providers/Microsoft.OperationalInsights/workspaces/"
            + settings.workspace_name
        )
        document = None
        for item in self._policy_documents():
            if str(item.get("id") or "").casefold() == settings.waf_policy_id.casefold():
                document = item
                break
        if document is None:
            document = self._policy(settings.waf_policy_id)
        resource_id = str(document.get("id") or settings.waf_policy_id)
        policy = PolicyView(
            name=str(document.get("name") or resource_id.rsplit("/", 1)[-1]),
            resource_id=resource_id,
            rules=_block_rules(document, settings.block_rule_name),
            gateways=(),
        )
        gateway_error = ""
        try:
            gateways = self._gateways()
        except AzureCallError as exc:
            gateways = []
            gateway_error = str(exc)
        matched = tuple(
            GatewayView(name, url)
            for policy_id, name, url in gateways
            if policy_id.casefold() == policy.resource_id.casefold()
        )
        attached = PolicyView(policy.name, policy.resource_id, policy.rules, matched)
        return Inventory(settings.workspace_name, sentinel_id, (attached,), gateway_error)

    def block_values(self) -> tuple[str, ...]:
        return tuple(sorted(self.inventory().addresses))

    def _policy_documents(self) -> list[dict]:
        try:
            document = self._arm(
                "GET",
                self._collection("Microsoft.Network/applicationGatewayWebApplicationFirewallPolicies"),
                params={"api-version": POLICY_API},
            )
        except AzureCallError:
            return [self._policy(self.settings.waf_policy_id)]
        values = document.get("value")
        if not isinstance(values, list):
            return [self._policy(self.settings.waf_policy_id)]
        return [item for item in values if isinstance(item, dict)]

    def _policy(self, resource_id: str) -> dict:
        document = self._arm("GET", "https://management.azure.com" + resource_id, params={"api-version": POLICY_API})
        document.setdefault("id", resource_id)
        document.setdefault("name", resource_id.rsplit("/", 1)[-1])
        return document

    def _gateways(self) -> list[tuple[str, str, str]]:
        document = self._arm(
            "GET",
            self._collection("Microsoft.Network/applicationGateways"),
            params={"api-version": POLICY_API},
        )
        found = []
        for gateway in document.get("value") or []:
            if not isinstance(gateway, dict):
                continue
            properties = gateway.get("properties") or {}
            policy_id = str((properties.get("firewallPolicy") or {}).get("id") or "")
            if not policy_id:
                continue
            name = str(gateway.get("name") or "gateway")
            for address in self._gateway_addresses(properties):
                found.append((policy_id, name, "http://" + address))
        return found

    def _gateway_addresses(self, properties: dict) -> list[str]:
        addresses = []
        for item in properties.get("frontendIPConfigurations") or []:
            if not isinstance(item, dict):
                continue
            nested = item.get("properties") if isinstance(item.get("properties"), dict) else {}
            public = nested.get("publicIPAddress") or item.get("publicIPAddress") or {}
            public_id = public.get("id") if isinstance(public, dict) else None
            if not isinstance(public_id, str) or not public_id.startswith("/"):
                continue
            address = self._public_address(public_id)
            if address and address not in addresses:
                addresses.append(address)
        return addresses

    def _public_address(self, resource_id: str) -> str:
        document = self._arm("GET", "https://management.azure.com" + resource_id, params={"api-version": POLICY_API})
        address = (document.get("properties") or {}).get("ipAddress")
        return address if isinstance(address, str) else ""

    def _collection(self, provider: str) -> str:
        settings = self.settings
        return (
            "https://management.azure.com/subscriptions/"
            + quote(settings.subscription_id, safe="")
            + "/resourceGroups/"
            + quote(settings.resource_group, safe="")
            + "/providers/"
            + provider
        )

    def enforce(self, incident: LiveIncident) -> dict:
        if not incident.ips:
            raise AzureCallError("this incident has no IPv4 address")
        if not incident.arm_id.startswith("/"):
            raise AzureCallError("the incident resource id is missing")
        return self._call_block(
            {
                "incidentArmId": incident.arm_id,
                "incidentNumber": incident.number,
                "incidentTitle": incident.title,
                "ipEntities": list(incident.ips),
                "execution": "enforce",
            }
        )

    def change_block(self, address: str, operation: str) -> dict:
        return self._call_block({"operation": operation, "address": address, "execution": "enforce"})

    def _call_block(self, payload: dict) -> dict:
        status, body = self.block(payload)
        if not isinstance(body, dict):
            raise AzureCallError("the block service did not return JSON")
        if status >= 400:
            reason = body.get("reason") if isinstance(body.get("reason"), str) else ""
            reason = " ".join(reason.split())[:300]
            raise AzureCallError(f"The block service returned HTTP {status}. {reason}".strip())
        return body

    def dismiss(self, incident: LiveIncident, actor: str) -> None:
        addresses = ", ".join(incident.ips) or "no IPv4 address"
        message = f"{actor} chose not to block {addresses}. Closed from the operations app."
        self._arm(
            "PUT",
            self._incidents() + f"/{incident.id}/comments/{uuid.uuid4()}?api-version=" + INCIDENT_API,
            body={"properties": {"message": message}},
        )
        current = self._arm("GET", self._incidents() + f"/{incident.id}?api-version=" + INCIDENT_API)
        properties = current.get("properties") if isinstance(current, dict) else {}
        if not isinstance(properties, dict):
            properties = {}
        updated: dict = {
            "title": properties.get("title") or incident.title or "incident",
            "severity": properties.get("severity") or incident.severity or "Medium",
            "status": "Closed",
            "classification": "BenignPositive",
            "classificationReason": "SuspiciousButExpected",
            "classificationComment": message,
        }
        if isinstance(properties.get("description"), str):
            updated["description"] = properties["description"]
        if isinstance(properties.get("owner"), dict):
            updated["owner"] = properties["owner"]
        if isinstance(properties.get("labels"), list):
            updated["labels"] = properties["labels"]
        self._arm(
            "PUT",
            self._incidents() + f"/{incident.id}?api-version=" + INCIDENT_API,
            body={"properties": updated},
        )

    def _incidents(self) -> str:
        settings = self.settings
        return (
            "https://management.azure.com/subscriptions/"
            + quote(settings.subscription_id, safe="")
            + "/resourceGroups/"
            + quote(settings.resource_group, safe="")
            + "/providers/Microsoft.OperationalInsights/workspaces/"
            + quote(settings.workspace_name, safe="")
            + "/providers/Microsoft.SecurityInsights/incidents"
        )

    def _arm(self, method: str, url: str, body=None, params=None) -> dict:
        response = self.http.request(
            method,
            url,
            headers={"Authorization": "Bearer " + self._token(), "Content-Type": "application/json"},
            json=body,
            params=params,
        )
        if response.status_code >= 400:
            raise AzureCallError(_public_error(response))
        if not response.content:
            return {}
        try:
            document = response.json()
        except ValueError as exc:
            raise AzureCallError("Azure returned a response that is not JSON") from exc
        if not isinstance(document, dict):
            raise AzureCallError("Azure returned a response that is not JSON")
        return document


def build_live_app(settings: Settings, azure: SentinelAzure | None = None) -> FastAPI:
    app = FastAPI(title="ASE Sentinel operations", version="1.0.0")
    app.state.settings = settings
    app.state.azure = azure or SentinelAzure(settings)
    install_errors(app)
    app.include_router(_routes())
    app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")
    return app


def _engine_payload(payload: object) -> tuple[int, dict]:
    from sentinel_waf_block.service import execute_payload

    return execute_payload(payload)


def _api_key_ok(request: Request) -> bool:
    expected = request.app.state.settings.block_api_key
    provided = request.headers.get("x-functions-key", "")
    if not expected or not provided:
        return False
    try:
        return hmac.compare_digest(provided.encode(), expected.encode())
    except Exception:
        return False


def _routes():
    from fastapi import APIRouter, Form

    ui = APIRouter()

    @ui.get("/health")
    def health() -> dict:
        return {"status": "ok", "liveAzure": True, "sql": False}

    @ui.post("/api/SentinelWafAutoBlock")
    async def block_api(request: Request):
        # Easy Auth excludes this path. The header is the playbook shared secret.
        if not _api_key_ok(request):
            return JSONResponse(
                {"status": "validation-failed", "changed": False, "reason": "unauthorized"},
                status_code=401,
            )
        try:
            payload = await request.json()
        except Exception:
            return JSONResponse(
                {"status": "validation-failed", "changed": False, "reason": "request body is not JSON"},
                status_code=400,
            )
        status, body = request.app.state.azure.block(payload)
        return JSONResponse(body, status_code=status)

    @ui.get("/login")
    def login_form(request: Request):
        return _render(request, "login.html")

    @ui.post("/login")
    def login(request: Request, email: str = Form(...), password: str = Form(...)):
        try:
            token = login_local(request.app.state.settings, email, password)
        except OpsError as exc:
            return RedirectResponse("/login?error=" + quote(str(exc)), status_code=303)
        response = RedirectResponse("/", status_code=303)
        response.set_cookie(COOKIE, token, httponly=True, samesite="lax")
        return response

    @ui.post("/logout")
    def logout() -> RedirectResponse:
        response = RedirectResponse("/", status_code=303)
        response.delete_cookie(COOKIE)
        return response

    @ui.get("/")
    def home(request: Request):
        if principal_from_request(request) is None:
            return RedirectResponse("/login", status_code=303)
        try:
            incidents = request.app.state.azure.list_open()
            inventory = request.app.state.azure.inventory()
        except AzureCallError as exc:
            return _render(request, "live_home.html", rows=[], pending=0, blocks=0, inventory=None, load_error=str(exc))
        blocked = inventory.addresses
        rows = [_row(item, blocked) for item in incidents]
        pending = sum(1 for row in rows if not row["on_block_list"])
        return _render(
            request,
            "live_home.html",
            rows=rows,
            pending=pending,
            blocks=len(blocked),
            inventory=inventory,
            load_error="",
        )

    @ui.get("/incidents/{incident_id}")
    def incident_detail(request: Request, incident_id: str):
        if principal_from_request(request) is None:
            return RedirectResponse("/login", status_code=303)
        if not _guid(incident_id):
            return _render(
                request,
                "live_incident.html",
                incident=None,
                on_block_list=False,
                can_decide=False,
                inventory=None,
            )
        try:
            incident = request.app.state.azure.get(incident_id)
            inventory = request.app.state.azure.inventory()
        except AzureCallError as exc:
            return _render(
                request,
                "live_incident.html",
                incident=None,
                on_block_list=False,
                can_decide=False,
                inventory=None,
                load_error=str(exc),
            )
        actor = principal_from_request(request)
        return _render(
            request,
            "live_incident.html",
            incident=incident,
            on_block_list=_on_block_list(incident.ips, inventory.addresses),
            can_decide=actor is not None and bool(actor.roles & DECISION_ROLES),
            inventory=inventory,
            load_error="",
        )

    @ui.post("/incidents/{incident_id}/block")
    def block(request: Request, incident_id: str):
        actor = _decision_actor(request)
        if isinstance(actor, RedirectResponse):
            return actor
        if not _guid(incident_id):
            return RedirectResponse("/?error=" + quote("Unknown incident"), status_code=303)
        try:
            incident = request.app.state.azure.get(incident_id)
            result = request.app.state.azure.enforce(incident)
        except AzureCallError as exc:
            return RedirectResponse(f"/incidents/{incident_id}?error=" + quote(str(exc)), status_code=303)
        status = str(result.get("status") or "")
        if status not in {"blocked", "already-blocked"}:
            reason = str(result.get("reason") or status or "the block service did not write the policy")
            return RedirectResponse(f"/incidents/{incident_id}?error=" + quote(reason[:300]), status_code=303)
        message = "The address is on SentinelAutoBlock." if status == "blocked" else "The address was already on SentinelAutoBlock."
        if result.get("notify_error"):
            message += " The Teams notification was not delivered."
        return RedirectResponse(f"/incidents/{incident_id}?message=" + quote(message), status_code=303)

    @ui.post("/incidents/{incident_id}/dismiss")
    def dismiss(request: Request, incident_id: str):
        actor = _decision_actor(request)
        if isinstance(actor, RedirectResponse):
            return actor
        if not _guid(incident_id):
            return RedirectResponse("/?error=" + quote("Unknown incident"), status_code=303)
        try:
            incident = request.app.state.azure.get(incident_id)
            request.app.state.azure.dismiss(incident, actor.name)
        except AzureCallError as exc:
            return RedirectResponse(f"/incidents/{incident_id}?error=" + quote(str(exc)), status_code=303)
        return RedirectResponse("/?message=" + quote("Incident closed. The WAF policy was not changed."), status_code=303)

    @ui.get("/blocks")
    def blocks(request: Request):
        if principal_from_request(request) is None:
            return RedirectResponse("/login", status_code=303)
        try:
            inventory = request.app.state.azure.inventory()
        except AzureCallError as exc:
            return _render(request, "live_blocks.html", inventory=None, load_error=str(exc))
        return _render(request, "live_blocks.html", inventory=inventory, load_error="")

    @ui.post("/blocks")
    def add_block(request: Request, address: str = Form(...)):
        return _edit_block(request, address, "add")

    @ui.post("/blocks/remove")
    def remove_block(request: Request, address: str = Form(...)):
        return _edit_block(request, address, "remove")

    return ui


def _edit_block(request: Request, address: str, operation: str):
    actor = _decision_actor(request)
    if isinstance(actor, RedirectResponse):
        return actor
    try:
        result = request.app.state.azure.change_block(address, operation)
    except AzureCallError as exc:
        return RedirectResponse("/blocks?error=" + quote(str(exc)), status_code=303)
    status = str(result.get("status") or "")
    stored = result.get("new_addresses") or result.get("candidate_addresses") or [address]
    shown = stored[0] if isinstance(stored, list) and stored else address
    if operation == "add" and status == "blocked":
        rule = str(result.get("written_rule") or "the block list")
        message = f"Added {shown} to {rule}."
    elif operation == "add" and status == "already-blocked":
        message = f"{shown} is already on the block list."
    elif operation == "remove" and status == "removed":
        rule = str(result.get("written_rule") or "the block list")
        message = f"Removed {shown} from {rule}."
    elif operation == "remove" and status == "not-listed":
        message = f"{shown} is not on a block list."
    else:
        reason = str(result.get("reason") or status or "the block service did not change the block list")
        return RedirectResponse("/blocks?error=" + quote(reason[:300]), status_code=303)
    if result.get("notify_error"):
        message += " The Teams notification was not delivered."
    return RedirectResponse("/blocks?message=" + quote(message), status_code=303)


def _decision_actor(request: Request):
    actor = principal_from_request(request)
    if actor is None:
        return RedirectResponse("/login", status_code=303)
    if not (actor.roles & DECISION_ROLES):
        return RedirectResponse("/?error=" + quote("Sign-in does not allow this decision"), status_code=303)
    return actor


def _render(request: Request, name: str, **extra):
    return TEMPLATES.TemplateResponse(
        request,
        name,
        {
            "principal": principal_from_request(request),
            "users": sorted(LOCAL_USERS),
            "message": request.query_params.get("message", ""),
            "error": request.query_params.get("error", ""),
            "live": True,
            "per_policy": MATCH_VALUES_PER_POLICY,
            **extra,
        },
    )


def _row(incident: LiveIncident, blocked: set[str]) -> dict:
    return {
        "id": incident.id,
        "number": incident.number,
        "title": incident.title,
        "severity": incident.severity,
        "status": incident.status,
        "created": incident.created,
        "ip": ", ".join(incident.ips),
        "on_block_list": _on_block_list(incident.ips, blocked),
    }


def _on_block_list(ips: tuple[str, ...], entries: set[str]) -> bool:
    if not ips:
        return False
    return all(_entry_covers(entries, ip) for ip in ips)


def _entry_covers(entries: set[str], host: str) -> bool:
    if host in entries:
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    for entry in entries:
        if "/" not in entry:
            continue
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue
        if address in network:
            return True
    return False


def _incident(item: dict) -> LiveIncident:
    properties = item.get("properties") or {}
    if not isinstance(properties, dict):
        properties = {}
    number = properties.get("incidentNumber")
    return LiveIncident(
        id=str(item.get("name") or ""),
        number="" if number is None else str(number),
        title=str(properties.get("title") or ""),
        severity=str(properties.get("severity") or ""),
        status=str(properties.get("status") or ""),
        created=str(properties.get("createdTimeUtc") or ""),
        arm_id=str(item.get("id") or ""),
        ips=(),
    )


def _with_ips(incident: LiveIncident, ips: tuple[str, ...]) -> LiveIncident:
    return LiveIncident(
        incident.id,
        incident.number,
        incident.title,
        incident.severity,
        incident.status,
        incident.created,
        incident.arm_id,
        ips,
    )


def _is_block_list_name(name: object, base: str) -> bool:
    return isinstance(name, str) and base != "" and (name == base or name.startswith(base + "-"))


def _block_rules(document: dict, rule_name: str) -> tuple[RuleView, ...]:
    rules = (document.get("properties") or {}).get("customRules")
    if not isinstance(rules, list):
        return ()
    found: list[RuleView] = []
    for rule in rules:
        if not isinstance(rule, dict) or not _is_block_list_name(rule.get("name"), rule_name):
            continue
        conditions = rule.get("matchConditions") or []
        values: list[str] = []
        if conditions and isinstance(conditions[0], dict):
            raw = conditions[0].get("matchValues") or []
            if not isinstance(raw, list):
                raise AzureCallError("matchValues is not an array")
            values = [item for item in raw if isinstance(item, str)]
        found.append(RuleView(str(rule.get("name")), tuple(values)))
    found.sort(key=lambda item: _rule_sort_key(item.name, rule_name))
    return tuple(found)


def _rule_sort_key(name: str, base: str) -> tuple[int, int, str]:
    if name == base:
        return (0, 0, name)
    suffix = name[len(base) + 1 :]
    if suffix.isdigit():
        return (1, int(suffix), name)
    return (2, 0, name)


def _host(value: object) -> str:
    if not isinstance(value, str):
        return ""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return ""
    if not isinstance(address, ipaddress.IPv4Address) or str(address) != value:
        return ""
    return value


def _guid(value: str) -> bool:
    if len(value) != 36:
        return False
    return all(character in "0123456789abcdefABCDEF-" for character in value)


def _public_error(response: httpx.Response) -> str:
    message = ""
    try:
        body = response.json()
    except ValueError:
        body = None
    if isinstance(body, dict):
        error = body.get("error")
        if isinstance(error, dict) and isinstance(error.get("message"), str):
            message = error["message"]
        elif isinstance(body.get("reason"), str):
            message = body["reason"]
    message = " ".join(message.split())[:300]
    return f"Azure returned HTTP {response.status_code}. {message}".strip()


def _msi_token() -> str:
    from azure.identity import DefaultAzureCredential

    return DefaultAzureCredential(exclude_interactive_browser_credential=True).get_token(
        "https://management.azure.com/.default"
    ).token
