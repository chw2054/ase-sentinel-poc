"""Incident, approval, and block-list operations.

The Logic App is not involved here. A decision becomes a WAF write only
inside approve(), after the approval row is claimed.
"""

from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.cidr import (
    PLATFORM_MATCH_VALUES,
    CidrError,
    overlaps_protected,
    parse_network,
    render,
    subtract_host,
)
from app.config import Settings
from app.orm import (
    ApprovalRow,
    AuditRow,
    BlockRow,
    ConfigRow,
    IncidentRow,
    SuppressionRow,
    utcnow,
)
from app.policy import pack_rules
from app.waf import MemoryWaf, ObservedPolicy, ObservedRule, WafConflict

PENDING = "pending"
APPROVED = "approved"
REJECTED = "rejected"
EXPIRED = "expired"
CANCELED = "canceled"
EXECUTION_PENDING = "execution_pending"
EXECUTED = "executed"
EXECUTION_FAILED = "execution_failed"


@dataclass(frozen=True)
class Principal:
    name: str
    roles: frozenset[str]
    kind: str = "user"


class OpsError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


class Ops:
    def __init__(self, settings: Settings, waf: MemoryWaf) -> None:
        self.settings = settings
        self.waf = waf

    def audit(self, db: Session, actor: str, action: str, target: str, detail: dict) -> None:
        db.add(
            AuditRow(
                id=str(uuid.uuid4()),
                actor=actor,
                action=action,
                target=target,
                detail=detail,
            )
        )

    def sync_external(self, db: Session) -> None:
        policy = self.waf.get(self._policy_key(db))
        rule = self._block_rule(policy)
        observed = set(rule.values)
        rows = db.scalars(select(BlockRow).where(BlockRow.policy_key == policy.policy_key)).all()
        known = {row.cidr for row in rows if row.active}
        for value in rule.values:
            if value in known:
                continue
            db.add(
                BlockRow(
                    id=str(uuid.uuid4()),
                    policy_key=policy.policy_key,
                    rule_name=rule.name,
                    cidr=value,
                    ownership="external",
                    active=True,
                    reason="Observed on the fixture rule. Not written by this Web App.",
                )
            )
        for row in rows:
            if row.ownership == "external" and row.active and row.cidr not in observed:
                row.active = False

    def ingest(self, db: Session, body: dict, correlation_id: str) -> dict:
        sentinel_id = str(body.get("sentinelIncidentId") or "")
        if not sentinel_id:
            raise OpsError(400, "validation", "sentinelIncidentId is required")
        existing = db.scalar(select(IncidentRow).where(IncidentRow.sentinel_id == sentinel_id))
        if existing is not None:
            self.audit(db, "integration", "incident_duplicate", existing.id, {"sentinelId": sentinel_id})
            return self._incident_payload(db, existing, duplicate=True)
        addresses = body.get("ipAddresses") or []
        if not isinstance(addresses, list) or len(addresses) != 1 or not isinstance(addresses[0], str):
            raise OpsError(400, "validation", "ipAddresses must contain one IPv4 host")
        try:
            network = parse_network(addresses[0])
        except CidrError as exc:
            raise OpsError(400, exc.code, str(exc)) from exc
        if network.prefixlen != 32:
            raise OpsError(400, "invalid_network", "an incident entity must be one IPv4 host")
        if overlaps_protected(network):
            raise OpsError(400, "protected", "that address is in a protected range")
        rendered = render(network)
        incident = IncidentRow(
            id=str(uuid.uuid4()),
            sentinel_id=sentinel_id,
            incident_number=str(body.get("incidentNumber") or ""),
            title=str(body.get("title") or ""),
            severity=str(body.get("severity") or ""),
            sentinel_status=str(body.get("sentinelStatus") or ""),
            sentinel_url=str(body.get("sentinelUrl") or ""),
            ip_address=rendered,
            processing_status="received",
            correlation_id=correlation_id,
            detail={"source": "logic-app"},
        )
        db.add(incident)
        db.flush()
        if self._suppressed(db, rendered):
            incident.processing_status = "suppressed"
            self.audit(db, "integration", "incident_suppressed", incident.id, {"cidr": rendered})
            return self._incident_payload(db, incident, duplicate=False)
        approval = self._open_approval(db, incident, [rendered], "Sentinel incident proposed a block")
        incident.processing_status = "pending_approval"
        self.audit(db, "integration", "approval_opened", approval.id, {"incidentId": incident.id})
        return self._incident_payload(db, incident, duplicate=False)

    def retry(self, db: Session, incident_id: str, actor: Principal) -> dict:
        self._need(actor, "operator", "admin")
        incident = self._incident(db, incident_id)
        approvals = self._approvals_for(db, incident.id)
        if any(row.state == EXECUTED for row in approvals):
            raise OpsError(409, "already_executed", "this incident already wrote the WAF")
        if any(row.state in {PENDING, EXECUTION_PENDING} for row in approvals):
            raise OpsError(409, "approval_open", "an approval is already open")
        if not incident.ip_address:
            raise OpsError(400, "validation", "the incident has no address to retry")
        if self._suppressed(db, incident.ip_address):
            raise OpsError(409, "suppressed", "that address was removed and is suppressed")
        approval = self._open_approval(db, incident, [incident.ip_address], "Operator retry")
        incident.processing_status = "pending_approval"
        self.audit(db, actor.name, "approval_retried", approval.id, {})
        return self._approval_payload(db, approval)

    def decide(
        self,
        db: Session,
        approval_id: str,
        actor: Principal,
        decision: str,
        version: int,
        comment: str,
    ) -> dict:
        self._need(actor, "approver", "admin")
        if decision not in {"approve", "reject"}:
            raise OpsError(400, "validation", "decision must be approve or reject")
        approval = self._approval(db, approval_id)
        if approval.state != PENDING or approval.version != version:
            raise OpsError(409, "conflict", "the approval changed or is no longer pending")
        approval.version = version + 1
        approval.reviewer = actor.name
        approval.reason = comment
        approval.decided_at = utcnow()
        incident = self._incident(db, approval.incident_id)
        if decision == "reject":
            approval.state = REJECTED
            incident.processing_status = "rejected"
            self.audit(db, actor.name, "approval_rejected", approval.id, {})
            return self._approval_payload(db, approval)
        approval.state = EXECUTION_PENDING
        db.flush()
        try:
            result = self._apply_managed(db, actor, incident, approval)
        except (OpsError, CidrError, WafConflict) as exc:
            approval.state = EXECUTION_FAILED
            approval.execution = {"error": str(exc)}
            incident.processing_status = "execution_failed"
            self.audit(db, actor.name, "execution_failed", approval.id, {"error": str(exc)})
            if isinstance(exc, OpsError):
                raise
            raise OpsError(409, "execution_failed", str(exc)) from exc
        approval.state = EXECUTED
        approval.execution = result
        incident.processing_status = "executed"
        self.audit(db, actor.name, "approval_executed", approval.id, result)
        return self._approval_payload(db, approval)

    def resume_execution(self, db: Session, approval_id: str, actor: Principal) -> dict:
        """Finish a write that was claimed but not recorded, without a second add."""

        self._need(actor, "operator", "admin")
        approval = self._approval(db, approval_id)
        if approval.state not in {EXECUTION_PENDING, EXECUTION_FAILED}:
            raise OpsError(409, "conflict", "this approval is not waiting on execution")
        incident = self._incident(db, approval.incident_id)
        try:
            result = self._apply_managed(db, actor, incident, approval)
        except (OpsError, CidrError, WafConflict) as exc:
            approval.state = EXECUTION_FAILED
            approval.execution = {"error": str(exc)}
            raise OpsError(409, "execution_failed", str(exc)) from exc
        approval.state = EXECUTED
        approval.execution = result
        incident.processing_status = "executed"
        self.audit(db, actor.name, "execution_resumed", approval.id, result)
        return self._approval_payload(db, approval)

    def add_block(self, db: Session, actor: Principal, value: str, reason: str, apply: bool) -> dict:
        self._need(actor, "operator", "admin")
        network = self._candidate(value)
        preview = self._preview(db, extra=[network], remove=None)
        if not apply:
            return preview
        self._insert_managed(db, render(network), reason, "", "")
        result = self._push(db, actor, "block_added")
        result["preview"] = preview
        return result

    def remove_block(
        self,
        db: Session,
        actor: Principal,
        entry_id: str,
        *,
        host: str,
        split_external: bool,
        apply: bool,
    ) -> dict:
        self._need(actor, "operator", "admin")
        row = db.get(BlockRow, entry_id)
        if row is None or not row.active:
            raise OpsError(404, "not_found", "block entry not found")
        current = parse_network(row.cidr)
        host_address = None
        if host:
            host_network = parse_network(host)
            if host_network.prefixlen != 32:
                raise OpsError(400, "validation", "unblock a single host, or the whole entry")
            host_address = host_network.network_address
            if host_address not in current:
                raise OpsError(400, "not_covered", "that host is not inside this entry")
            if current.prefixlen != 32 and row.ownership == "external" and not split_external:
                raise OpsError(
                    409,
                    "external_cidr",
                    "that host sits inside an external CIDR. Confirm the split to rewrite only that entry.",
                )
        preview = self._preview(db, extra=[], remove=(row, host_address))
        if not apply:
            return preview
        self._mutate_removal(db, row, host_address, actor)
        result = self._push(db, actor, "block_removed")
        result["preview"] = preview
        return result

    def reconcile(self, db: Session, actor: Principal, repair: bool) -> dict:
        self._need(actor, "operator", "admin")
        policy = self.waf.get(self._policy_key(db))
        desired = self._desired_values(db, policy)
        observed = list(self._block_rule(policy).values)
        drift = observed != desired
        report = {"drift": drift, "observed": observed, "desired": desired, "repaired": False}
        if drift and repair:
            self._push(db, actor, "reconcile_repair")
            report["repaired"] = True
        self.audit(db, actor.name, "reconcile", policy.policy_key, {"drift": drift, "repair": repair})
        return report

    def configuration(self, db: Session) -> dict:
        row = self._config(db)
        return {"confirmed": row.confirmed, "updatedBy": row.updated_by, "document": row.document}

    def save_configuration(self, db: Session, actor: Principal, document: dict) -> dict:
        self._need(actor, "admin", "operator")
        provider = document.get("wafProvider")
        if provider not in {None, "ApplicationGateway"}:
            raise OpsError(400, "wrong_provider", "this Web App manages Application Gateway WAF policies")
        row = self._config(db)
        row.document = document
        row.confirmed = True
        row.updated_by = actor.name
        row.updated_at = utcnow()
        self.audit(db, actor.name, "configuration_saved", "configuration", {"keys": sorted(document)})
        return self.configuration(db)

    def _apply_managed(self, db: Session, actor: Principal, incident: IncidentRow, approval: ApprovalRow) -> dict:
        before = list(self._block_rule(self.waf.get(self._policy_key(db))).values)
        for value in approval.proposed:
            if self._suppressed(db, value):
                raise OpsError(409, "suppressed", f"{value} is suppressed")
            if self._covered(db, value):
                continue
            self._insert_managed(
                db,
                value,
                "Approved block",
                incident.id,
                approval.id,
            )
        result = self._push(db, actor, "approval_apply")
        result["changed"] = result["values"] != before
        return result

    def _push(self, db: Session, actor: Principal, action: str) -> dict:
        policy = self.waf.get(self._policy_key(db))
        rule = self._block_rule(policy)
        external = [row.cidr for row in self._active(db, policy.policy_key) if row.ownership == "external"]
        managed_networks = [parse_network(row.cidr) for row in self._active(db, policy.policy_key) if row.ownership == "application"]
        others = [item for item in policy.rules if item.name != rule.name and not item.name.startswith(f"{rule.name}-")]
        occupied_priorities = {item.priority for item in others}
        occupied_names = {item.name for item in others}
        existing_managed = [item.name for item in policy.rules if item.name == rule.name or item.name.startswith(f"{rule.name}-")]
        try:
            packed = pack_rules(
                managed_networks,
                external,
                product_cap=self.settings.product_cap,
                base_name=rule.name,
                base_priority=rule.priority,
                occupied_priorities=occupied_priorities,
                occupied_names=occupied_names,
                existing_managed_names=existing_managed,
            )
        except CidrError as exc:
            raise OpsError(409, exc.code, str(exc)) from exc
        rewritten = {
            item.name: ObservedRule(item.name, item.priority, "IPMatch", item.values)
            for item in packed.rules
        }
        new_rules: list[ObservedRule] = []
        seen: set[str] = set()
        for item in policy.rules:
            if item.name in packed.retired_names:
                continue
            if item.name in rewritten:
                new_rules.append(rewritten[item.name])
                seen.add(item.name)
            else:
                new_rules.append(item)
                seen.add(item.name)
        for item in packed.rules:
            if item.name not in seen:
                new_rules.append(rewritten[item.name])
        try:
            updated = self.waf.put(policy.policy_key, policy.etag, tuple(new_rules))
        except WafConflict as exc:
            fresh = self.waf.get(policy.policy_key)
            raise OpsError(409, "waf_conflict", str(exc) + f" current etag {fresh.etag}") from exc
        self.audit(db, actor.name, action, policy.policy_key, {"etag": updated.etag, "rules": [item.name for item in packed.rules]})
        return {"etag": updated.etag, "values": list(self._block_rule(updated).values), "changed": True}

    def _preview(self, db: Session, extra: list[ipaddress.IPv4Network], remove) -> dict:
        policy = self.waf.get(self._policy_key(db))
        rows = self._active(db, policy.policy_key)
        before = [row.cidr for row in rows]
        managed = [parse_network(row.cidr) for row in rows if row.ownership == "application"]
        external = [row.cidr for row in rows if row.ownership == "external"]
        if remove is not None:
            row, host = remove
            managed = [network for network, item in zip(managed, [item for item in rows if item.ownership == "application"]) if item.id != row.id]
            external = [item.cidr for item in rows if item.ownership == "external" and item.id != row.id]
            network = parse_network(row.cidr)
            if host is not None and network.prefixlen != 32:
                managed.extend(subtract_host([network], host))
        managed.extend(extra)
        packed = pack_rules(
            managed,
            external,
            product_cap=self.settings.product_cap,
            base_name=self.settings.block_rule_name,
            base_priority=self.settings.block_rule_priority,
            occupied_priorities={50},
            occupied_names={"PocSimulatedProbe"},
            existing_managed_names=[self.settings.block_rule_name],
        )
        after = [value for rule in packed.rules for value in rule.values]
        return {
            "before": before,
            "after": after,
            "productCap": self.settings.product_cap,
            "platformCap": PLATFORM_MATCH_VALUES,
            "remaining": self.settings.product_cap - len(after),
        }

    def _mutate_removal(self, db: Session, row: BlockRow, host: ipaddress.IPv4Address | None, actor: Principal) -> None:
        network = parse_network(row.cidr)
        row.active = False
        if host is None or network.prefixlen == 32:
            self._suppress(db, row.policy_key, str(network), actor, "removed entry")
            return
        for piece in subtract_host([network], host):
            self._insert_managed(
                db,
                render(piece),
                f"Remainder after removing {host}",
                row.incident_id,
                row.approval_id,
            )
        self._suppress(db, row.policy_key, str(host), actor, "removed host from CIDR")

    def _insert_managed(self, db: Session, cidr: str, reason: str, incident_id: str, approval_id: str) -> None:
        policy_key = self.waf.get(self._policy_key(db)).policy_key
        existing = db.scalar(
            select(BlockRow).where(
                BlockRow.policy_key == policy_key,
                BlockRow.cidr == cidr,
                BlockRow.ownership == "application",
                BlockRow.active == True,
            )
        )
        if existing is not None:
            return
        db.add(
            BlockRow(
                id=str(uuid.uuid4()),
                policy_key=policy_key,
                rule_name=self.settings.block_rule_name,
                cidr=cidr,
                ownership="application",
                active=True,
                reason=reason,
                incident_id=incident_id,
                approval_id=approval_id,
            )
        )

    def _suppress(self, db: Session, policy_key: str, cidr: str, actor: Principal, reason: str) -> None:
        if self._suppressed(db, cidr):
            return
        db.add(
            SuppressionRow(
                id=str(uuid.uuid4()),
                policy_key=policy_key,
                cidr=cidr,
                reason=reason,
                actor=actor.name,
                active=True,
            )
        )

    def _covered(self, db: Session, value: str) -> bool:
        network = parse_network(value)
        policy_key = self.waf.get(self._policy_key(db)).policy_key
        for row in self._active(db, policy_key):
            if network.subnet_of(parse_network(row.cidr)):
                return True
        return False

    def _suppressed(self, db: Session, cidr: str) -> bool:
        host = parse_network(cidr)
        rows = db.scalars(select(SuppressionRow).where(SuppressionRow.active == True)).all()
        for row in rows:
            if host.network_address in parse_network(row.cidr) or parse_network(row.cidr) == host:
                return True
        return False

    def _open_approval(self, db: Session, incident: IncidentRow, proposed: list[str], reason: str) -> ApprovalRow:
        approval = ApprovalRow(
            id=str(uuid.uuid4()),
            incident_id=incident.id,
            state=PENDING,
            proposed=proposed,
            reason=reason,
            version=1,
            execution={},
        )
        db.add(approval)
        db.flush()
        return approval

    def _desired_values(self, db: Session, policy: ObservedPolicy) -> list[str]:
        external = [row.cidr for row in self._active(db, policy.policy_key) if row.ownership == "external"]
        managed = [parse_network(row.cidr) for row in self._active(db, policy.policy_key) if row.ownership == "application"]
        packed = pack_rules(
            managed,
            external,
            product_cap=self.settings.product_cap,
            base_name=self.settings.block_rule_name,
            base_priority=self.settings.block_rule_priority,
            occupied_priorities={50},
            occupied_names={"PocSimulatedProbe"},
            existing_managed_names=[self.settings.block_rule_name],
        )
        return [value for rule in packed.rules for value in rule.values]

    def _active(self, db: Session, policy_key: str) -> list[BlockRow]:
        return list(
            db.scalars(
                select(BlockRow).where(BlockRow.policy_key == policy_key, BlockRow.active == True)
            ).all()
        )

    def _policy_key(self, db: Session) -> str:
        document = self._config(db).document or {}
        return str(document.get("policyKey") or self.waf.get_default_key())

    def _config(self, db: Session) -> ConfigRow:
        row = db.get(ConfigRow, 1)
        if row is None:
            row = ConfigRow(id=1, document={"policyKey": self.waf.get_default_key(), "wafProvider": "ApplicationGateway"}, confirmed=False)
            db.add(row)
            db.flush()
        return row

    def _block_rule(self, policy: ObservedPolicy) -> ObservedRule:
        for rule in policy.rules:
            if rule.name == self.settings.block_rule_name and rule.operator == "IPMatch":
                return rule
        raise OpsError(409, "rule_missing", "the application block rule is missing")

    def _candidate(self, value: str) -> ipaddress.IPv4Network:
        try:
            network = parse_network(value)
        except CidrError as exc:
            raise OpsError(400, exc.code, str(exc)) from exc
        if overlaps_protected(network):
            raise OpsError(400, "protected", "that network overlaps a protected range")
        return network

    def _incident(self, db: Session, incident_id: str) -> IncidentRow:
        row = db.get(IncidentRow, incident_id)
        if row is None:
            raise OpsError(404, "not_found", "incident not found")
        return row

    def _approval(self, db: Session, approval_id: str) -> ApprovalRow:
        row = db.get(ApprovalRow, approval_id)
        if row is None:
            raise OpsError(404, "not_found", "approval not found")
        return row

    def _approvals_for(self, db: Session, incident_id: str) -> list[ApprovalRow]:
        return list(db.scalars(select(ApprovalRow).where(ApprovalRow.incident_id == incident_id)).all())

    def _need(self, actor: Principal, *roles: str) -> None:
        if actor.roles.isdisjoint(set(roles)):
            raise OpsError(403, "forbidden", "the caller does not have that role")

    def _incident_payload(self, db: Session, incident: IncidentRow, duplicate: bool) -> dict:
        approvals = self._approvals_for(db, incident.id)
        notification = None
        open_approval = next((row for row in approvals if row.state == PENDING), None)
        if open_approval is not None and not duplicate:
            link = f"{self.settings.public_base_url}/approvals/{open_approval.id}"
            notification = {
                "channel": "email",
                "to": self.settings.approver_email,
                "subject": f"ASE POC approval for {incident.ip_address}",
                "body": (
                    f"Review incident {incident.incident_number} ({incident.title}) "
                    f"and decide at {link}. Approving writes {incident.ip_address} "
                    "to the Application Gateway block list."
                ),
                "link": link,
            }
        return {
            "incidentId": incident.id,
            "processingStatus": incident.processing_status,
            "duplicate": duplicate,
            "approvalId": open_approval.id if open_approval else None,
            "notification": notification,
            "correlationId": incident.correlation_id,
        }

    def _approval_payload(self, db: Session, approval: ApprovalRow) -> dict:
        incident = self._incident(db, approval.incident_id)
        return {
            "id": approval.id,
            "state": approval.state,
            "version": approval.version,
            "proposed": approval.proposed,
            "reviewer": approval.reviewer,
            "reason": approval.reason,
            "execution": approval.execution,
            "incident": {
                "id": incident.id,
                "number": incident.incident_number,
                "title": incident.title,
                "severity": incident.severity,
                "sentinelStatus": incident.sentinel_status,
                "sentinelUrl": incident.sentinel_url,
                "ipAddress": incident.ip_address,
                "processingStatus": incident.processing_status,
            },
        }


def seed(db: Session, ops: Ops) -> None:
    ops.sync_external(db)
    if db.get(ConfigRow, 1) is None:
        db.add(
            ConfigRow(
                id=1,
                confirmed=False,
                document={
                    "policyKey": ops.waf.get_default_key(),
                    "wafProvider": "ApplicationGateway",
                    "subscriptionName": "ME-MngEnvMCAP591832-v-henchang-1",
                    "resourceGroup": "rg-ase-sentinel-poc",
                    "workspace": "log-ase-sentinel-poc-7ttpll74bmhiq",
                    "source": "fixture",
                },
            )
        )


# MemoryWaf needs get_default_key. Add it via a small mixin-style assignment.
def _default_key(self: MemoryWaf) -> str:
    return self._policy.policy_key


MemoryWaf.get_default_key = _default_key  # type: ignore[attr-defined]
