"""WAF gateway port. The memory gateway is the default and does not call Azure."""

from __future__ import annotations

import itertools
import threading
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ObservedRule:
    name: str
    priority: int
    operator: str
    values: tuple[str, ...]
    action: str = "Block"


@dataclass
class ObservedPolicy:
    policy_key: str
    name: str
    provider: str
    location: str
    tags: dict[str, str]
    etag: str
    rules: tuple[ObservedRule, ...]
    gateway_names: tuple[str, ...] = ()
    live: bool = False


class WafConflict(RuntimeError):
    pass


class MemoryWaf:
    """Fixture policy. live is always false."""

    def __init__(self, policy: ObservedPolicy) -> None:
        self._policy = policy
        self._lock = threading.Lock()
        self._serial = itertools.count(1)
        self.puts = 0

    def get(self, policy_key: str) -> ObservedPolicy:
        with self._lock:
            if policy_key != self._policy.policy_key:
                raise KeyError(policy_key)
            return self._policy

    def put(self, policy_key: str, etag: str, rules: tuple[ObservedRule, ...]) -> ObservedPolicy:
        with self._lock:
            if policy_key != self._policy.policy_key:
                raise KeyError(policy_key)
            if etag != self._policy.etag:
                raise WafConflict("the WAF policy changed before this write")
            self.puts += 1
            self._policy = ObservedPolicy(
                policy_key=self._policy.policy_key,
                name=self._policy.name,
                provider=self._policy.provider,
                location=self._policy.location,
                tags=dict(self._policy.tags),
                etag=f"etag-{next(self._serial)}",
                rules=rules,
                gateway_names=self._policy.gateway_names,
                live=False,
            )
            return self._policy


def fixture_policy() -> ObservedPolicy:
    """Addresses observed on SentinelAutoBlock on 29 October 2026.

    This is a local copy for the UI. It is not a read of the live policy.
    """

    return ObservedPolicy(
        policy_key="local-wafpol-ase-sentinel-poc",
        name="wafpol-ase-sentinel-poc",
        provider="ApplicationGateway",
        location="eastus",
        tags={"ase-sentinel-poc": "fixture"},
        etag="etag-0",
        gateway_names=("agw-ase-sentinel-poc",),
        rules=(
            ObservedRule(
                "SentinelAutoBlock",
                10,
                "IPMatch",
                ("49.216.110.148", "4.194.122.136", "4.194.122.144", "4.194.122.162"),
            ),
            ObservedRule("PocSimulatedProbe", 50, "Contains", ("ase-poc-probe",)),
        ),
    )


@dataclass
class DiscoveryCatalog:
    """Static catalog. source=fixture means Azure was not queried."""

    subscriptions: list[dict[str, str]] = field(default_factory=list)
    resource_groups: list[dict[str, str]] = field(default_factory=list)
    workspaces: list[dict[str, str]] = field(default_factory=list)
    gateways: list[dict[str, str]] = field(default_factory=list)
    policies: list[dict[str, str]] = field(default_factory=list)


def fixture_catalog() -> DiscoveryCatalog:
    subscription = "ae4654a2-8a96-431c-ad3d-176ae51ec9d8"
    return DiscoveryCatalog(
        subscriptions=[
            {
                "id": subscription,
                "name": "ME-MngEnvMCAP591832-v-henchang-1",
                "source": "fixture",
            }
        ],
        resource_groups=[
            {
                "name": "rg-ase-sentinel-poc",
                "subscriptionId": subscription,
                "source": "fixture",
            }
        ],
        workspaces=[
            {
                "name": "log-ase-sentinel-poc-7ttpll74bmhiq",
                "sentinel": "enabled",
                "subscriptionId": subscription,
                "resourceGroup": "rg-ase-sentinel-poc",
                "source": "fixture",
            }
        ],
        gateways=[
            {
                "name": "agw-ase-sentinel-poc",
                "publicIp": "20.169.234.86",
                "provider": "ApplicationGateway",
                "source": "fixture",
            }
        ],
        policies=[
            {
                "policyKey": "local-wafpol-ase-sentinel-poc",
                "name": "wafpol-ase-sentinel-poc",
                "provider": "ApplicationGateway",
                "gateway": "agw-ase-sentinel-poc",
                "liveResourceNote": "Fixture only. The live policy was not read by this process.",
                "source": "fixture",
            }
        ],
    )
