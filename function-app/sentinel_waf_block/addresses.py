"""Canonical IPv4 hosts and protected-network membership.

Incident parsing accepts one dotted IPv4 address. Any other text is invalid.
Customer ranges fail closed on prefix lengths the matcher does not allow,
including lengths ``ipaddress`` itself can parse.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

REASON_DIRTY = "empty, CIDR, or whitespace"
REASON_INVALID_V4 = "invalid IPv4"
REASON_BUILTIN_V4 = (
    "protected built-in range (loopback, RFC1918, link-local, "
    "Azure metadata 169.254.169.254, or CGNAT)"
)
REASON_CUSTOMER = "protectedIpRanges"

_V4_PREFIXES = frozenset({8, 16, 24, 32})

_BUILTIN_V4 = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


@dataclass(frozen=True)
class Classification:
    original: str
    canonical: str | None
    reason: str | None


@dataclass(frozen=True)
class ProtectedNetwork:
    source: str
    network: ipaddress.IPv4Network


def _dirty(value: str, *, allow_slash: bool) -> bool:
    if value == "":
        return True
    if any(character.isspace() for character in value):
        return True
    if "," in value or "%" in value:
        return True
    if not allow_slash and "/" in value:
        return True
    return False


def canonical_host(value: str) -> Classification:
    """Classify one incident entity. Does not strip or split the text."""

    if _dirty(value, allow_slash=False):
        return Classification(value, None, REASON_DIRTY)
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return Classification(value, None, REASON_INVALID_V4)
    if not isinstance(parsed, ipaddress.IPv4Address) or str(parsed) != value:
        return Classification(value, None, REASON_INVALID_V4)
    return Classification(value, str(parsed), None)


def parse_protected_ranges(
    entries: object,
) -> tuple[tuple[ProtectedNetwork, ...], tuple[str, ...]]:
    """Return usable networks and the original entries that cannot be used.

    Any invalid entry fails the whole run. Callers must not continue with the
    networks that did parse.
    """

    if isinstance(entries, str) or not isinstance(entries, (list, tuple)):
        return (), ("<protectedIpRanges>",)
    good: list[ProtectedNetwork] = []
    bad: list[str] = []
    for entry in entries:
        if not isinstance(entry, str):
            bad.append(repr(entry))
            continue
        parsed = _parse_one_range(entry)
        if isinstance(parsed, str):
            bad.append(entry)
        else:
            good.append(parsed)
    return tuple(good), tuple(bad)


def _parse_one_range(entry: str) -> ProtectedNetwork | str:
    if _dirty(entry, allow_slash=True) or entry.count("/") > 1:
        return "bad"
    try:
        if "/" not in entry:
            address = ipaddress.ip_address(entry)
            if not isinstance(address, ipaddress.IPv4Address) or str(address) != entry:
                return "bad"
            network = ipaddress.ip_network(f"{address}/32", strict=False)
        else:
            prefix_token = entry.split("/", 1)[1]
            network = ipaddress.ip_network(entry, strict=False)
            # Reject "/08" and other non-canonical prefix spellings.
            if prefix_token != str(network.prefixlen) or network.version != 4:
                return "bad"
    except ValueError:
        return "bad"
    if network.prefixlen not in _V4_PREFIXES:
        return "bad"
    return ProtectedNetwork(entry, network)


def protection_reason(
    canonical: str,
    ranges: tuple[ProtectedNetwork, ...],
    *,
    override: bool,
) -> str | None:
    """Return a rejection reason, or None when the host may be blocked."""

    if override:
        return None
    address = ipaddress.ip_address(canonical)
    for network in _BUILTIN_V4:
        if address in network:
            return REASON_BUILTIN_V4
    for protected in ranges:
        if address in protected.network:
            return REASON_CUSTOMER
    return None
