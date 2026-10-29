"""IPv4 block-list math.

collapse_addresses is used because it covers exactly the addresses it is
given. It does not widen a pair of hosts into a CIDR that also blocks their
neighbors. Protected space is rejected when a candidate overlaps it.
"""

from __future__ import annotations

import ipaddress

PROTECTED = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)

# Microsoft documents 600 IP ranges per match condition on CRS 3.2+.
# This repo also filled a separate CapacityTestBlock rule to 600.
PLATFORM_MATCH_VALUES = 600
MAX_CUSTOM_RULES = 100
PRIORITY_MIN = 1
PRIORITY_MAX = 100


class CidrError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def parse_network(value: str) -> ipaddress.IPv4Network:
    """Accept one canonical IPv4 host or CIDR. Do not strip or rewrite text."""

    if value == "" or any(character.isspace() for character in value) or "," in value or "%" in value:
        raise CidrError("invalid_network", "value must be one IPv4 host or CIDR")
    try:
        if "/" in value:
            network = ipaddress.ip_network(value, strict=True)
        else:
            address = ipaddress.ip_address(value)
            if not isinstance(address, ipaddress.IPv4Address) or str(address) != value:
                raise CidrError("invalid_network", "value must be one IPv4 host or CIDR")
            network = ipaddress.ip_network(f"{address}/32")
    except CidrError:
        raise
    except ValueError as exc:
        raise CidrError("invalid_network", "value must be one IPv4 host or CIDR") from exc
    if not isinstance(network, ipaddress.IPv4Network):
        raise CidrError("ipv6_unsupported", "Application Gateway IPMatch accepts IPv4 only")
    text = str(network)
    if "/" in value and text != value:
        raise CidrError("invalid_network", "CIDR must be in canonical form")
    return network


def render(network: ipaddress.IPv4Network) -> str:
    if network.prefixlen == 32:
        return str(network.network_address)
    return str(network)


def overlaps_protected(
    network: ipaddress.IPv4Network,
    extra: tuple[ipaddress.IPv4Network, ...] = (),
) -> bool:
    return any(network.overlaps(item) for item in (*PROTECTED, *extra))


def collapse_exact(networks: list[ipaddress.IPv4Network]) -> list[ipaddress.IPv4Network]:
    """Return the shortest exact covering set. Coverage does not grow."""

    unique = sorted(set(networks), key=lambda item: (int(item.network_address), item.prefixlen))
    collapsed = list(ipaddress.collapse_addresses(unique))
    return sorted(collapsed, key=lambda item: (int(item.network_address), item.prefixlen))


def subtract_host(
    networks: list[ipaddress.IPv4Network],
    host: ipaddress.IPv4Address,
) -> list[ipaddress.IPv4Network]:
    """Remove one host and keep every other address that was blocked."""

    remaining: list[ipaddress.IPv4Network] = []
    needle = ipaddress.ip_network(f"{host}/32")
    for network in networks:
        if host not in network:
            remaining.append(network)
        elif network.prefixlen == 32:
            continue
        else:
            remaining.extend(network.address_exclude(needle))
    return collapse_exact(remaining)


def covers(networks: list[ipaddress.IPv4Network], host: ipaddress.IPv4Address) -> list[ipaddress.IPv4Network]:
    return [network for network in networks if host in network]
