import ipaddress

import pytest

from app.cidr import CidrError, collapse_exact, overlaps_protected, parse_network, render, subtract_host
from app.policy import build_agw_put_body, pack_rules


def test_adjacent_hosts_collapse_without_covering_neighbors() -> None:
    collapsed = collapse_exact(
        [parse_network("203.0.113.0"), parse_network("203.0.113.1")]
    )
    assert [render(item) for item in collapsed] == ["203.0.113.0/31"]


def test_non_adjacent_hosts_stay_separate() -> None:
    collapsed = collapse_exact(
        [parse_network("203.0.113.1"), parse_network("203.0.113.2")]
    )
    assert [render(item) for item in collapsed] == ["203.0.113.1", "203.0.113.2"]


def test_removing_one_host_from_a_cidr_keeps_the_rest() -> None:
    remaining = subtract_host(
        [ipaddress.ip_network("203.0.113.0/30")],
        ipaddress.ip_address("203.0.113.1"),
    )
    assert [render(item) for item in remaining] == ["203.0.113.0", "203.0.113.2/31"]
    covered = set()
    for network in remaining:
        covered.update(network)
    assert ipaddress.ip_address("203.0.113.1") not in covered
    assert ipaddress.ip_address("203.0.113.0") in covered
    assert ipaddress.ip_address("203.0.113.3") in covered


def test_protected_and_ipv6_are_rejected() -> None:
    assert overlaps_protected(parse_network("10.0.0.1"))
    with pytest.raises(CidrError):
        parse_network("2001:db8::1")
    with pytest.raises(CidrError):
        parse_network(" 203.0.113.5")


def test_pack_preserves_external_values_and_the_probe_rule() -> None:
    packed = pack_rules(
        [parse_network("203.0.113.9")],
        ["198.51.100.4"],
        product_cap=100,
        base_name="SentinelAutoBlock",
        base_priority=10,
        occupied_priorities={50},
        occupied_names={"PocSimulatedProbe"},
        existing_managed_names=["SentinelAutoBlock"],
    )
    assert packed.rules[0].values == ("198.51.100.4", "203.0.113.9")
    document = {
        "location": "eastus",
        "tags": {"keep": "yes"},
        "properties": {
            "policySettings": {"mode": "Prevention"},
            "managedRules": {"managedRuleSets": []},
            "customRules": [
                {"name": "PocSimulatedProbe", "priority": 50, "matchConditions": []},
                {"name": "SentinelAutoBlock", "priority": 10},
            ],
        },
    }
    body = build_agw_put_body(document, list(packed.rules), list(packed.retired_names))
    names = [rule["name"] for rule in body["properties"]["customRules"]]
    assert names[0] == "PocSimulatedProbe"
    block = next(rule for rule in body["properties"]["customRules"] if rule["name"] == "SentinelAutoBlock")
    assert block["matchConditions"][0]["negationConditon"] is False
    assert block["matchConditions"][0]["matchValues"] == ["198.51.100.4", "203.0.113.9"]


def test_product_cap_fails_before_a_wider_cidr_is_invented() -> None:
    hosts = [parse_network(f"203.0.113.{index}") for index in (1, 3, 5)]
    with pytest.raises(CidrError) as caught:
        pack_rules(
            hosts,
            [],
            product_cap=2,
            base_name="SentinelAutoBlock",
            base_priority=10,
            occupied_priorities=set(),
            occupied_names=set(),
            existing_managed_names=["SentinelAutoBlock"],
        )
    assert caught.value.code == "capacity_exceeded"
