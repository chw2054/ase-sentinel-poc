import copy

from sentinel_waf_block.addresses import REASON_BUILTIN_V4, REASON_INVALID_V4
from sentinel_waf_block.engine import CommentError, Engine, WafGetError, WafPutError
from sentinel_waf_block.models import STATUS_COMMENT
from tests.conftest import (
    FakeComments,
    FakeWaf,
    agw_block_rule,
    agw_policy,
    config,
    front_door,
    front_door_policy,
    incident,
    probe_rule,
)

def engine(waf: FakeWaf | None = None, comments: FakeComments | None = None) -> tuple[Engine, FakeWaf, FakeComments]:
    waf = waf or FakeWaf()
    comments = comments or FakeComments()
    return Engine(waf, comments), waf, comments


def test_valid_public_ipv4_dry_run_does_not_put() -> None:
    app, waf, comments = engine()
    result = app.execute(incident("203.0.113.5"), config())
    assert result.status == "dry-run"
    assert result.changed is False
    assert result.new_addresses == ("203.0.113.5",)
    assert "Would block IP: 203.0.113.5" in result.comment
    assert waf.puts == []
    assert len(waf.gets) == 1
    assert comments.messages


def test_invalid_and_protected_ipv4_are_rejected_without_get() -> None:
    app, waf, _comments = engine()
    result = app.execute(
        incident("192.0.2.01", "10.1.2.3", "169.254.169.254", "100.77.1.1", "127.0.0.1"),
        config(),
    )
    assert result.status == "nothing-to-block"
    assert result.changed is False
    reasons = [item.reason for item in result.rejected_addresses]
    assert "invalid IPv4" in reasons
    assert reasons.count(REASON_BUILTIN_V4) == 4
    assert "Would block IP:" not in result.comment
    assert waf.gets == []


def test_duplicate_candidates_collapse() -> None:
    app, waf, _comments = engine()
    result = app.execute(incident("203.0.113.5", "203.0.113.5"), config())
    assert result.new_addresses == ("203.0.113.5",)
    assert result.comment.count("Would block IP:") == 1
    assert waf.puts == []


def test_already_listed_address_does_not_put() -> None:
    document = agw_policy(probe_rule(), agw_block_rule(["203.0.113.5", "198.51.100.8"]))
    original = copy.deepcopy(document)
    app, waf, _comments = engine(FakeWaf(document))
    result = app.execute(incident("203.0.113.5"), config())
    assert result.status == "already-blocked"
    assert result.new_addresses == ()
    assert result.changed is False
    assert waf.puts == []
    assert "Would block IP:" not in result.comment
    assert "already on custom rule" in result.comment
    assert document == original


def test_customer_ranges_and_fail_closed() -> None:
    app, waf, _comments = engine()
    blocked = app.execute(incident("203.0.113.50"), config(protected_ip_ranges=("203.0.113.9/24",)))
    assert blocked.status == "nothing-to-block"
    assert blocked.rejected_addresses[0].reason == "protectedIpRanges"
    assert waf.gets == []

    app, waf, _comments = engine()
    invalid = app.execute(
        incident("203.0.113.50"),
        config(protected_ip_ranges=("172.16.0.0/12", "not-a-range"), override_protected_ranges=True),
    )
    assert invalid.status == "protected-ranges-invalid"
    assert invalid.invalid_protected_ranges == ("172.16.0.0/12", "not-a-range")
    assert "Would block IP:" not in invalid.comment
    assert waf.gets == []
    assert waf.puts == []


def test_non_ipv4_incident_is_rejected_without_get() -> None:
    for cfg in (config(auto_block_enabled=True), front_door(auto_block_enabled=True)):
        app, waf, _comments = engine()
        result = app.execute(incident("2001:db8::1", "::ffff:203.0.113.5", "fe80::1"), cfg)
        assert result.status == "nothing-to-block"
        assert result.candidate_addresses == ()
        assert {item.reason for item in result.rejected_addresses} == {REASON_INVALID_V4}
        assert "Would block IP:" not in result.comment
        assert "Blocked IP:" not in result.comment
        assert waf.gets == []
        assert waf.puts == []


def test_non_ipv4_protected_range_fails_closed() -> None:
    app, waf, _comments = engine()
    result = app.execute(incident("203.0.113.5"), front_door(protected_ip_ranges=("2001:db8::/32",)))
    assert result.status == "protected-ranges-invalid"
    assert result.invalid_protected_ranges == ("2001:db8::/32",)
    assert waf.gets == []
    assert waf.puts == []


def test_mixed_incident_puts_ipv4_and_rejects_other_text() -> None:
    document = agw_policy(probe_rule())
    app, waf, _comments = engine(FakeWaf(document))
    result = app.execute(incident("203.0.113.5", "2001:db8::1"), config(auto_block_enabled=True))
    assert result.status == "blocked"
    assert result.changed is True
    assert result.new_addresses == ("203.0.113.5",)
    assert result.rejected_addresses[0].reason == REASON_INVALID_V4
    body = waf.puts[0]
    values = body["properties"]["customRules"][0]["matchConditions"][0]["matchValues"]
    assert values == ["203.0.113.5"]
    assert "Blocked IP: 203.0.113.5" in result.comment
    assert "Would block IP:" not in result.comment
    assert "invalid IPv4" in result.comment
    assert "There is no automatic expiry. Rollback is an operator action." in result.comment


def test_string_true_does_not_put_and_override_still_rejects_non_ipv4() -> None:
    app, waf, _comments = engine()
    dry = app.execute(incident("203.0.113.5"), config(auto_block_enabled="true"))
    assert dry.status == "dry-run"
    assert waf.puts == []

    app, waf, _comments = engine()
    overridden = app.execute(incident("10.1.2.3", "2001:db8::1"), config(override_protected_ranges=True))
    assert overridden.status == "dry-run"
    assert overridden.new_addresses == ("10.1.2.3",)
    assert overridden.rejected_addresses[0].reason == REASON_INVALID_V4
    assert waf.puts == []


def test_front_door_keeps_other_rules_when_blocking_ipv4() -> None:
    rule = {
        "name": "SentinelAutoBlock",
        "enabledState": "Enabled",
        "priority": 10,
        "ruleType": "MatchRule",
        "action": "Block",
        "matchConditions": [
            {
                "matchVariable": "RemoteAddr",
                "operator": "IPMatch",
                "negateCondition": False,
                "matchValue": ["198.51.100.8"],
            }
        ],
    }
    probe = {"name": "PocSimulatedProbe", "action": "Block", "matchConditions": []}
    app, waf, _comments = engine(FakeWaf(front_door_policy(probe, rule)))
    result = app.execute(incident("203.0.113.5"), front_door(auto_block_enabled=True))
    assert result.status == "blocked"
    written = waf.puts[0]["properties"]["customRules"]["rules"][0]["matchConditions"][0]["matchValue"]
    assert written == ["198.51.100.8", "203.0.113.5"]
    assert waf.puts[0]["properties"]["customRules"]["rules"][1] == probe
    assert waf.puts[0]["sku"]["name"] == "Premium_AzureFrontDoor"


def test_existing_match_strings_are_copied_and_other_rules_stay() -> None:
    stored = "2001:db8::1"
    block = agw_block_rule([stored, "192.0.2.10"])
    first = {"name": "KeepFirst", "priority": 20, "matchConditions": []}
    probe = probe_rule()
    document = agw_policy(first, block, probe)
    app, waf, _comments = engine(FakeWaf(document))
    result = app.execute(incident("203.0.113.5"), config(auto_block_enabled=True))
    assert result.status == "blocked"
    body = waf.puts[0]
    assert set(body) == {"location", "tags", "properties"}
    assert set(body["properties"]) == {"policySettings", "customRules", "managedRules"}
    rules = body["properties"]["customRules"]
    assert [rule["name"] for rule in rules] == ["SentinelAutoBlock", "KeepFirst", "PocSimulatedProbe"]
    condition = rules[0]["matchConditions"][0]
    assert condition["negationConditon"] is False
    assert "negationCondition" not in condition
    assert condition["matchValues"] == [stored, "192.0.2.10", "203.0.113.5"]
    assert rules[2] == probe
    assert body["properties"]["policySettings"]["mode"] == "Prevention"
    assert body["properties"]["managedRules"]["managedRuleSets"][0]["ruleSetVersion"] == "3.2"


def test_capacity_counts_existing_values_and_rejects_non_ipv4() -> None:
    document = agw_policy(agw_block_rule(["198.51.100.8"]))
    app, waf, _comments = engine(FakeWaf(document))
    result = app.execute(
        incident("203.0.113.5", "2001:db9::1"),
        config(maximum_block_entries=1, auto_block_enabled=True),
    )
    assert result.status == "capacity-exceeded"
    assert result.existing_count == 1
    assert result.resulting_count == 2
    assert result.new_addresses == ("203.0.113.5",)
    assert result.rejected_addresses[0].reason == REASON_INVALID_V4
    assert result.changed is False
    assert waf.puts == []
    assert "203.0.113.5" in result.reason
    assert "Blocked IP:" not in result.comment


def test_get_failure_has_no_would_block_line() -> None:
    app, waf, _comments = engine(FakeWaf(get_error=WafGetError("GET failed with HTTP 403")))
    result = app.execute(incident("203.0.113.5"), config(auto_block_enabled=True))
    assert result.status == "waf-get-failed"
    assert result.changed is False
    assert "Would block IP:" not in result.comment
    assert waf.puts == []


def test_put_failure_is_not_reported_as_blocked() -> None:
    app, waf, _comments = engine(FakeWaf(put_error=WafPutError("PUT timed out")))
    result = app.execute(incident("203.0.113.5"), config(auto_block_enabled=True))
    assert result.status == "waf-put-failed"
    assert result.changed is False
    assert "Do not assume" in result.comment
    assert "Blocked IP:" not in result.comment
    assert len(waf.puts) == 1


def test_comment_failure_after_put_does_not_retry() -> None:
    app, waf, _comments = engine(comments=FakeComments(error=CommentError("comment failed")))
    result = app.execute(incident("203.0.113.5"), config(auto_block_enabled=True))
    assert result.status == STATUS_COMMENT
    assert result.changed is True
    assert len(waf.puts) == 1
    assert "Blocked IP: 203.0.113.5" in result.comment


def test_unsupported_provider_does_not_call_azure() -> None:
    app, waf, _comments = engine()
    result = app.execute(incident("203.0.113.5"), config(waf_provider="CDN"))
    assert result.status == "unsupported-provider"
    assert waf.gets == []
    assert waf.puts == []


def test_unexpected_policy_shape_does_not_put() -> None:
    document = agw_policy(probe_rule())
    del document["properties"]["customRules"]
    app, waf, _comments = engine(FakeWaf(document))
    result = app.execute(incident("203.0.113.5"), config(auto_block_enabled=True))
    assert result.status == "policy-shape-invalid"
    assert waf.puts == []
    assert "Would block IP:" not in result.comment


def test_front_door_put_uses_negate_condition_and_sku() -> None:
    app, waf, _comments = engine(FakeWaf(front_door_policy(probe_rule())))
    result = app.execute(incident("203.0.113.5"), front_door(auto_block_enabled=True))
    assert result.status == "blocked"
    body = waf.puts[0]
    assert "sku" in body
    condition = body["properties"]["customRules"]["rules"][0]["matchConditions"][0]
    assert condition["negateCondition"] is False
    assert condition["matchValue"] == ["203.0.113.5"]
    assert condition["matchVariable"] == "RemoteAddr"
    assert "negationConditon" not in condition
