from sentinel_waf_block.addresses import (
    REASON_BUILTIN_V4,
    REASON_CUSTOMER,
    REASON_DIRTY,
    REASON_INVALID_V4,
    canonical_host,
    parse_protected_ranges,
    protection_reason,
)


def test_public_ipv4_is_canonical() -> None:
    result = canonical_host("203.0.113.5")
    assert result.canonical == "203.0.113.5"
    assert result.reason is None


def test_leading_zero_ipv4_is_rejected() -> None:
    result = canonical_host("192.0.2.01")
    assert result.reason == REASON_INVALID_V4
    assert result.canonical is None


def test_dirty_incident_values_are_not_repaired() -> None:
    assert canonical_host("").reason == REASON_DIRTY
    assert canonical_host(" 203.0.113.5").reason == REASON_DIRTY
    assert canonical_host("203.0.113.5/32").reason == REASON_DIRTY
    assert canonical_host("203.0.113.5,198.51.100.8").reason == REASON_DIRTY
    assert canonical_host("fe80::1%eth0").reason == REASON_DIRTY


def test_non_ipv4_text_is_invalid() -> None:
    samples = (
        "2001:DB8::1",
        "2001:0db8:0000:0000:0000:0000:0000:0001",
        "not:an:ip",
        "gggg::1",
        "::ffff:192.0.2.1",
        "0000:0000:0000:0000:0000:ffff:c000:0201",
        "::192.0.2.1",
        "2001:db8::192.0.2.1",
        "::",
        "::1",
        "fe80::1",
        "not-an-ip",
    )
    for value in samples:
        result = canonical_host(value)
        assert result.reason == REASON_INVALID_V4
        assert result.canonical is None


def test_builtin_ipv4_categories() -> None:
    ranges, bad = parse_protected_ranges([])
    assert bad == ()
    samples = {
        "0.0.0.1": REASON_BUILTIN_V4,
        "10.1.2.3": REASON_BUILTIN_V4,
        "172.16.5.5": REASON_BUILTIN_V4,
        "192.168.1.20": REASON_BUILTIN_V4,
        "127.0.0.1": REASON_BUILTIN_V4,
        "169.254.1.1": REASON_BUILTIN_V4,
        "169.254.169.254": REASON_BUILTIN_V4,
        "100.64.1.1": REASON_BUILTIN_V4,
        "100.127.255.255": REASON_BUILTIN_V4,
    }
    for address, reason in samples.items():
        assert protection_reason(address, ranges, override=False) == reason
    assert protection_reason("203.0.113.5", ranges, override=False) is None
    assert protection_reason("100.128.0.1", ranges, override=False) is None


def test_customer_ranges_use_membership_and_reject_other_prefixes() -> None:
    ranges, bad = parse_protected_ranges(["203.0.113.9/24", "198.51.100.10"])
    assert bad == ()
    assert protection_reason("203.0.113.8", ranges, override=False) == REASON_CUSTOMER
    assert protection_reason("203.0.113.255", ranges, override=False) == REASON_CUSTOMER
    assert protection_reason("198.51.100.10", ranges, override=False) == REASON_CUSTOMER
    assert protection_reason("198.51.100.11", ranges, override=False) is None

    _ranges, rejected = parse_protected_ranges(
        ["172.16.0.0/12", "100.64.0.0/10", "fe80::/10", "2001:db8::/32", "192.0.2.0/08", "::ffff:192.0.2.1"]
    )
    assert rejected == (
        "172.16.0.0/12",
        "100.64.0.0/10",
        "fe80::/10",
        "2001:db8::/32",
        "192.0.2.0/08",
        "::ffff:192.0.2.1",
    )


def test_override_skips_membership_only() -> None:
    ranges, _bad = parse_protected_ranges(["203.0.113.0/24"])
    assert protection_reason("10.1.2.3", ranges, override=True) is None
    assert protection_reason("203.0.113.8", ranges, override=True) is None
    assert canonical_host("::ffff:10.1.2.3").reason == REASON_INVALID_V4
