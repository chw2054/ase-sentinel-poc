"""Pure list decisions. No Azure calls and no address parsing."""

from __future__ import annotations


def enforcement_enabled(flag: object) -> bool:
    """Only the JSON boolean true may update a policy."""

    return flag is True


def override_enabled(flag: object) -> bool:
    return flag is True


def merge_addresses(
    existing: list[str],
    candidates: list[str],
) -> tuple[list[str], list[str]]:
    """Append candidates that are not already present as the same string.

    Existing values are kept verbatim, including duplicate or compressed text.
    """

    present = set(existing)
    new: list[str] = []
    for candidate in candidates:
        if candidate in present:
            continue
        present.add(candidate)
        new.append(candidate)
    return [*existing, *new], new


def exceeds_capacity(merged: list[str], maximum: int) -> bool:
    return len(merged) > maximum
