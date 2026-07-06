#!/usr/bin/env python3
"""Guard against cross-verifier fixture drift (2026-07-05 audit, GRANTMINT-155).

The pinned golden vector (seed, public key, token, iat, exp) lives as duplicated
literals in five test suites — an unavoidable consequence of spanning Java, Go,
Swift, and TypeScript. grantmint-core's CrossVerifierFixtureTest is the source of
truth (docs/testing/CROSS_VERIFIER_FIXTURES.md); this script extracts its values
and fails if any other suite's copy has drifted, so a fixture regeneration cannot
silently leave one language pinned to the old vector.

Stdlib-only; run from the repo root: python3 scripts/check-fixture-parity.py
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SOURCE_OF_TRUTH = ROOT / (
    "grantmint-core/src/test/java/dev/hg/grantmint/core/token/CrossVerifierFixtureTest.java"
)

# Suites that duplicate the vector, with the keys each one deliberately omits:
# the Apache-2.0 starter never embeds the signing seed (it mints adversarial
# tokens through its test-scoped grantmint-core dependency instead). The docs
# file is local-only (docs/ is not in git), so it is checked only when present.
TARGETS: list[tuple[Path, frozenset[str]]] = [
    (
        ROOT / "grantmint-spring-boot-starter/src/test/java/dev/hg/grantmint/client/verify/CrossVerifierFixtureTest.java",
        frozenset({"seed"}),
    ),
    (ROOT / "verifiers/go/grantmint_test.go", frozenset()),
    (ROOT / "verifiers/swift/Tests/GrantmintVerifierTests/GrantmintVerifierTests.swift", frozenset()),
    (ROOT / "dashboard/src/lib/tokenVerify.test.ts", frozenset()),
]
OPTIONAL_TARGETS: list[tuple[Path, frozenset[str]]] = [
    (ROOT / "docs/testing/CROSS_VERIFIER_FIXTURES.md", frozenset()),
]

# Header and payload segments start with base64url("{\"") == "eyJ"; the signature
# segment of a 64-byte Ed25519 signature is exactly 86 unpadded base64url chars.
TOKEN_RE = re.compile(r"eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{86}")


def joined_literals(text: str) -> str:
    """Collapse string-literal concatenation so a token split across lines
    ("..." + "..." in Java/Go/Swift/TS) becomes one contiguous string. Line
    comments go first — an inline `// gitleaks:allow` between two concatenated
    literals would otherwise interrupt the joined token. (Base64url and hex can
    never contain `//`, so this strips nothing we search for.)"""
    without_comments = re.sub(r"//[^\n]*", "", text)
    return re.sub(r'["\'+\s\\]', "", without_comments)


def without_digit_separators(text: str) -> str:
    """1_751_130_000 (Swift/Java digit groups) -> 1751130000. Applied only for
    numeric searches; base64url legitimately contains underscores."""
    return re.sub(r"(?<=\d)_(?=\d)", "", text)


def extract_canonical() -> dict[str, str]:
    text = SOURCE_OF_TRUTH.read_text(encoding="utf-8")
    values: dict[str, str] = {}

    for name, pattern in {
        "seed": r'SEED_HEX\s*=\s*"([0-9a-f]{64})"',
        "public key": r'PUBLIC_KEY_HEX\s*=\s*"([0-9a-f]{64})"',
        "iat": r"IAT\s*=\s*([0-9_]+)L?\b",
        "exp": r"EXP\s*=\s*([0-9_]+)L?\b",
    }.items():
        match = re.search(pattern, text)
        if not match:
            sys.exit(f"FAIL: cannot extract the canonical {name} from {SOURCE_OF_TRUTH}")
        values[name] = without_digit_separators(match.group(1))

    token_match = TOKEN_RE.search(joined_literals(text))
    if not token_match:
        sys.exit(f"FAIL: cannot extract the canonical token from {SOURCE_OF_TRUTH}")
    values["token"] = token_match.group(0)
    return values


def check(path: Path, canonical: dict[str, str], skip: frozenset[str]) -> list[str]:
    text = path.read_text(encoding="utf-8")
    blob = joined_literals(text)
    numbers = without_digit_separators(text)
    problems = []
    for name, value in canonical.items():
        if name in skip:
            continue
        haystack = blob if name == "token" else (numbers if name in ("iat", "exp") else text)
        if value not in haystack:
            problems.append(f"  {path.relative_to(ROOT)}: {name} does not match the canonical vector")
    return problems


def main() -> None:
    canonical = extract_canonical()
    targets = list(TARGETS) + [(p, skip) for p, skip in OPTIONAL_TARGETS if p.exists()]
    missing = [p for p, _ in TARGETS if not p.exists()]
    if missing:
        sys.exit("FAIL: expected fixture suite(s) not found:\n" + "\n".join(f"  {p}" for p in missing))

    problems: list[str] = []
    for target, skip in targets:
        problems.extend(check(target, canonical, skip))

    if problems:
        print("Cross-verifier fixture drift detected — grantmint-core's CrossVerifierFixtureTest")
        print("is the source of truth; re-sync the copies below (docs/testing/CROSS_VERIFIER_FIXTURES.md,")
        print('"Regenerating the vector"):')
        print("\n".join(problems))
        sys.exit(1)

    print(f"fixture parity OK: {len(targets)} suites pin the canonical vector "
          f"(token {canonical['token'][:24]}…, iat {canonical['iat']}, exp {canonical['exp']})")


if __name__ == "__main__":
    main()
