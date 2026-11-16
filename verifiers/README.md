# Cross-language verifier harnesses (Apache-2.0)

The [Rust v2 verifier and activation CLI](rust/README.md) implement device-bound,
long-term offline licensing. They require a finite expiry, explicit product and
device identity, and initialized verification state. The v1 parity harnesses below
remain unchanged; v1 tokens are never accepted by the v2 verifier.

Executable counterparts of the offline verifiers documented in
[docs/features/CLIENT_SDK.md](../docs/features/CLIENT_SDK.md), each pinned to the golden vector in
[docs/testing/CROSS_VERIFIER_FIXTURES.md](../docs/testing/CROSS_VERIFIER_FIXTURES.md). Until these
existed, Swift/Go parity rested on manual inspection of doc snippets (M6–M10 audit finding); now a
token must verify — and every alternate encoding must fail — identically in **Java (core), Java
(starter), Go, and Swift**, or a test suite goes red.

| Directory | Language / crypto | Run with |
|-----------|-------------------|----------|
| `go/` | Go, `crypto/ed25519` stdlib | `cd go && go test ./...` |
| `swift/` | Swift, Apple CryptoKit | `cd swift && swift test` (macOS) |
| `rust/` | Rust, ed25519-dalek (v2 device certificates) | `cd rust && cargo test --locked` |

Each harness asserts, against the pinned vector and tokens minted from its published test seed:

- the fixture token verifies at `iat` and is **EXPIRED at exactly `exp`** (exclusive bound);
- all **15 non-canonical spellings** of the signature segment (non-zero trailing bits) are
  malformed — one text form per byte string;
- padded (`=`) and standard-alphabet (`+`/`/`) segments are malformed;
- `alg` confusion is rejected **before** the signature is touched;
- validly-signed but non-strict payloads are malformed: duplicate keys, floats/exponents,
  integers beyond int64, a missing `exp` key, an unknown `ver`;
- `exp: null` is perpetual (never expires); `nbf` is inclusive.

Like the Spring Boot starter, this code is **Apache License 2.0** — it is client-side and meant to
be embedded in downstream (possibly closed-source) applications. Nothing here depends on the AGPL
modules; the shared contract is the wire format alone.

> CI note (M13): wire `go test` into the pipeline unconditionally; run `swift test` on the macOS
> runner leg. Both suites are dependency-free beyond their toolchains.
