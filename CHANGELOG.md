# Changelog

**Last Updated: 2026-06-28**

All notable changes to **Grantmint** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> ℹ️ **Versioning scope.** A single version number covers the whole repository
> (`grantmint-core`, `grantmint-server`, `grantmint-spring-boot-starter`,
> `grantmint-cli`, and `dashboard`), even though artifacts are published and
> licensed separately (AGPL-3.0 for server/core/cli, Apache-2.0 for the starter
> and the documented Swift/Go verifiers).

> ⚠️ **Compatibility note for the signed-token format.** The token format is
> versioned with the `gm1.` prefix. Any change that affects how already-issued
> tokens verify offline against an embedded public key is a **breaking change**
> and will bump the major version, because it can break clients already shipped
> to customers. See [LICENSE_TOKEN_FORMAT.md](docs/features/LICENSE_TOKEN_FORMAT.md).

---

## Table of Contents

- [Unreleased](#unreleased)
- [0.1.0 - 2026-06-28](#010---2026-06-28)
- [How to update this changelog](#how-to-update-this-changelog)

---

## [Unreleased]

Changes landed on `main` but not yet released. Move entries into a dated,
versioned section on release.

### Added
- _Nothing yet._

### Changed
- _Nothing yet._

### Deprecated
- _Nothing yet._

### Removed
- _Nothing yet._

### Fixed
- _Nothing yet._

### Security
- _Nothing yet._

---

## [0.1.0] - 2026-06-28

Initial public release: the **v1 MVP** — a self-hostable, single-binary license
& entitlement server. This release delivers the full in-scope feature set: signed-token
issuance, layered offline/online validation, node-locked activation with seat limits,
entitlements, the license-lifecycle state machine, the admin API + dashboard, the
client SDK, the Stripe webhook reference adapter, and the property-based test suite.

> ℹ️ **Boundary reminder, by design.** Grantmint consumes billing webhooks and
> issues/suspends/expires licenses in response — **the payment provider handles
> the money, Grantmint handles the licensing.** Payment processing is permanently
> out of scope. Offline verification proves authenticity and expiry; it is **not**
> unbreakable DRM.

### Added

**Crypto / issuance core (`grantmint-core`, AGPL-3.0)**
- Ed25519 key-pair generation and management.
- Signed structured token: construction, serialization (`gm1.` prefix), and
  offline signature verification against an embedded public key — **no network**.
- Embedded payload: entitlements, expiry, holder, and constraints.
- Short, human-readable **key ID** scheme (e.g. `GRNT-7F3A-9KQ2-X4M8`) used as the
  online identifier, paired with the signed token.
- Entitlement encoding for feature flags (booleans) and numeric limits.
- Pure Java, **zero Spring dependencies** — enforced by an ArchUnit rule.

**Server (`grantmint-server`, AGPL-3.0)**
- Admin/issuance REST API: products, policies, entitlements, and licenses
  (issue / suspend / reinstate / revoke), documented via springdoc-openapi
  (Swagger UI + OpenAPI 3).
- Client/validation REST API: `validate`, `activate`, `deactivate`, `heartbeat`.
- **Online validation** layered on top of offline verification: activation,
  seat counting, heartbeats, and real-time revocation.
- **Node-locked device activation** with machine fingerprinting and per-license
  **seat limits** (max machines per license).
- **Entitlements** carried in the token and checkable online.
- **License-lifecycle state machine**: `created → active → suspended → expired
  → revoked`, including trials, expiry, and grace periods.
- **Three distinct auth schemes**: admin/dashboard auth, per-product issuance
  API keys, and a license-validation auth scheme. (No end-user signup/login/OAuth.)
- **Pluggable payment-webhook adapter** (Strategy pattern + Spring
  auto-configuration) with a **Stripe reference adapter** that auto-issues,
  suspends, and expires licenses on billing events. Incoming webhook signatures
  are verified.
- **Background jobs**: license-expiry sweeps and heartbeat-timeout deactivation.
- Persistence via Spring Data JPA on **PostgreSQL** with **Flyway** migrations
  (products, policies, entitlements, licenses, machine activations).
- **Caffeine** in-process cache on the validation hot path; **rate limiting** on
  validation endpoints. **Redis** available as an optional multi-node profile.
- **Micrometer** metrics with a Prometheus scrape endpoint: issuance count,
  validation latency, active licenses, activation/seat counts, webhook processing.
- **GraalVM native image** build → single self-contained binary, sub-50ms startup.
  Fat JAR and Docker image provided as secondary artifacts.

**Client SDK (`grantmint-spring-boot-starter`, Apache-2.0)**
- Auto-configured validation/entitlement-check bean for any consuming Spring Boot
  app via one dependency + properties (~20 lines + an embedded public key).
- Documented **Swift** (Apple CryptoKit) and **Go** (`ed25519` stdlib) offline-verifier
  snippets for first-party clients.

**CLI (`grantmint-cli`, AGPL-3.0)**
- Picocli-based commands to generate keys, issue / inspect / revoke licenses, and
  **verify tokens offline**.

**Dashboard (`dashboard`)**
- Minimal React 18 + TypeScript + Vite + Tailwind operator console: manage
  products, policies, entitlements, licenses, and activations; issue and revoke;
  and run the offline-vs-online tradeoff demo.

**Quality / tests**
- **jqwik** property-based tests asserting the core invariants: any license issued
  from a policy verifies offline against the public key; any tampered or expired
  token fails verification; activations never exceed the policy's seat limit; a
  revoked license fails online validation.
- **Testcontainers** integration tests against real PostgreSQL.
- **ArchUnit** rules enforcing the `grantmint-core` (no Spring) ↔ server boundary.

**Distribution / CI**
- Docker + Docker Compose (app + Postgres) with a multi-stage GraalVM native build.
- GitHub Actions pipeline: build, test suite, native-image build, and release of
  binaries + Docker image, publishing the Apache-2.0 SDK and AGPL-3.0 server as
  separate artifacts.

### Security
- Ed25519 signatures make license tokens **hard to forge**; only the holder of the
  private signing key can mint valid licenses.
- Incoming payment-webhook payloads are signature-verified before driving any
  license lifecycle transition.
- Validation endpoints are rate-limited to resist abuse.
- Documented threat model and signing-key protection/rotation guidance in
  [SECURITY.md](docs/security/SECURITY.md).

> 🔒 **Known and documented limitation.** Offline revocation is not possible — a
> token verified offline cannot be revoked offline. Mitigations (online check-ins,
> short token lifetimes) are documented; a signed revocation list (CRL) is a
> stretch goal, not part of 0.1.0. See [LICENSE_LIFECYCLE.md](docs/features/LICENSE_LIFECYCLE.md).

### Known limitations / not in this release
The following are intentionally **out of v1 scope** and tracked in
[ROADMAP.md](docs/reference/ROADMAP.md):
- Floating/concurrent (lease-based) licenses.
- Signed revocation-list (CRL) distribution.
- Software-artifact/release distribution and OCI registry (no CDN by design).
- Usage/metered/consumption licensing.
- SSO/SAML for admin and audit-log product tiers.
- Reseller/multi-tenant hierarchies.
- License upgrades/downgrades/proration (billing's job).
- Additional webhook adapters beyond Stripe (Polar is the planned easy second).
- **Payment processing — permanently out of scope.**

---

## How to update this changelog

Keep this file human-curated. Do not auto-generate it from commit messages.

### Workflow
1. While working on `main`, add bullet points under **[Unreleased]** in the correct
   category as you merge user-facing changes.
2. On release, rename `[Unreleased]` to the new version with a date and open a fresh,
   empty `[Unreleased]` block above it.
3. Update the comparison links at the bottom of this file.

### Categories (Keep a Changelog)

| Category | Use it for |
|---|---|
| **Added** | New features (e.g. a new webhook adapter, a new validation endpoint). |
| **Changed** | Changes to existing behavior (e.g. default cache TTL, API response shape). |
| **Deprecated** | Soon-to-be-removed features; give a migration note and a removal target. |
| **Removed** | Features removed in this release. |
| **Fixed** | Bug fixes (e.g. a seat-count race, a clock-skew expiry edge case). |
| **Security** | Vulnerability fixes and hardening (e.g. webhook signature verification, key handling). |

### Semantic versioning rules for Grantmint

| Bump | When |
|---|---|
| **MAJOR** (`x.0.0`) | A breaking change to the REST API, the **signed-token format** (`gm1.` → `gm2.`), the SDK's public bean/properties contract, or the DB schema in a non-backward-compatible way. Breaking token-format changes are especially serious — they can invalidate licenses already shipped to customers. |
| **MINOR** (`0.x.0`) | Backward-compatible new features (new endpoints, new webhook adapters, new entitlement types, new CLI commands). |
| **PATCH** (`0.0.x`) | Backward-compatible bug fixes, security patches, and docs-only changes. |

> 💡 **Tip.** When a change touches the token format or the SDK's public API, call
> it out explicitly under **Changed** (or **Removed**) with an upgrade note —
> downstream apps embed the verifier and the public key, so even small changes can
> ripple into shipped clients.

> ✅ **Do** write entries from the operator's/integrator's point of view ("Stripe
> adapter now retries failed deliveries"), not the implementation's ("refactored
> `WebhookDispatcher`").

> ❌ **Don't** list internal refactors, dependency bumps with no user impact, or
> CI tweaks here — those live in the commit history.

### Entry template

```markdown
## [X.Y.Z] - YYYY-MM-DD

### Added
- Short, user-facing description of the new capability. (#PR)

### Changed
- What changed and why it matters. Include an upgrade note if needed.

### Deprecated
- What is deprecated, the replacement, and the planned removal version.

### Removed
- What was removed and the migration path.

### Fixed
- The bug, observed symptom, and the fix.

### Security
- The hardening or vulnerability fix (CVE link if applicable).
```

---

## Related Documentation

- [README](README.md)
- [Roadmap](docs/reference/ROADMAP.md)
- [License Token Format](docs/features/LICENSE_TOKEN_FORMAT.md)
- [License Lifecycle](docs/features/LICENSE_LIFECYCLE.md)
- [Security](docs/security/SECURITY.md)
- [Contributing](docs/contributing/CONTRIBUTING.md)

---

[Unreleased]: https://github.com/hg/grantmint/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/hg/grantmint/releases/tag/v0.1.0
