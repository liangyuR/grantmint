# Grantmint

> A self-hostable, single-binary **license & entitlement server** for the JVM. It issues **authentic, cryptographically sealed credentials** your apps can verify **offline** — and adds online activation, seat counting, and revocation when you need richer control.

[![Build](https://img.shields.io/github/actions/workflow/status/harungungorer/grantmint/ci.yml?branch=main)](https://github.com/harungungorer/grantmint/actions)
[![License: AGPL-3.0 (server) / Apache-2.0 (SDK)](https://img.shields.io/badge/license-AGPL--3.0%20server%20%2F%20Apache--2.0%20SDK-blue.svg)](LICENSE)
[![Java 21](https://img.shields.io/badge/Java-21-orange.svg)](https://openjdk.org/projects/jdk/21/)
[![GraalVM Native](https://img.shields.io/badge/GraalVM-native--image-purple.svg)](https://www.graalvm.org/)

---

## Table of Contents

- [The elevator pitch](#the-elevator-pitch)
- [What Grantmint is — and is not](#what-grantmint-is--and-is-not)
- [Key features](#key-features)
- [How it compares](#how-it-compares)
- [Tech stack](#tech-stack)
- [Module structure](#module-structure)
- [Quick start](#quick-start)
- [The signature demo: offline vs online](#the-signature-demo-offline-vs-online)
- [The offline ↔ online tradeoff](#the-offline--online-tradeoff)
- [Dual-license model](#dual-license-model)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

---

## The elevator pitch

The name is the model. A **mint** stamps legitimate currency that is hard to counterfeit; **Grantmint** stamps legitimate **grants of rights** — licenses — that are equally hard to forge. Each license is an **Ed25519-signed token** that embeds its own entitlements, expiry, holder, and constraints. A client app verifies it against a **baked-in public key with no network connection at all**, then layers on online checks (activation, seats, heartbeats, revocation) when connectivity and tighter control are available.

The core insight: **an entitlement check the vendor can't trust is worthless.** If your macOS app asks "did this user pay for Pro?" the answer has to be unforgeable even when the machine is offline and the answer has to be cheap to verify. Grantmint gives you exactly that — a credential that proves authenticity and expiry against a public key, and a server that adds real-time control on top.

And the boundary that keeps the project honest:

> ℹ️ **The payment provider handles the money. Grantmint handles the licensing.** Grantmint is **not** a billing system. It never touches checkout, money, tax, refunds, or proration. It **consumes webhooks** from Stripe (or another provider) and issues, suspends, or expires licenses in response.

---

## What Grantmint is — and is not

Grantmint sits squarely in the camp of **dedicated licensing platforms** (Keygen, Cryptlex, LicenseSpring) — offline validation, device fingerprinting, time-bound entitlements, native verification. It is **complementary** to whatever billing platform you already use (Stripe, Polar, Lemon Squeezy, Gumroad), which mint keys only as a bonus feature with basic boolean flags.

Grantmint's differentiator is **not** scale or feature parity with Keygen. It is being a **clean, self-hostable, single-binary, JVM-native licensing _server_ with a permissively-licensed SDK.**

> ❌ **Not a billing system / payment processor.** No checkout, no money movement, no tax, no refunds, no proration. It reacts to billing webhooks; it never originates them.

> ❌ **Not a Keygen-scale competitor.** No software-artifact distribution, no CDN, no OCI registry. We do not benchmark against Keygen or imply parity on throughput or breadth.

> ❌ **Not DRM and not unbreakable.** Offline verification proves a credential is authentic and unexpired. It **cannot** stop a determined user from patching out the check. It raises the cost of piracy and gives legitimate customers a clean experience — that is the whole claim, stated honestly.

> ⚠️ **The offline ↔ online tradeoff is the intellectual core.** A signed token you can verify offline is exactly a token you **cannot** revoke or seat-count without connectivity. Grantmint documents this tension everywhere it is relevant rather than hand-waving it. See [The offline ↔ online tradeoff](#the-offline--online-tradeoff).

---

## Key features

- **Signed-token issuance** — issue a license from a policy and receive an Ed25519-signed token (embedding entitlements, expiry, holder, constraints) plus a short, human-typeable **key ID** like `K7P2-9QXM-4T1Y` (checksummed, ambiguity-free alphabet — survives being read over the phone).
- **Offline verification** — clients verify the signed token against an embedded public key with **zero network**. Canonical byte-for-byte encoding is part of the security contract, pinned by a shared cross-verifier test fixture.
- **Online validation** — `validate` / `activate` / `deactivate` / `heartbeat` against the server for richer control, with a Caffeine cache whose TTL is documented as the revocation-latency ceiling.
- **Node-locked activation** — machine fingerprinting + per-license **seat limits**, enforced under a database lock so concurrent activations can never oversubscribe a license. Floating/concurrent licenses are deferred to post-v1.
- **Entitlements** — named feature flags (`team_sync`), numeric limits (`max_devices=5`), and string values, defined per policy, snapshotted into the license at issuance, carried inside the token, and checkable both offline and online.
- **License lifecycle** — trials, expiry, grace periods, suspend/reinstate, and online revocation, modeled as an explicit state machine (`created → active → suspended → expired → revoked`) with property-tested transition guards.
- **Admin REST API + React dashboard** — manage products, policies, entitlements, licenses, and activations; issue and revoke; walk the offline-vs-online demo end to end in the browser.
- **Three isolated auth schemes** — admin/dashboard sessions, per-product issuance API keys (`X-Grantmint-Issuance-Key`), and low-privilege, rate-limited license-validation keys (`X-Grantmint-License-Key`) — each on its own Spring Security filter chain, with a default-deny catch-all behind them. **No end-user signup/login/OAuth.**
- **`grantmint-spring-boot-starter`** (Apache-2.0) — a self-contained offline verifier + optional online client, auto-configured into any Spring Boot app with one dependency and an embedded public key.
- **Swift, Go, and TypeScript verifiers** — real implementations (Apple CryptoKit, Go `crypto/ed25519`, WebCrypto), all verifying the same pinned token fixture; parity is enforced in CI so the five verifiers can never drift apart.
- **CLI** — `keygen` / `issue` / `inspect` / `revoke` / `verify`, with offline `verify` needing no server and per-failure-class exit codes for scripting.
- **Pluggable payment-webhook adapter** — Strategy + auto-configuration, with **Stripe** as the reference adapter (signature verified before parsing; idempotent redelivery) that auto-issues/suspends/expires licenses.
- **Background jobs** — expiry sweeps and heartbeat-timeout deactivation.
- **Single-binary distribution** — GraalVM native image with sub-second startup (~0.5 s including a live Postgres connect + Flyway migration check), plus a fat-JAR fallback and Docker Compose stack.
- **Observability** — Micrometer metrics (issuance count, validation latency, active licenses, seats) on a loopback-bound management port with a Prometheus scrape endpoint, and structured JSON logs that provably never leak tokens or holder PII.

---

## How it compares

| Dimension | **Grantmint** | **Keygen** | **Billing platforms that mint keys** (Stripe, Polar, Gumroad, Lemon Squeezy) |
|---|---|---|---|
| Category | Dedicated licensing **server** | Dedicated licensing platform | Payment platform; keys are a bonus feature |
| Primary job | Issue + verify cryptographic licenses | Licensing + artifact distribution | Process payments |
| Offline verification | ✅ Ed25519 signed token, embedded public key | ✅ Cryptographic licenses | ⚠️ Usually just a key string + boolean |
| Entitlements | ✅ Feature flags + numeric limits in token | ✅ Rich | ❌ Basic flags |
| Seat counting / activation | ✅ Node-locked + seat limits | ✅ | ❌ / minimal |
| Artifact distribution / CDN / OCI | ❌ **Out of scope by design** | ✅ | ❌ |
| Handles money | ❌ **Never** | ❌ | ✅ (that's their job) |
| Runtime | JVM, **single native binary** | Ruby | SaaS only |
| Self-hostable | ✅ VPS / Docker / bare metal | ✅ (Ruby app) / Cloud | ❌ |
| SDK license | **Apache-2.0** (permissive) | Fair-source / BUSL | Vendor SDK |

> 💡 **How to choose.** Use a billing platform for checkout. Use Grantmint to turn a "this customer paid" webhook into a cryptographic, verifiable license. Use Keygen if you need artifact distribution and operate at scale beyond what a single self-hosted node targets.

---

## Tech stack

| Layer | Technology | Version / notes |
|---|---|---|
| Language | Java | 21 (LTS) |
| Framework | Spring Boot | 3.x — Spring Web, Spring Security, Spring Data JPA |
| API docs | springdoc-openapi | Swagger UI + OpenAPI 3, admin-gated by default |
| Crypto | Ed25519 | Signed structured token + short key ID; offline-verifiable |
| Crypto core | `grantmint-core` | Pure Java, **zero runtime dependencies** (ArchUnit-enforced) |
| Database | PostgreSQL | Primary, via Spring Data JPA + Flyway migrations |
| Cache | Caffeine | In-process cache on the validation hot path |
| CLI | Picocli | `grantmint-cli` — issue/inspect/revoke + offline verify |
| Dashboard | React 18 + TypeScript + Vite + Tailwind | Operator console + in-browser demo verifier |
| Native build | GraalVM native image | Single binary, sub-second startup with live DB + Flyway |
| Observability | Micrometer + Prometheus | Issuance, validation latency, active licenses, seats |
| Tests | Testcontainers + jqwik + ArchUnit | Integration, property-based, architecture |

---

## Module structure

```
grantmint/
├── grantmint-core                 # Pure-Java crypto/issuance core (AGPL-3.0)
│                                  #   Ed25519 keys, signed-token build/verify,
│                                  #   key-ID scheme, entitlement encoding.
│                                  #   ZERO runtime dependencies (ArchUnit-enforced).
├── grantmint-server               # Spring Boot app (AGPL-3.0)
│                                  #   REST API, JPA persistence, Flyway, security,
│                                  #   lifecycle state machine, webhook adapters,
│                                  #   background jobs, native-image build.
├── grantmint-spring-boot-starter  # Client SDK (Apache-2.0)
│                                  #   Self-contained offline verifier + online client,
│                                  #   auto-configured. Never depends on the AGPL core.
├── grantmint-cli                  # Picocli CLI (AGPL-3.0), packaged as a fat JAR
│                                  #   keygen / issue / inspect / revoke / verify-offline.
├── verifiers/                     # Apache-2.0 offline verifiers
│   ├── go                         #   Go (crypto/ed25519 stdlib) + test suite
│   └── swift                      #   Swift (Apple CryptoKit) + test suite
└── dashboard                      # React 18 + TS + Vite + Tailwind operator console
                                   #   incl. the WebCrypto in-browser demo verifier
```

Base package / Maven groupId: **`dev.hg.grantmint`**.

---

## Quick start

Both paths end with you issuing a license and verifying its token **offline** with the CLI.

### Option A — Docker Compose (server + Postgres)

```bash
git clone https://github.com/harungungorer/grantmint.git
cd grantmint

# 1. Generate a signing key pair BEFORE starting the stack (the private key
#    seed is the crown jewel — keygen writes it 0600 and prints the public key).
./mvnw -q -pl grantmint-cli -am package -DskipTests
mkdir -p keys
java -jar grantmint-cli/target/grantmint-cli-*.jar keygen --out keys/acme.seed

# 2. Review the bootstrap credentials in docker-compose.yml
#    (GRANTMINT_ADMIN_USERNAME / GRANTMINT_ADMIN_PASSWORD), then start.
docker compose up -d

# 3. Health lives on the management port, mapped to loopback only.
curl -s http://127.0.0.1:9090/actuator/health
# {"status":"UP"}
```

### Option B — native binary or fat JAR (no Docker)

```bash
# Grab grantmint-server-<tag>-<platform> (or grantmint-server-<tag>.jar) from
# https://github.com/harungungorer/grantmint/releases — or build your own:
#   ./mvnw -Pnative -DskipTests -pl grantmint-server native:compile

export GRANTMINT_DB_URL="jdbc:postgresql://localhost:5432/grantmint"
export GRANTMINT_DB_USER="grantmint"
export GRANTMINT_DB_PASSWORD="change-me"
export GRANTMINT_ADMIN_USERNAME="admin"
export GRANTMINT_ADMIN_PASSWORD="change-me"   # bootstraps the first operator
./grantmint-server
```

### Issue and verify a license

```bash
# 1. Log in as the bootstrapped operator (session cookie + XSRF token).
curl -s -c cookies.txt -X POST http://localhost:8080/admin/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"change-me"}'

# 2. Create a product, register the signing key, and add a "Pro Annual"
#    policy with entitlements and a 2-seat limit (IDs come back as UUIDs).
curl -s -b cookies.txt -X POST http://localhost:8080/admin/products \
  -d '{"slug":"acme-studio","name":"Acme Studio"}' -H "Content-Type: application/json"

curl -s -b cookies.txt -X POST http://localhost:8080/admin/products/<productId>/signing-keys \
  -d '{"keyId":"acme-2026","privateKeyRef":"file:/keys/acme.seed",
       "publicKey":"<base64 from keygen>","makeActive":true}' \
  -H "Content-Type: application/json"

curl -s -b cookies.txt -X POST http://localhost:8080/admin/products/<productId>/policies \
  -d '{"code":"pro-annual","name":"Pro Annual","activationType":"node_locked",
       "maxSeats":2,"durationDays":365}' -H "Content-Type: application/json"

# 3. Mint a per-product ISSUANCE API key (plaintext is shown exactly once).
curl -s -b cookies.txt -X POST http://localhost:8080/admin/products/<productId>/issuance-keys \
  -d '{"name":"backend"}' -H "Content-Type: application/json"

# 4. Issue a license — note the separate auth scheme and header.
curl -s -X POST http://localhost:8080/issuance/licenses \
  -H "X-Grantmint-Issuance-Key: <issuance key>" \
  -H "Content-Type: application/json" \
  -d '{"policyId":"<policyId>","holder":{"name":"Jane Doe","email":"jane@example.com"}}'
# => { "keyId": "K7P2-9QXM-4T1Y",
#      "token": "eyJhbGciOiJFZERTQSJ9...three-segment-signed-token...",
#      "status": "active", "expiresAt": "2027-07-11T00:00:00Z" }

# 5. Verify the token OFFLINE — no server, just the public key.
java -jar grantmint-cli/target/grantmint-cli-*.jar verify \
  --token "eyJ..." --public-key "<base64 public key>" --product acme-studio
# VALID  |  holder=Jane Doe <jane@example.com>  |  expires 2027-07-11
```

That is the full loop: a product, a policy, an issued license, and a token your client can prove is authentic **with no network**. Swagger UI at `/swagger-ui.html` documents every endpoint (admin session required by default; set `GRANTMINT_OPENAPI_ACCESS=public` for open docs in dev).

---

## The signature demo: offline vs online

This is the flow that makes the tradeoff visceral — the dashboard walks it as a guided 7-step page with an in-browser WebCrypto verifier:

```
1. Create a Product + a "Pro" Policy  → entitlements + a 2-seat limit
2. Issue a License                    → receive the signed token + key ID
3. Simulated client activates on Device #1   → ✅ seat 1 of 2
4. ...activates on Device #2                  → ✅ seat 2 of 2
5. ...tries Device #3                         → ❌ blocked: seat limit reached
6. The license keeps working OFFLINE          → ✅ signature verifies, no server
7. You REVOKE the license in the dashboard
8. Next ONLINE check                          → ❌ revoked, access denied
9. The OFFLINE token still passes             → ⚠️ until its next online check-in
```

> ⚠️ Step 9 is the honest, intellectually interesting money-shot: **revocation is an online property.** A token you verify offline cannot be revoked offline. Mitigations — online check-ins, short token lifetimes, and a stretch-goal signed CRL — are part of the documented design.

---

## The offline ↔ online tradeoff

```
            OFFLINE verification                ONLINE validation
            (signature + embedded pubkey)       (server check)
          ┌──────────────────────────────┐    ┌──────────────────────────────┐
 Proves   │ authenticity (Ed25519 sig)    │    │ everything offline proves     │
          │ not-expired (embedded expiry) │    │ + activation / seat counting  │
          │                               │    │ + heartbeats                  │
          │                               │    │ + real-time revocation        │
          ├──────────────────────────────┤    ├──────────────────────────────┤
 Needs    │ nothing — works air-gapped    │    │ connectivity to the server    │
 Cannot   │ revoke, count seats, or       │    │ work when the client is       │
          │ enforce live policy changes   │    │ offline                       │
          └──────────────────────────────┘    └──────────────────────────────┘

  The defining fact: a token you can verify offline is exactly a token you
  CANNOT revoke or seat-count offline. Choose short lifetimes + periodic
  online check-ins to get the best of both. This is a tradeoff, not a flaw.
```

---

## Dual-license model

Grantmint is deliberately split so downstream apps can embed the client without copyleft contagion:

| Component | License | Why |
|---|---|---|
| `grantmint-server`, `grantmint-core`, `grantmint-cli` | **AGPL-3.0** | The server is the product; copyleft keeps improvements open. |
| `grantmint-spring-boot-starter` | **Apache-2.0** | Permissive so closed-source apps can embed the validator freely. |
| Swift + Go verifiers (`verifiers/`) | **Apache-2.0** | Same — drop them into shipping first-party products. |

The starter is **self-contained by construction** — an ArchUnit rule fails the build if its main sources ever touch the AGPL core.

> ℹ️ A Keygen-style fair-source / BUSL split is **deliberately not used**. That model defends a paid hosted service; Grantmint has none.

> ✅ **Yes, you can use the SDK in a closed-source commercial app.** It is Apache-2.0.

---

## Documentation

- **API reference** — Swagger UI at `/swagger-ui.html` on a running server (all three auth schemes documented; admin-gated by default).
- **Cross-verifier contract** — the pinned token fixture consumed by the Java core, the starter, and the Go/Swift suites, guarded in CI by `scripts/check-fixture-parity.py`.
- **Changelog** — [CHANGELOG.md](CHANGELOG.md).
- **Licensing** — [LICENSE](LICENSE) plus per-module license files.

The full design-doc set (architecture, token format, threat model, deployment and operations guides) is maintained alongside the project and will be published with the first public release.

---

## Contributing

Contributions are welcome. New behavior touching issuance, signing, verification, or seat logic must come with **property-based tests** (jqwik), and the **`grantmint-core` module must remain free of framework dependencies** (ArchUnit enforces it, and the build fails otherwise). Run `./mvnw verify` before sending a PR — it runs the unit, property, integration (Testcontainers, needs Docker), and architecture suites.

---

## License

Dual-licensed. **AGPL-3.0** for `grantmint-server`, `grantmint-core`, and `grantmint-cli`; **Apache-2.0** for `grantmint-spring-boot-starter` and the Swift/Go verifiers. See [LICENSE](LICENSE).
