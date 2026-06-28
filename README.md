# Grantmint

> A self-hostable, single-binary **license & entitlement server** for the JVM. It issues **authentic, cryptographically sealed credentials** your apps can verify **offline** — and adds online activation, seat counting, and revocation when you need richer control.

**Last Updated: 2026-06-28**

[![Build](https://img.shields.io/github/actions/workflow/status/hg/grantmint/ci.yml?branch=main)](https://github.com/hg/grantmint/actions)
[![License: AGPL-3.0 (server) / Apache-2.0 (SDK)](https://img.shields.io/badge/license-AGPL--3.0%20server%20%2F%20Apache--2.0%20SDK-blue.svg)](LICENSE)
[![Java 21](https://img.shields.io/badge/Java-21-orange.svg)](https://openjdk.org/projects/jdk/21/)
[![GraalVM Native](https://img.shields.io/badge/GraalVM-native--image-purple.svg)](https://www.graalvm.org/)

![demo](docs/assets/demo.gif)

---

## Table of Contents

- [The elevator pitch](#the-elevator-pitch)
- [What Grantmint is — and is not](#what-grantmint-is--and-is-not)
- [Key features](#key-features)
- [How it compares](#how-it-compares)
- [Tech stack](#tech-stack)
- [Module structure](#module-structure)
- [5-minute quick start](#5-minute-quick-start)
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

- **Signed-token issuance** — issue a license from a policy and receive an Ed25519-signed token (embedding entitlements, expiry, holder, constraints) plus a short, human-readable **key ID** like `GRNT-7F3A-9KQ2-X4M8`.
- **Offline verification** — clients verify the signed token against an embedded public key with **zero network**.
- **Online validation** — `validate` / `activate` / `deactivate` / `heartbeat` against the server for richer control.
- **Node-locked activation** — machine fingerprinting + per-license **seat limits** (max machines per license). Floating/concurrent licenses are deferred — see [ROADMAP](docs/reference/ROADMAP.md).
- **Entitlements** — named feature flags (`team_sync`) and numeric limits (`max_devices=5`), defined per policy, carried inside the token, and checkable both offline and online.
- **License lifecycle** — trials, expiry, grace periods, suspend/reinstate, and online revocation, modeled as an explicit state machine (`created → active → suspended → expired → revoked`).
- **Admin REST API + minimal React/TS dashboard** — manage products, policies, entitlements, licenses, and activations; issue and revoke.
- **Three auth schemes** — admin/dashboard auth, per-product issuance API keys, and a license-validation auth scheme. **No end-user signup/login/OAuth.**
- **`grantmint-spring-boot-starter`** (Apache-2.0) — drop-in validation/entitlement checks for any Spring Boot app in ~20 lines + an embedded public key.
- **Swift & Go verifiers** — documented offline-verifier snippets (Apple CryptoKit, Go `ed25519` stdlib) for first-party clients.
- **Pluggable payment-webhook adapter** — Strategy + auto-configuration, with **Stripe** as the reference adapter that auto-issues/suspends/expires licenses.
- **Background jobs** — expiry sweeps and heartbeat-timeout deactivation.
- **Single-binary distribution** — GraalVM native image with sub-50ms startup.
- **Observability** — Micrometer metrics (issuance count, validation latency, active licenses, activation/seat counts) with a Prometheus scrape endpoint.

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
| API docs | springdoc-openapi | Swagger UI + OpenAPI 3 |
| Crypto | Ed25519 | Signed structured token + short key ID; offline-verifiable |
| Crypto core | `grantmint-core` | Pure Java, **zero Spring deps** (enforced by ArchUnit) |
| Database | PostgreSQL | Primary, via Spring Data JPA + Flyway migrations |
| Cache | Caffeine | In-process cache on the validation hot path |
| Optional cache | Redis | Optional profile for multi-node deployments |
| CLI | Picocli | `grantmint-cli` — issue/inspect/revoke + offline verify |
| Dashboard | React 18 + TypeScript + Vite + Tailwind | Minimal operator console |
| Native build | GraalVM native image | Single binary, sub-50ms startup |
| Observability | Micrometer + Prometheus | Issuance, validation latency, active licenses, seats |
| Tests | Testcontainers + jqwik + ArchUnit | Integration, property-based, architecture |

See [TECH_STACK.md](docs/architecture/TECH_STACK.md) for the rationale behind each choice.

---

## Module structure

```
grantmint/
├── grantmint-core                 # Pure-Java crypto/issuance core (AGPL-3.0)
│                                  #   Ed25519 keys, signed-token build/verify,
│                                  #   key-ID scheme, entitlement encoding.
│                                  #   ZERO Spring dependencies (ArchUnit-enforced).
├── grantmint-server               # Spring Boot app (AGPL-3.0)
│                                  #   REST API, JPA persistence, Flyway, security,
│                                  #   lifecycle state machine, webhook adapters,
│                                  #   background jobs, native-image build.
├── grantmint-spring-boot-starter  # Client SDK (Apache-2.0)
│                                  #   Auto-configured validation/entitlement bean.
├── grantmint-cli                  # Picocli CLI (AGPL-3.0)
│                                  #   issue / inspect / revoke / verify-offline.
└── dashboard                      # React 18 + TS + Vite + Tailwind operator console
```

Base package / Maven groupId: **`dev.hg.grantmint`**.

---

## 5-minute quick start

Two paths below. Both end with you issuing a license and verifying its token **offline** with the CLI.

### Option A — Docker Compose (app + Postgres)

```bash
# 1. Clone and start the stack (server + Postgres).
git clone https://github.com/hg/grantmint.git
cd grantmint
docker compose up -d

# 2. Generate a signing key pair (the private key is the crown jewel).
#    The server writes the public key to ./keys/ed25519.pub for client embedding.
docker compose exec grantmint grantmint keys generate --out /keys

# 3. The server is now at http://localhost:8080  (Swagger UI at /swagger-ui.html)
curl -s http://localhost:8080/actuator/health
# {"status":"UP"}
```

### Option B — native binary (no Docker)

```bash
# 1. Download the single self-contained native binary (sub-50ms startup).
curl -L -o grantmint https://github.com/hg/grantmint/releases/latest/download/grantmint-linux-amd64
chmod +x grantmint

# 2. Point it at a Postgres instance and start.
export GRANTMINT_DB_URL="jdbc:postgresql://localhost:5432/grantmint"
export GRANTMINT_DB_USER="grantmint"
export GRANTMINT_DB_PASSWORD="change-me"
./grantmint keys generate --out ./keys
./grantmint server
```

### Issue and verify a license

```bash
# Set the admin issuance API key the server printed on first start.
export GRANTMINT_API_KEY="gm_issue_1a2b3c4d..."

# 1. Create a Product.
curl -s -X POST http://localhost:8080/api/v1/products \
  -H "Authorization: Bearer $GRANTMINT_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"Acme Studio","slug":"acme-studio"}'

# 2. Create a "Pro Annual" Policy with entitlements and a 2-seat limit.
curl -s -X POST http://localhost:8080/api/v1/products/acme-studio/policies \
  -H "Authorization: Bearer $GRANTMINT_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
        "name": "Pro Annual",
        "durationDays": 365,
        "maxSeats": 2,
        "nodeLocked": true,
        "entitlements": { "team_sync": true, "max_devices": 2 }
      }'

# 3. Issue a License to a customer.
curl -s -X POST http://localhost:8080/api/v1/policies/pro-annual/licenses \
  -H "Authorization: Bearer $GRANTMINT_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"holderName":"Jane Doe","holderEmail":"jane@example.com"}'
# => { "keyId": "GRNT-7F3A-9KQ2-X4M8",
#      "token": "gm1.eyJ...signed-ed25519-token...",
#      "status": "ACTIVE", "expiresAt": "2027-06-28T00:00:00Z" }

# 4. Verify the token OFFLINE — no server, just the embedded public key.
./grantmint verify \
  --token "gm1.eyJ...signed-ed25519-token..." \
  --public-key ./keys/ed25519.pub
# ✅ Signature VALID  |  holder=Jane Doe  |  expires=2027-06-28
#    entitlements: team_sync=true, max_devices=2
```

That is the full loop: a product, a policy, an issued license, and a token your client can prove is authentic **with no network**. For the detailed walkthrough see [QUICK_START.md](docs/getting-started/QUICK_START.md) and [SETUP_GUIDE.md](docs/getting-started/SETUP_GUIDE.md).

---

## The signature demo: offline vs online

This is the flow that makes the tradeoff visceral (and the one in the GIF above):

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

> ⚠️ Step 9 is the honest, intellectually interesting money-shot: **revocation is an online property.** A token you verify offline cannot be revoked offline. Mitigations — online check-ins, short token lifetimes, and the stretch-goal signed CRL — are documented in [LICENSE_LIFECYCLE.md](docs/features/LICENSE_LIFECYCLE.md).

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

Full treatment in [ARCHITECTURE.md](docs/architecture/ARCHITECTURE.md) and [LICENSE_LIFECYCLE.md](docs/features/LICENSE_LIFECYCLE.md).

---

## Dual-license model

Grantmint is deliberately split so downstream apps can embed the client without copyleft contagion:

| Component | License | Why |
|---|---|---|
| `grantmint-server`, `grantmint-core`, `grantmint-cli` | **AGPL-3.0** | The server is the product; copyleft keeps improvements open. |
| `grantmint-spring-boot-starter` | **Apache-2.0** | Permissive so closed-source apps can embed the validator freely. |
| Swift + Go verifier snippets | **Apache-2.0** | Same — drop them into shipping first-party products. |

> ℹ️ A Keygen-style fair-source / BUSL split is **deliberately not used**. That model defends a paid hosted service; Grantmint has none. The rationale is documented in [OPERATOR_AND_LICENSE_NOTES.md](docs/security/OPERATOR_AND_LICENSE_NOTES.md).

> ✅ **Yes, you can use the SDK in a closed-source commercial app.** It is Apache-2.0.

---

## Documentation

### Getting started
- [Quick Start](docs/getting-started/QUICK_START.md) — TL;DR for experienced devs
- [Setup Guide](docs/getting-started/SETUP_GUIDE.md) — full local setup
- [Development Guide](docs/getting-started/DEVELOPMENT_GUIDE.md) — module layout, conventions, the no-Spring-in-core rule

### Architecture
- [Architecture](docs/architecture/ARCHITECTURE.md) — flows, diagrams, the offline↔online tradeoff
- [Tech Stack](docs/architecture/TECH_STACK.md) — every choice justified
- [Database Schema](docs/architecture/DATABASE_SCHEMA.md) — products, policies, licenses, activations

### API
- [API Documentation](docs/api/API_DOCUMENTATION.md) — admin/issuance + client/validation endpoints

### Features
- [Admin & API Auth](docs/features/ADMIN_AND_API_AUTH.md) — the three auth schemes
- [License Token Format](docs/features/LICENSE_TOKEN_FORMAT.md) — the signed-token structure
- [Activation & Seats](docs/features/ACTIVATION_AND_SEATS.md) — node-locking, fingerprinting, heartbeats
- [Entitlements](docs/features/ENTITLEMENTS.md) — feature flags + numeric limits
- [License Lifecycle](docs/features/LICENSE_LIFECYCLE.md) — the state machine + revocation honesty
- [Client SDK](docs/features/CLIENT_SDK.md) — the starter + Swift/Go verifiers
- [Webhook Integration](docs/features/WEBHOOK_INTEGRATION.md) — the Stripe reference adapter

### Deployment & operations
- [Deployment Guide](docs/deployment/DEPLOYMENT_GUIDE.md)
- [Docker Setup](docs/deployment/DOCKER_SETUP.md)
- [CI/CD](docs/deployment/CI_CD.md)
- [Scaling Guide](docs/deployment/SCALING_GUIDE.md)
- [Monitoring & Logging](docs/operations/MONITORING_LOGGING.md)
- [Maintenance](docs/operations/MAINTENANCE.md)
- [Troubleshooting](docs/operations/TROUBLESHOOTING.md)

### Security & compliance
- [Security](docs/security/SECURITY.md) — threat model, signing-key protection
- [Operator & License Notes](docs/security/OPERATOR_AND_LICENSE_NOTES.md) — PII handling + license rationale

### Testing & contributing
- [Testing](docs/testing/TESTING.md) — the property-based test suite as a centerpiece
- [Contributing](docs/contributing/CONTRIBUTING.md)

### Reference
- [FAQ](docs/reference/FAQ.md)
- [Roadmap](docs/reference/ROADMAP.md)
- [Self-Hosting Footprint](docs/reference/SELF_HOSTING_FOOTPRINT.md)
- [Performance Optimization](docs/reference/PERFORMANCE_OPTIMIZATION.md)
- [Internationalization](docs/reference/INTERNATIONALIZATION.md)
- [Accessibility](docs/reference/ACCESSIBILITY.md)

### Project
- [Changelog](CHANGELOG.md)
- [License](LICENSE)

---

## Contributing

Contributions are welcome. New behavior must come with **property-based tests** (jqwik) for the issue/verify/expire/seat invariants, and the **`grantmint-core` module must remain free of Spring dependencies** (ArchUnit enforces it). See [CONTRIBUTING.md](docs/contributing/CONTRIBUTING.md) and [TESTING.md](docs/testing/TESTING.md).

---

## License

Dual-licensed. **AGPL-3.0** for `grantmint-server`, `grantmint-core`, and `grantmint-cli`; **Apache-2.0** for `grantmint-spring-boot-starter` and the documented Swift/Go verifiers. See [LICENSE](LICENSE) and [OPERATOR_AND_LICENSE_NOTES.md](docs/security/OPERATOR_AND_LICENSE_NOTES.md).

---

## Related Documentation

- [Architecture](docs/architecture/ARCHITECTURE.md)
- [Tech Stack](docs/architecture/TECH_STACK.md)
- [License Token Format](docs/features/LICENSE_TOKEN_FORMAT.md)
- [License Lifecycle](docs/features/LICENSE_LIFECYCLE.md)
- [FAQ](docs/reference/FAQ.md)
- [Changelog](CHANGELOG.md)
