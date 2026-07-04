#!/usr/bin/env bash
#
# Native-image runtime smoke: the full issue → activate → validate → revoke
# cycle against the GraalVM binary and a real PostgreSQL (GRANTMINT-116).
#
# Exercises exactly what the CI boot smoke cannot: the Ed25519 signing path
# (native reflection on the crypto classes), Hibernate jsonb writes (holder,
# entitlements, activation metadata), and the online/offline verdict split
# after a revoke. Fails on the first unexpected status code and finally scans
# the server log for native closed-world errors (MissingReflectionRegistration
# etc.).
#
# Prerequisites:
#   - grantmint-server/target/grantmint-server  (./mvnw -Pnative ... native:compile)
#   - a reachable PostgreSQL with an EMPTY grantmint database, e.g.
#       docker run -d --name gm-native-smoke-pg -e POSTGRES_DB=grantmint \
#         -e POSTGRES_USER=grantmint -e POSTGRES_PASSWORD=grantmint \
#         -p 5433:5432 postgres:16-alpine
#
# Everything, including signing-key registration, runs over the HTTP API
# (GRANTMINT-118), so no direct DB access is needed.
#
# Overridable env: PG_PORT (5433), SERVER_BIN, ADMIN_USER/ADMIN_PASS,
# BASE (http://127.0.0.1:8080), MGMT (http://127.0.0.1:9090).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SERVER_BIN="${SERVER_BIN:-$ROOT/grantmint-server/target/grantmint-server}"
PG_PORT="${PG_PORT:-5433}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-native-smoke-admin-pass}"
BASE="${BASE:-http://127.0.0.1:8080}"
MGMT="${MGMT:-http://127.0.0.1:9090}"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/gm-native-smoke.XXXXXX")"
SERVER_LOG="$WORK/server.log"
SERVER_PID=""

cleanup() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
}
trap cleanup EXIT

fail() {
    echo "SMOKE FAIL: $*" >&2
    echo "--- last 40 server log lines ---" >&2
    tail -40 "$SERVER_LOG" >&2 || true
    echo "(workdir kept at $WORK)" >&2
    exit 1
}

step() { echo ">>> $*"; }

# json_get <field> [<field2> ...]  — reads JSON on stdin, prints nested field.
json_get() {
    python3 -c '
import json, sys
d = json.load(sys.stdin)
for k in sys.argv[1:]:
    d = d[k]
print(d)' "$@"
}

# req <expected_status> <method> <url> [curl args...] — asserts status, prints body.
req() {
    local expected="$1" method="$2" url="$3"
    shift 3
    local out status body
    out="$(curl -sS -X "$method" "$url" -w $'\n%{http_code}' "$@")" \
        || fail "curl $method $url did not complete"
    status="${out##*$'\n'}"
    body="${out%$'\n'*}"
    if [ "$status" != "$expected" ]; then
        fail "$method $url returned $status (expected $expected): $body"
    fi
    printf '%s' "$body"
}

command -v python3 >/dev/null || fail "python3 is required"
[ -x "$SERVER_BIN" ] || fail "native binary not found at $SERVER_BIN"

# --- 0. CLI jar (keygen + offline verify come from grantmint-cli) ------------
step "Preparing the grantmint-cli jar"
CLI_JAR="$(ls "$ROOT"/grantmint-cli/target/grantmint-cli-*.jar 2>/dev/null | head -1 || true)"
if [ -z "$CLI_JAR" ]; then
    (cd "$ROOT" && ./mvnw -q -B -ntp -DskipTests -pl grantmint-cli -am package) \
        || fail "could not build grantmint-cli"
    CLI_JAR="$(ls "$ROOT"/grantmint-cli/target/grantmint-cli-*.jar | head -1)"
fi
CLI="java -jar $CLI_JAR"

# --- 1. Ed25519 keypair via the CLI ------------------------------------------
step "keygen: Ed25519 seed file + public key"
KEYGEN_OUT="$($CLI keygen --out "$WORK/signing.seed")"
PUB_B64="$(echo "$KEYGEN_OUT" | sed -n 's/^Public key (base64): //p')"
KEY_REF="$(echo "$KEYGEN_OUT" | sed -n 's/^Server private_key_ref: //p')"
[ -n "$PUB_B64" ] && [ -n "$KEY_REF" ] || fail "could not parse keygen output: $KEYGEN_OUT"

# --- 2. Boot the native binary ------------------------------------------------
step "Booting the native binary against Postgres :$PG_PORT"
GRANTMINT_DB_URL="jdbc:postgresql://127.0.0.1:$PG_PORT/grantmint" \
GRANTMINT_DB_USER=grantmint \
GRANTMINT_DB_PASSWORD=grantmint \
GRANTMINT_ADMIN_USERNAME="$ADMIN_USER" \
GRANTMINT_ADMIN_PASSWORD="$ADMIN_PASS" \
    "$SERVER_BIN" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 30); do
    if curl -fsS "$MGMT/actuator/health" 2>/dev/null | grep -q '"status":"UP"'; then break; fi
    kill -0 "$SERVER_PID" 2>/dev/null || fail "server exited during startup"
    sleep 1
done
curl -fsS "$MGMT/actuator/health" | grep -q '"status":"UP"' || fail "health never reached UP"

# --- 3. Admin login -----------------------------------------------------------
step "Admin login"
SESS="$(req 200 POST "$BASE/admin/auth/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" | json_get token)"

# --- 4. Product ----------------------------------------------------------------
step "Create product"
PRODUCT_ID="$(req 201 POST "$BASE/admin/products" \
    -H "Authorization: Bearer $SESS" -H 'Content-Type: application/json' \
    -d '{"slug":"native-smoke","name":"Native Smoke","description":"GRANTMINT-116"}' \
    | json_get id)"

# --- 5. Register the signing key over the admin API (GRANTMINT-118) ------------
# The server proves the public key matches the seed behind the ref before
# persisting — this exercises seed resolution + the Ed25519 probe under native.
step "Register signing key via POST /admin/products/{id}/signing-keys"
req 201 POST "$BASE/admin/products/$PRODUCT_ID/signing-keys" \
    -H "Authorization: Bearer $SESS" -H 'Content-Type: application/json' \
    -d "{\"keyId\":\"native-smoke-ed25519\",\"privateKeyRef\":\"$KEY_REF\",\"publicKey\":\"$PUB_B64\",\"makeActive\":true}" >/dev/null

step "Signing-key registration rejects a mismatched public key (400)"
WRONG_PUB="$($CLI keygen --out "$WORK/wrong.seed" | sed -n 's/^Public key (base64): //p')"
req 400 POST "$BASE/admin/products/$PRODUCT_ID/signing-keys" \
    -H "Authorization: Bearer $SESS" -H 'Content-Type: application/json' \
    -d "{\"keyId\":\"native-smoke-mismatch\",\"privateKeyRef\":\"$KEY_REF\",\"publicKey\":\"$WRONG_PUB\",\"makeActive\":false}" >/dev/null

# --- 6. Policy (2 seats, node-locked) ------------------------------------------
step "Create 2-seat policy"
POLICY_ID="$(req 201 POST "$BASE/admin/products/$PRODUCT_ID/policies" \
    -H "Authorization: Bearer $SESS" -H 'Content-Type: application/json' \
    -d '{"code":"smoke-pro","name":"Smoke Pro","activationType":"node_locked","maxSeats":2,"durationDays":30,"gracePeriodDays":7,"trial":false,"heartbeatIntervalSeconds":600,"constraints":{}}' \
    | json_get id)"

# --- 7. API keys ----------------------------------------------------------------
step "Create issuance + validation keys"
ISS_KEY="$(req 201 POST "$BASE/admin/products/$PRODUCT_ID/issuance-keys" \
    -H "Authorization: Bearer $SESS" -H 'Content-Type: application/json' \
    -d '{"name":"smoke-issuance","environment":"live"}' | json_get secret)"
VAL_KEY="$(req 201 POST "$BASE/admin/products/$PRODUCT_ID/validation-keys" \
    -H "Authorization: Bearer $SESS" -H 'Content-Type: application/json' \
    -d '{"name":"smoke-validation"}' | json_get secret)"

# --- 8. Issue — the Ed25519 signing path under native ---------------------------
step "Issue a license (native Ed25519 signing + jsonb holder write)"
ISSUED="$(req 201 POST "$BASE/issuance/licenses" \
    -H "Authorization: Bearer $ISS_KEY" -H 'Content-Type: application/json' \
    -d "{\"policyId\":\"$POLICY_ID\",\"holder\":{\"name\":\"Smoke Tester\",\"email\":\"smoke@example.com\"}}")"
KEY_ID="$(echo "$ISSUED" | json_get keyId)"
TOKEN="$(echo "$ISSUED" | json_get token)"
[ -n "$TOKEN" ] || fail "issuance returned an empty token"

# --- 9. Offline verify of the natively-signed token -----------------------------
step "Offline verify (CLI, no network) of the native-issued token"
$CLI verify --token "$TOKEN" --public-key "$PUB_B64" \
    || fail "offline verification of a freshly issued native token failed"

# --- 10. Online validate ---------------------------------------------------------
step "Online validate"
VALID="$(req 200 POST "$BASE/v1/licenses/validate" \
    -H "X-Grantmint-Validation: $VAL_KEY" -H 'Content-Type: application/json' \
    -d "{\"keyId\":\"$KEY_ID\"}" | json_get valid)"
[ "$VALID" = "True" ] || [ "$VALID" = "true" ] || fail "validate returned valid=$VALID"

# --- 11. Activations: 2 seats, idempotent re-activation, 3rd blocked -------------
step "Activate seat 1 (fp-alpha)"
req 201 POST "$BASE/v1/licenses/activate" \
    -H "X-Grantmint-Validation: $VAL_KEY" -H 'Content-Type: application/json' \
    -d "{\"keyId\":\"$KEY_ID\",\"fingerprint\":\"fp-alpha\",\"name\":\"machine-a\"}" >/dev/null

step "Re-activate fp-alpha (idempotent, must NOT burn a seat)"
REACT="$(req 200 POST "$BASE/v1/licenses/activate" \
    -H "X-Grantmint-Validation: $VAL_KEY" -H 'Content-Type: application/json' \
    -d "{\"keyId\":\"$KEY_ID\",\"fingerprint\":\"fp-alpha\"}" | json_get reactivated)"
[ "$REACT" = "True" ] || [ "$REACT" = "true" ] || fail "re-activation not reported idempotent"

step "Activate seat 2 (fp-beta)"
req 201 POST "$BASE/v1/licenses/activate" \
    -H "X-Grantmint-Validation: $VAL_KEY" -H 'Content-Type: application/json' \
    -d "{\"keyId\":\"$KEY_ID\",\"fingerprint\":\"fp-beta\"}" >/dev/null

step "Activate seat 3 (fp-gamma) — must hit the seat limit"
LIMIT_ERR="$(req 409 POST "$BASE/v1/licenses/activate" \
    -H "X-Grantmint-Validation: $VAL_KEY" -H 'Content-Type: application/json' \
    -d "{\"keyId\":\"$KEY_ID\",\"fingerprint\":\"fp-gamma\"}" | json_get error)"
[ "$LIMIT_ERR" = "seat_limit_exceeded" ] || fail "expected seat_limit_exceeded, got $LIMIT_ERR"

# --- 12. Heartbeat ----------------------------------------------------------------
step "Heartbeat fp-alpha"
req 200 POST "$BASE/v1/licenses/heartbeat" \
    -H "X-Grantmint-Validation: $VAL_KEY" -H 'Content-Type: application/json' \
    -d "{\"keyId\":\"$KEY_ID\",\"fingerprint\":\"fp-alpha\"}" >/dev/null

# --- 13. Revoke, then the honest offline/online split ------------------------------
step "Revoke the license"
REV_STATUS="$(req 200 DELETE "$BASE/issuance/licenses/$KEY_ID" \
    -H "Authorization: Bearer $ISS_KEY" -H 'Content-Type: application/json' \
    -d '{"reason":"native smoke"}' | json_get status)"
[ "$REV_STATUS" = "revoked" ] || fail "revoke returned status=$REV_STATUS"

step "Online validate after revoke — must be 422 license_revoked"
REV_ERR="$(req 422 POST "$BASE/v1/licenses/validate" \
    -H "X-Grantmint-Validation: $VAL_KEY" -H 'Content-Type: application/json' \
    -d "{\"keyId\":\"$KEY_ID\"}" | json_get error)"
[ "$REV_ERR" = "license_revoked" ] || fail "expected license_revoked, got $REV_ERR"

step "Offline verify after revoke — still passes (the documented offline↔online tradeoff)"
$CLI verify --token "$TOKEN" --public-key "$PUB_B64" \
    || fail "offline token stopped verifying after an ONLINE revoke — that would mean the wire format leaked online state"

# --- 14. Native closed-world error scan --------------------------------------------
step "Scanning the server log for native-image registration errors"
if grep -nE 'MissingReflectionRegistrationError|MissingSerializationRegistrationError|MissingProxyRegistrationError|MissingResourceRegistrationError|UnsupportedFeatureError' "$SERVER_LOG"; then
    fail "native closed-world violations found in the server log"
fi

echo
echo "NATIVE SMOKE PASS: issue → offline verify → validate → activate x2 (+idempotent, +seat-limit 409) → heartbeat → revoke → 422 online / offline-still-valid. No native registration errors."
rm -rf "$WORK"
