import { useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { api, ApiError } from '../api/client';
import type {
  ActivateResponse,
  ApiErrorBody,
  IssueLicenseResponse,
  Policy,
  Product,
  ValidateResponse,
} from '../api/types';
import { browserSupportsEd25519, verifyTokenOffline } from '../lib/tokenVerify';
import type { OfflineVerificationResult } from '../lib/tokenVerify';
import { randomFingerprint } from '../lib/random';
import Alert from '../components/Alert';
import FormField, { buttonClasses, inputClasses, secondaryButtonClasses } from '../components/FormField';

// ─── Small helper: call the v1 validation-key surface directly (not the admin client — different
// auth scheme, no cookie/XSRF involved). ────────────────────────────────────────────────────────

interface ValidationCallResult<T> {
  ok: boolean;
  status: number;
  data?: T;
  errorBody?: ApiErrorBody;
}

async function callValidationApi<T>(path: string, validationKey: string, body: unknown): Promise<ValidationCallResult<T>> {
  const response = await fetch(path, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Grantmint-Validation': validationKey,
    },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  const parsed = text.length > 0 ? (JSON.parse(text) as unknown) : undefined;
  if (response.ok) {
    return { ok: true, status: response.status, data: parsed as T };
  }
  return { ok: false, status: response.status, errorBody: parsed as ApiErrorBody };
}

// ─── Step state ──────────────────────────────────────────────────────────────

type StepState<T> =
  | { kind: 'idle' }
  | { kind: 'loading' }
  | { kind: 'success'; result: T }
  | { kind: 'error'; status: number; body?: ApiErrorBody };

function StepCard({
  index,
  title,
  description,
  action,
  disabled,
  children,
}: {
  index: number;
  title: string;
  description: string;
  action: ReactNode;
  disabled?: boolean;
  children?: ReactNode;
}) {
  return (
    <li className={`rounded-lg border border-gray-800 bg-gray-900 p-4 ${disabled ? 'opacity-60' : ''}`}>
      <div className="flex items-start gap-3">
        <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-indigo-600 text-xs font-semibold text-white">
          {index}
        </span>
        <div className="flex-1 space-y-2">
          <h3 className="text-sm font-semibold text-gray-100">{title}</h3>
          <p className="text-sm text-gray-400">{description}</p>
          {action}
          {children}
        </div>
      </div>
    </li>
  );
}

export default function DemoPage() {
  const [validationKey, setValidationKey] = useState('');
  const [keyId, setKeyId] = useState('');
  const [token, setToken] = useState('');
  const [publicKeyBase64, setPublicKeyBase64] = useState('');

  const [fingerprintA] = useState(randomFingerprint);
  const [fingerprintB] = useState(randomFingerprint);
  const [fingerprintC] = useState(randomFingerprint);

  const [stepA, setStepA] = useState<StepState<ActivateResponse>>({ kind: 'idle' });
  const [stepB, setStepB] = useState<StepState<ActivateResponse>>({ kind: 'idle' });
  const [stepC, setStepC] = useState<StepState<ActivateResponse>>({ kind: 'idle' });
  const [offlineBefore, setOfflineBefore] = useState<StepState<OfflineVerificationResult>>({ kind: 'idle' });
  const [revokeStep, setRevokeStep] = useState<StepState<{ revoked: true }>>({ kind: 'idle' });
  const [validateAfterRevoke, setValidateAfterRevoke] = useState<StepState<ValidateResponse>>({ kind: 'idle' });
  const [offlineAfter, setOfflineAfter] = useState<StepState<OfflineVerificationResult>>({ kind: 'idle' });

  const readyForOnlineSteps = validationKey.trim().length > 0 && keyId.trim().length > 0;
  const readyForOfflineSteps = token.trim().length > 0 && publicKeyBase64.trim().length > 0;
  const ed25519Supported = browserSupportsEd25519();

  function resetTimeline() {
    setStepA({ kind: 'idle' });
    setStepB({ kind: 'idle' });
    setStepC({ kind: 'idle' });
    setOfflineBefore({ kind: 'idle' });
    setRevokeStep({ kind: 'idle' });
    setValidateAfterRevoke({ kind: 'idle' });
    setOfflineAfter({ kind: 'idle' });
  }

  async function runActivate(fingerprint: string, setState: (s: StepState<ActivateResponse>) => void) {
    setState({ kind: 'loading' });
    const result = await callValidationApi<ActivateResponse>('/v1/licenses/activate', validationKey, {
      keyId,
      fingerprint,
    });
    if (result.ok && result.data) {
      setState({ kind: 'success', result: result.data });
    } else {
      setState({ kind: 'error', status: result.status, body: result.errorBody });
    }
  }

  async function runOfflineCheck(setState: (s: StepState<OfflineVerificationResult>) => void) {
    setState({ kind: 'loading' });
    try {
      const verification = await verifyTokenOffline(token, publicKeyBase64);
      setState({ kind: 'success', result: verification });
    } catch (err) {
      setState({ kind: 'error', status: 0, body: { error: 'offline_verify_failed', message: (err as Error).message } });
    }
  }

  async function runRevoke() {
    setRevokeStep({ kind: 'loading' });
    try {
      await api.delete(`/admin/licenses/${keyId}`, { reason: 'Grantmint operator console demo' });
      setRevokeStep({ kind: 'success', result: { revoked: true } });
    } catch (err) {
      if (err instanceof ApiError) {
        setRevokeStep({ kind: 'error', status: err.status, body: { error: err.code ?? 'error', message: err.message } });
      } else {
        setRevokeStep({ kind: 'error', status: 0, body: { error: 'error', message: 'Revoke failed.' } });
      }
    }
  }

  async function runValidateAfterRevoke() {
    setValidateAfterRevoke({ kind: 'loading' });
    const result = await callValidationApi<ValidateResponse>('/v1/licenses/validate', validationKey, { keyId });
    if (result.ok && result.data) {
      setValidateAfterRevoke({ kind: 'success', result: result.data });
    } else {
      setValidateAfterRevoke({ kind: 'error', status: result.status, body: result.errorBody });
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-white">Offline ↔ online demo</h1>
        <p className="mt-1 max-w-2xl text-sm text-gray-400">
          A signed token you can verify offline is exactly one you cannot revoke or seat-count without
          connectivity. This walkthrough proves both halves of that tradeoff with one real license.
        </p>
      </div>

      <SetupPanel
        validationKey={validationKey}
        setValidationKey={setValidationKey}
        keyId={keyId}
        setKeyId={setKeyId}
        token={token}
        setToken={setToken}
        publicKeyBase64={publicKeyBase64}
        setPublicKeyBase64={setPublicKeyBase64}
        onIssued={() => resetTimeline()}
      />

      <ol className="space-y-4">
        <StepCard
          index={1}
          title="Activate device A"
          description={`Claim a seat with fingerprint ${fingerprintA}.`}
          disabled={!readyForOnlineSteps}
          action={
            <button
              type="button"
              className={buttonClasses}
              disabled={!readyForOnlineSteps || stepA.kind === 'loading'}
              onClick={() => void runActivate(fingerprintA, setStepA)}
            >
              {stepA.kind === 'loading' ? 'Activating…' : 'Activate device A'}
            </button>
          }
        >
          <StepResult state={stepA} successCopy={(r) => `Seat claimed. Seats used: ${r.seatsUsed}/${r.seatsTotal}.`} />
        </StepCard>

        <StepCard
          index={2}
          title="Activate device B"
          description={`Claim a second seat with fingerprint ${fingerprintB}.`}
          disabled={!readyForOnlineSteps}
          action={
            <button
              type="button"
              className={buttonClasses}
              disabled={!readyForOnlineSteps || stepB.kind === 'loading'}
              onClick={() => void runActivate(fingerprintB, setStepB)}
            >
              {stepB.kind === 'loading' ? 'Activating…' : 'Activate device B'}
            </button>
          }
        >
          <StepResult state={stepB} successCopy={(r) => `Seat claimed. Seats used: ${r.seatsUsed}/${r.seatsTotal}.`} />
        </StepCard>

        <StepCard
          index={3}
          title="Activate device C — expect the seat limit to bite"
          description={`Try a third device (${fingerprintC}) on a 2-seat license. This should be REJECTED with 409 seat_limit_exceeded — that rejection is the feature working.`}
          disabled={!readyForOnlineSteps}
          action={
            <button
              type="button"
              className={buttonClasses}
              disabled={!readyForOnlineSteps || stepC.kind === 'loading'}
              onClick={() => void runActivate(fingerprintC, setStepC)}
            >
              {stepC.kind === 'loading' ? 'Activating…' : 'Activate device C'}
            </button>
          }
        >
          {stepC.kind === 'error' && stepC.status === 409 ? (
            <Alert kind="success">
              Seat limit enforced as expected: {stepC.body?.error ?? 'seat_limit_exceeded'} — {stepC.body?.message}
            </Alert>
          ) : (
            <StepResult state={stepC} successCopy={() => 'Unexpected: this activation succeeded — seat limit was not enforced.'} />
          )}
        </StepCard>

        <StepCard
          index={4}
          title="Offline check — verify the token in this browser"
          description="No server call. WebCrypto verifies the Ed25519 signature over the token locally using only the pasted public key."
          disabled={!readyForOfflineSteps}
          action={
            !ed25519Supported ? (
              <Alert kind="info">Offline verification unavailable in this browser (no WebCrypto Ed25519 support).</Alert>
            ) : (
              <button
                type="button"
                className={buttonClasses}
                disabled={!readyForOfflineSteps || offlineBefore.kind === 'loading'}
                onClick={() => void runOfflineCheck(setOfflineBefore)}
              >
                {offlineBefore.kind === 'loading' ? 'Verifying…' : 'Run offline check'}
              </button>
            )
          }
        >
          <OfflineResult state={offlineBefore} />
        </StepCard>

        <StepCard
          index={5}
          title="Revoke the license"
          description="Terminal action via the admin API. After this, online validation must reject the license."
          disabled={!readyForOnlineSteps}
          action={
            <button
              type="button"
              className="rounded-md bg-red-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-red-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-500 disabled:opacity-60"
              disabled={!readyForOnlineSteps || revokeStep.kind === 'loading'}
              onClick={() => void runRevoke()}
            >
              {revokeStep.kind === 'loading' ? 'Revoking…' : 'Revoke license'}
            </button>
          }
        >
          {revokeStep.kind === 'success' && <Alert kind="success">License revoked.</Alert>}
          {revokeStep.kind === 'error' && (
            <Alert kind="error">
              {revokeStep.body?.error ?? 'error'} — {revokeStep.body?.message}
            </Alert>
          )}
        </StepCard>

        <StepCard
          index={6}
          title="Online validate after revoke — expect 422"
          description="The online layer knows about revocation immediately."
          disabled={!readyForOnlineSteps}
          action={
            <button
              type="button"
              className={buttonClasses}
              disabled={!readyForOnlineSteps || validateAfterRevoke.kind === 'loading'}
              onClick={() => void runValidateAfterRevoke()}
            >
              {validateAfterRevoke.kind === 'loading' ? 'Validating…' : 'Validate license'}
            </button>
          }
        >
          {validateAfterRevoke.kind === 'error' && validateAfterRevoke.status === 422 ? (
            <Alert kind="success">
              Correctly rejected: {validateAfterRevoke.body?.error ?? 'license_revoked'} —{' '}
              {validateAfterRevoke.body?.message}
            </Alert>
          ) : (
            <StepResult state={validateAfterRevoke} successCopy={() => 'Unexpected: validation still reports valid.'} />
          )}
        </StepCard>

        <StepCard
          index={7}
          title="Offline check again — still VALID"
          description="Re-run the same offline verification against the same token. It still passes: the token cannot un-sign itself. This is the documented offline-revocation window, closed only by the token's own expiry (exp)."
          disabled={!readyForOfflineSteps}
          action={
            ed25519Supported && (
              <button
                type="button"
                className={buttonClasses}
                disabled={!readyForOfflineSteps || offlineAfter.kind === 'loading'}
                onClick={() => void runOfflineCheck(setOfflineAfter)}
              >
                {offlineAfter.kind === 'loading' ? 'Verifying…' : 'Run offline check again'}
              </button>
            )
          }
        >
          <OfflineResult state={offlineAfter} />
          {offlineAfter.kind === 'success' && offlineAfter.result.signatureValid && !offlineAfter.result.expired && (
            <Alert kind="info">
              This is expected and honest, not a bug: offline verification only proves authenticity and expiry — it
              has no way to know the license was revoked online. See docs/features/LICENSE_TOKEN_FORMAT.md.
            </Alert>
          )}
        </StepCard>
      </ol>
    </div>
  );
}

function StepResult<T>({ state, successCopy }: { state: StepState<T>; successCopy: (result: T) => string }) {
  if (state.kind === 'idle' || state.kind === 'loading') return null;
  if (state.kind === 'success') return <Alert kind="success">{successCopy(state.result)}</Alert>;
  return (
    <Alert kind="error">
      {state.status ? `HTTP ${state.status} — ` : ''}
      {state.body?.error ?? 'error'}: {state.body?.message ?? 'Request failed.'}
    </Alert>
  );
}

function OfflineResult({ state }: { state: StepState<OfflineVerificationResult> }) {
  if (state.kind === 'idle' || state.kind === 'loading') return null;
  if (state.kind === 'error') {
    return (
      <Alert kind="error">{state.body?.message ?? 'Offline verification failed.'}</Alert>
    );
  }
  const { signatureValid, expired, notYetValid, payload } = state.result;
  const overallValid = signatureValid && !expired && !notYetValid;
  return (
    <div className="space-y-2">
      <Alert kind={overallValid ? 'success' : 'error'}>
        {overallValid
          ? 'VALID — signature verified locally, no network call made.'
          : `INVALID — signatureValid=${signatureValid}, expired=${expired}, notYetValid=${notYetValid}.`}
      </Alert>
      <div className="rounded-md border border-gray-800 bg-gray-950 p-3">
        <p className="text-xs font-semibold uppercase tracking-wider text-gray-500">Decoded claims (offline, unverified against the server)</p>
        <pre className="mt-1 overflow-x-auto text-xs text-gray-300">{JSON.stringify(payload, null, 2)}</pre>
      </div>
    </div>
  );
}

interface SetupPanelProps {
  validationKey: string;
  setValidationKey: (v: string) => void;
  keyId: string;
  setKeyId: (v: string) => void;
  token: string;
  setToken: (v: string) => void;
  publicKeyBase64: string;
  setPublicKeyBase64: (v: string) => void;
  onIssued: () => void;
}

function SetupPanel({
  validationKey,
  setValidationKey,
  keyId,
  setKeyId,
  token,
  setToken,
  publicKeyBase64,
  setPublicKeyBase64,
  onIssued,
}: SetupPanelProps) {
  const [showIssue, setShowIssue] = useState(false);
  const [products, setProducts] = useState<Product[]>([]);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [productId, setProductId] = useState('');
  const [policyId, setPolicyId] = useState('');
  const [holderName, setHolderName] = useState('Demo User');
  const [holderEmail, setHolderEmail] = useState('demo@example.com');
  const [issuing, setIssuing] = useState(false);
  const [issueError, setIssueError] = useState<string | null>(null);

  useEffect(() => {
    if (!showIssue) return;
    api
      .get<Product[]>('/admin/products')
      .then((data) => {
        setProducts(data);
        if (data.length > 0) setProductId(data[0].id);
      })
      .catch(() => setIssueError('Failed to load products.'));
  }, [showIssue]);

  useEffect(() => {
    if (!productId) return;
    api
      .get<Policy[]>(`/admin/products/${productId}/policies`)
      .then((data) => {
        setPolicies(data);
        const twoSeat = data.find((p) => p.maxSeats === 2);
        setPolicyId((twoSeat ?? data[0])?.id ?? '');
      })
      .catch(() => setIssueError('Failed to load policies.'));
  }, [productId]);

  async function handleIssue() {
    setIssuing(true);
    setIssueError(null);
    try {
      const response = await api.post<IssueLicenseResponse>('/admin/licenses', {
        productId,
        policyId,
        holder: { name: holderName, email: holderEmail },
      });
      setKeyId(response.keyId);
      setToken(response.token);
      onIssued();
    } catch (err) {
      setIssueError(err instanceof ApiError ? err.message : 'Failed to issue demo license.');
    } finally {
      setIssuing(false);
    }
  }

  return (
    <div className="space-y-4 rounded-lg border border-gray-800 bg-gray-900 p-4">
      <h2 className="text-sm font-semibold text-gray-200">Setup</h2>
      <div className="grid gap-4 sm:grid-cols-2">
        <FormField id="demo-validation-key" label="Validation API key" hint="gm_val_… — pasted by the operator">
          <input
            id="demo-validation-key"
            className={`${inputClasses} font-mono`}
            value={validationKey}
            onChange={(e) => setValidationKey(e.target.value)}
            placeholder="gm_val_..."
          />
        </FormField>
        <FormField id="demo-public-key" label="Ed25519 public key (base64)" hint="Used only for the in-browser offline check">
          <input
            id="demo-public-key"
            className={`${inputClasses} font-mono`}
            value={publicKeyBase64}
            onChange={(e) => setPublicKeyBase64(e.target.value)}
            placeholder="base64-encoded 32-byte public key"
          />
        </FormField>
        <FormField id="demo-key-id" label="License key ID">
          <input
            id="demo-key-id"
            className={`${inputClasses} font-mono`}
            value={keyId}
            onChange={(e) => setKeyId(e.target.value)}
            placeholder="K7P2-9QXM-4T1Y"
          />
        </FormField>
        <FormField id="demo-token" label="Signed token">
          <textarea
            id="demo-token"
            rows={2}
            className={`${inputClasses} font-mono`}
            value={token}
            onChange={(e) => setToken(e.target.value)}
            placeholder="eyJ...header.eyJ...payload.signature"
          />
        </FormField>
      </div>

      <button type="button" className={secondaryButtonClasses} onClick={() => setShowIssue((v) => !v)}>
        {showIssue ? 'Hide issue form' : 'Or issue a demo license now'}
      </button>

      {showIssue && (
        <div className="grid gap-4 rounded-md border border-gray-800 p-3 sm:grid-cols-2">
          {issueError && (
            <div className="sm:col-span-2">
              <Alert kind="error">{issueError}</Alert>
            </div>
          )}
          <FormField id="demo-issue-product" label="Product">
            <select id="demo-issue-product" className={inputClasses} value={productId} onChange={(e) => setProductId(e.target.value)}>
              {products.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          </FormField>
          <FormField id="demo-issue-policy" label="Policy" hint="A 2-seat policy is pre-selected when available">
            <select id="demo-issue-policy" className={inputClasses} value={policyId} onChange={(e) => setPolicyId(e.target.value)}>
              {policies.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} ({p.maxSeats} seats)
                </option>
              ))}
            </select>
          </FormField>
          <FormField id="demo-issue-holder-name" label="Holder name">
            <input id="demo-issue-holder-name" className={inputClasses} value={holderName} onChange={(e) => setHolderName(e.target.value)} />
          </FormField>
          <FormField id="demo-issue-holder-email" label="Holder email">
            <input
              id="demo-issue-holder-email"
              type="email"
              className={inputClasses}
              value={holderEmail}
              onChange={(e) => setHolderEmail(e.target.value)}
            />
          </FormField>
          <div className="sm:col-span-2">
            <button type="button" className={buttonClasses} disabled={issuing || !policyId} onClick={() => void handleIssue()}>
              {issuing ? 'Issuing…' : 'Issue 2-seat demo license'}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
