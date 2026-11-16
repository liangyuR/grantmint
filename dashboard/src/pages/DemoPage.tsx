import { useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { api, ApiError, localizedError } from '../api/client';
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
  try {
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
    const error = parsed as ApiErrorBody | undefined;
    return { ok: false, status: response.status, errorBody: { error: error?.error ?? 'request_failed', message: localizedError(response.status, error?.error) } };
  } catch {
    return { ok: false, status: 0, errorBody: { error: 'network_error', message: '请求失败，请检查网络和服务器响应。' } };
  }
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
    } catch {
      setState({ kind: 'error', status: 0, body: { error: 'offline_verify_failed', message: '离线验签失败，请检查 v1 证书格式和公钥。' } });
    }
  }

  async function runRevoke() {
    setRevokeStep({ kind: 'loading' });
    try {
      await api.delete(`/admin/licenses/${keyId}`, { reason: 'Grantmint 管理控制台演示' });
      setRevokeStep({ kind: 'success', result: { revoked: true } });
    } catch (err) {
      if (err instanceof ApiError) {
        setRevokeStep({ kind: 'error', status: err.status, body: { error: err.code ?? 'error', message: err.message } });
      } else {
        setRevokeStep({ kind: 'error', status: 0, body: { error: 'error', message: '撤销失败。' } });
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
        <h1 className="text-xl font-semibold text-white">v1 在线与离线演示</h1>
        <p className="mt-1 max-w-2xl text-sm text-gray-400">
          本页仅演示旧版 v1 协议，不支持 v2 设备证书。离线验签无法即时获知服务端撤销，设备绑定授权请使用 Rust 客户端。
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
          title="激活设备 A"
          description={`使用指纹 ${fingerprintA} 激活设备。`}
          disabled={!readyForOnlineSteps}
          action={
            <button
              type="button"
              className={buttonClasses}
              disabled={!readyForOnlineSteps || stepA.kind === 'loading'}
              onClick={() => void runActivate(fingerprintA, setStepA)}
            >
              {stepA.kind === 'loading' ? '激活中…' : '激活设备 A'}
            </button>
          }
        >
          <StepResult state={stepA} successCopy={(r) => `激活成功，已用设备数：${r.seatsUsed}/${r.seatsTotal}。`} />
        </StepCard>

        <StepCard
          index={2}
          title="激活设备 B"
          description={`使用指纹 ${fingerprintB} 激活第二台设备。`}
          disabled={!readyForOnlineSteps}
          action={
            <button
              type="button"
              className={buttonClasses}
              disabled={!readyForOnlineSteps || stepB.kind === 'loading'}
              onClick={() => void runActivate(fingerprintB, setStepB)}
            >
              {stepB.kind === 'loading' ? '激活中…' : '激活设备 B'}
            </button>
          }
        >
          <StepResult state={stepB} successCopy={(r) => `激活成功，已用设备数：${r.seatsUsed}/${r.seatsTotal}。`} />
        </StepCard>

        <StepCard
          index={3}
          title="激活设备 C：验证设备数上限"
          description={`在双设备授权上尝试第三台设备 ${fingerprintC}，应返回 409 seat_limit_exceeded。`}
          disabled={!readyForOnlineSteps}
          action={
            <button
              type="button"
              className={buttonClasses}
              disabled={!readyForOnlineSteps || stepC.kind === 'loading'}
              onClick={() => void runActivate(fingerprintC, setStepC)}
            >
              {stepC.kind === 'loading' ? '激活中…' : '激活设备 C'}
            </button>
          }
        >
          {stepC.kind === 'error' && stepC.status === 409 ? (
            <Alert kind="success">
              设备数限制符合预期： {stepC.body?.error ?? 'seat_limit_exceeded'} — {stepC.body?.message}
            </Alert>
          ) : (
            <StepResult state={stepC} successCopy={() => '异常：激活成功，设备数量限制未生效。'} />
          )}
        </StepCard>

        <StepCard
          index={4}
          title="浏览器本地离线验签"
          description="不调用服务器，使用输入的公钥通过 WebCrypto 在本地校验 Ed25519 签名。"
          disabled={!readyForOfflineSteps}
          action={
            !ed25519Supported ? (
              <Alert kind="info">当前浏览器不支持 WebCrypto Ed25519 离线验签。</Alert>
            ) : (
              <button
                type="button"
                className={buttonClasses}
                disabled={!readyForOfflineSteps || offlineBefore.kind === 'loading'}
                onClick={() => void runOfflineCheck(setOfflineBefore)}
              >
                {offlineBefore.kind === 'loading' ? '校验中…' : '执行离线校验'}
              </button>
            )
          }
        >
          <p className="text-xs text-gray-500">
            此演示仅验证 v1 格式。实际设备绑定与长期离线接入请使用 Rust SDK，不要把浏览器演示当作客户授权检查。
          </p>
          <OfflineResult state={offlineBefore} />
        </StepCard>

        <StepCard
          index={5}
          title="撤销授权"
          description="通过管理 API 执行不可撤销的操作，之后在线校验应拒绝此授权。"
          disabled={!readyForOnlineSteps}
          action={
            <button
              type="button"
              className="rounded-md bg-red-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-red-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-500 disabled:opacity-60"
              disabled={!readyForOnlineSteps || revokeStep.kind === 'loading'}
              onClick={() => void runRevoke()}
            >
              {revokeStep.kind === 'loading' ? '撤销中…' : '撤销授权'}
            </button>
          }
        >
          {revokeStep.kind === 'success' && <Alert kind="success">授权已撤销。</Alert>}
          {revokeStep.kind === 'error' && (
            <Alert kind="error">
              {revokeStep.body?.error ?? 'error'} — {revokeStep.body?.message}
            </Alert>
          )}
        </StepCard>

        <StepCard
          index={6}
          title="撤销后的在线校验：应返回 422"
          description="在线服务会根据已撤销状态拒绝授权。"
          disabled={!readyForOnlineSteps}
          action={
            <button
              type="button"
              className={buttonClasses}
              disabled={!readyForOnlineSteps || validateAfterRevoke.kind === 'loading'}
              onClick={() => void runValidateAfterRevoke()}
            >
              {validateAfterRevoke.kind === 'loading' ? '校验中…' : '校验授权'}
            </button>
          }
        >
          {validateAfterRevoke.kind === 'error' && validateAfterRevoke.status === 422 ? (
            <Alert kind="success">
              已按预期拒绝： {validateAfterRevoke.body?.error ?? 'license_revoked'} —{' '}
              {validateAfterRevoke.body?.message}
            </Alert>
          ) : (
            <StepResult state={validateAfterRevoke} successCopy={() => '异常：在线校验仍返回有效。'} />
          )}
        </StepCard>

        <StepCard
          index={7}
          title="再次离线校验：仍可能有效"
          description="再次校验同一证书。撤销无法改变已下载的签名，离线证书到期前仍可通过校验。"
          disabled={!readyForOfflineSteps}
          action={
            ed25519Supported && (
              <button
                type="button"
                className={buttonClasses}
                disabled={!readyForOfflineSteps || offlineAfter.kind === 'loading'}
                onClick={() => void runOfflineCheck(setOfflineAfter)}
              >
                {offlineAfter.kind === 'loading' ? '校验中…' : '再次离线校验'}
              </button>
            )
          }
        >
          <OfflineResult state={offlineAfter} />
          {offlineAfter.kind === 'success' && offlineAfter.result.signatureValid && !offlineAfter.result.expired && (
            <Alert kind="info">
              这是离线授权的限制：签名有效且未到期的证书无法获知服务端刚发生的撤销。
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
      {state.body?.error ?? 'error'}: {state.body?.message ?? '请求失败。'}
    </Alert>
  );
}

function OfflineResult({ state }: { state: StepState<OfflineVerificationResult> }) {
  if (state.kind === 'idle' || state.kind === 'loading') return null;
  if (state.kind === 'error') {
    return (
      <Alert kind="error">{state.body?.message ?? '离线校验失败。'}</Alert>
    );
  }
  const { signatureValid, expired, notYetValid, payload } = state.result;
  const overallValid = signatureValid && !expired && !notYetValid;
  return (
    <div className="space-y-2">
      <Alert kind={overallValid ? 'success' : 'error'}>
        {overallValid
          ? '有效：已在本地验证签名，没有发起网络请求。'
          : `无效：签名有效=${signatureValid}，已到期=${expired}，尚未生效=${notYetValid}。`}
      </Alert>
      <div className="rounded-md border border-gray-800 bg-gray-950 p-3">
        <p className="text-xs font-semibold uppercase tracking-wider text-gray-500">证书声明（离线解码，未向服务器确认状态）</p>
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
  const [holderName, setHolderName] = useState('演示客户');
  const [holderEmail, setHolderEmail] = useState('demo@example.com');
  const [issuing, setIssuing] = useState(false);
  const [issueError, setIssueError] = useState<string | null>(null);

  useEffect(() => {
    if (!showIssue) return;
    api
      .get<Product[]>('/admin/products')
      .then((data) => {
        setProducts(data);
        const first = data[0];
        if (first) setProductId(first.id);
      })
      .catch(() => setIssueError('加载应用失败。'));
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
      .catch(() => setIssueError('加载策略失败。'));
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
      setIssueError(err instanceof ApiError ? err.message : '创建演示授权失败。');
    } finally {
      setIssuing(false);
    }
  }

  return (
    <div className="space-y-4 rounded-lg border border-gray-800 bg-gray-900 p-4">
      <h2 className="text-sm font-semibold text-gray-200">演示配置</h2>
      <div className="grid gap-4 sm:grid-cols-2">
        <FormField id="demo-validation-key" label="校验 API 密钥" hint="由管理员粘贴 gm_val_… 密钥">
          <input
            id="demo-validation-key"
            className={`${inputClasses} font-mono`}
            value={validationKey}
            onChange={(e) => setValidationKey(e.target.value)}
            placeholder="gm_val_..."
          />
        </FormField>
        <FormField id="demo-public-key" label="Ed25519 公钥（Base64）" hint="仅用于浏览器离线验签">
          <input
            id="demo-public-key"
            className={`${inputClasses} font-mono`}
            value={publicKeyBase64}
            onChange={(e) => setPublicKeyBase64(e.target.value)}
            placeholder="32 字节公钥的 Base64 编码"
          />
        </FormField>
        <FormField id="demo-key-id" label="授权编号">
          <input
            id="demo-key-id"
            className={`${inputClasses} font-mono`}
            value={keyId}
            onChange={(e) => setKeyId(e.target.value)}
            placeholder="K7P2-9QXM-4T1Y"
          />
        </FormField>
        <FormField id="demo-token" label="签名证书">
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
        {showIssue ? '收起创建表单' : '创建 v1 演示授权'}
      </button>

      {showIssue && (
        <div className="grid gap-4 rounded-md border border-gray-800 p-3 sm:grid-cols-2">
          {issueError && (
            <div className="sm:col-span-2">
              <Alert kind="error">{issueError}</Alert>
            </div>
          )}
          <FormField id="demo-issue-product" label="应用">
            <select id="demo-issue-product" className={inputClasses} value={productId} onChange={(e) => setProductId(e.target.value)}>
              {products.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          </FormField>
          <FormField id="demo-issue-policy" label="权益策略" hint="优先选择允许两台设备的策略">
            <select id="demo-issue-policy" className={inputClasses} value={policyId} onChange={(e) => setPolicyId(e.target.value)}>
              {policies.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}（{p.maxSeats} 台设备）
                </option>
              ))}
            </select>
          </FormField>
          <FormField id="demo-issue-holder-name" label="客户名称">
            <input id="demo-issue-holder-name" className={inputClasses} value={holderName} onChange={(e) => setHolderName(e.target.value)} />
          </FormField>
          <FormField id="demo-issue-holder-email" label="客户邮箱">
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
              {issuing ? '创建中…' : '创建 v1 演示授权'}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
