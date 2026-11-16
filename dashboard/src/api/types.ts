/**
 * Wire types for the Grantmint admin/validation APIs, read directly off the server controllers:
 * ProductAdminController, PolicyAdminController, EntitlementAdminController, ActivationController,
 * ValidationController, AdminAuthController, LicenseAdminController.
 */

// ─── Auth ──────────────────────────────────────────────────────────────────

export interface AdminSummary {
  username: string;
}

export interface LoginResponse {
  token: string; // bearer token for CLI/API use — the dashboard ignores this and relies on the cookie
  expiresAt: string;
  admin: AdminSummary;
}

// ─── Products (ProductAdminController) ──────────────────────────────────────

export interface Product {
  id: string;
  slug: string;
  name: string;
  description: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface CreateProductRequest {
  slug: string;
  name: string;
  description: string | null;
}

export interface UpdateProductRequest {
  name: string;
  description: string | null;
}

export interface SigningKey {
  keyId: string;
  productId: string;
  algorithm: string;
  publicKey: string;
  status: string;
  createdAt: string;
}

// ─── Policies (PolicyAdminController) ───────────────────────────────────────

export type EntitlementValue = boolean | number | string;

export interface Policy {
  id: string;
  productId: string;
  code: string;
  name: string;
  activationType: string; // node_locked | floating
  maxSeats: number;
  durationDays: number | null;
  gracePeriodDays: number;
  trial: boolean;
  heartbeatIntervalSeconds: number;
  entitlements: Record<string, EntitlementValue>;
  constraints: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
}

export interface CreatePolicyRequest {
  code: string;
  name: string;
  activationType: string;
  maxSeats: number;
  durationDays: number | null;
  gracePeriodDays: number;
  trial: boolean;
  heartbeatIntervalSeconds: number;
  constraints: Record<string, unknown>;
}

export type UpdatePolicyRequest = Omit<CreatePolicyRequest, 'code'>;

// ─── Entitlements (EntitlementAdminController) ──────────────────────────────

export type EntitlementValueType = 'flag' | 'limit' | 'string';

/** The server's encoded value wrapper: {"bool":true} | {"int":5} | {"string":"..."}. */
export type EncodedEntitlementValue = { bool: boolean } | { int: number } | { string: string };

export interface Entitlement {
  id: string;
  policyId: string;
  code: string;
  valueType: EntitlementValueType;
  value: EncodedEntitlementValue;
  createdAt: string;
}

export interface CreateEntitlementRequest {
  code: string;
  valueType: EntitlementValueType;
  value: EntitlementValue;
}

export type UpdateEntitlementRequest = Omit<CreateEntitlementRequest, 'code'>;

// ─── Licenses (LicenseAdminController) ──────────────────────────────────────

export type LicenseStatus = 'created' | 'active' | 'suspended' | 'expired' | 'revoked' | string;

export interface LicenseListItem {
  id: string;
  keyId: string;
  productId: string;
  status: LicenseStatus;
  holderName: string;
  holderEmail: string;
  maxSeats: number;
  activeSeats: number;
  issuedAt: string;
  expiresAt: string | null;
  externalRef: string | null;
}

export interface LicensePage {
  items: LicenseListItem[];
  page: number;
  size: number;
  total: number;
}

export interface LicenseActivation {
  id: string;
  fingerprint: string;
  machineName: string | null;
  platform: string | null;
  status: string;
  activatedAt: string;
  lastHeartbeatAt: string | null;
  deactivatedAt: string | null;
}

/**
 * LicenseAdminController.LicenseDetailView — unlike the list rows, the detail view has no
 * `activeSeats` field; derive it by counting activations with status 'active'.
 */
export interface LicenseDetail {
  id: string;
  keyId: string;
  productId: string;
  policyId: string;
  status: LicenseStatus;
  holderName: string;
  holderEmail: string;
  entitlements: Record<string, unknown>;
  constraints: Record<string, unknown>;
  maxSeats: number;
  signedToken: string;
  revocationReason: string | null;
  issuedAt: string;
  activatedAt: string | null;
  expiresAt: string | null;
  suspendedAt: string | null;
  revokedAt: string | null;
  externalRef: string | null;
  activations: LicenseActivation[];
}

export interface IssueLicenseRequest {
  productId: string;
  policyId: string;
  holder: { name: string; email: string };
  expiresAt?: string;
  seat?: number;
  externalRef?: string;
}

/** LicenseAdminController.IssuedLicenseResponse — the token field is `token`, not `signedToken`. */
export interface IssueLicenseResponse {
  keyId: string;
  token: string;
  status: string;
  expiresAt: string | null;
}

// ─── Validation / Activation surfaces (v1, validation-key protected) ────────

export interface ActivateResponse {
  keyId: string;
  activationId: string;
  fingerprint: string;
  status: string;
  reactivated: boolean;
  seatsUsed: number;
  seatsTotal: number;
  activatedAt: string;
  heartbeatIntervalSeconds: number;
  nextHeartbeatDueBy: string;
}

export interface ValidateResponse {
  valid: boolean;
  status: string;
  keyId: string;
  expiresAt: string | null;
  entitlements: Record<string, unknown>;
  checkedAt: string;
}

export interface ApiErrorBody {
  error: string;
  message: string;
}
