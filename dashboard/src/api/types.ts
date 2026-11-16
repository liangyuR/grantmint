export interface AdminSummary { username: string; csrfToken: string }
export type LoginResponse = AdminSummary;
export interface Product {
  id: string; slug: string; name: string; description: string | null;
  signingKeyId: string; archivedAt: string | null; createdAt: string; updatedAt?: string;
}
export interface SigningKey { keyId: string; publicKey: string; applicationId?: string | null; active?: boolean }
export type Entitlements = Record<string, boolean | number | string>;
export interface Renewal {
  id: string; oldExpiresAt: string; newExpiresAt: string; revision: number;
  serial: string | null; confirmedAt: string | null; reason: string; createdAt: string;
}
export interface LicenseDetail {
  id: string; keyId: string; applicationId: string; applicationName: string;
  customer: { name: string; email: string }; status: string; expiresAt: string;
  revision: number; bindingVersion: number; signedToken: string | null;
  devicePublicKey: string | null; fingerprintHash: string | null; fingerprintVersion: number | null;
  entitlements: Entitlements; renewals: Renewal[]; deliveryStatus: 'not_activated' | 'pending' | 'confirmed';
  createdAt: string; revokedAt: string | null;
}
export interface CreateOfflineLicenseResponse extends LicenseDetail { licenseId: string; activationSecret: string }
export interface Page<T> { content: T[]; totalElements: number; totalPages: number; number: number; size: number }
export interface AuditEvent { id: string; action: string; actor: string; applicationId: string | null; licenseId: string | null; detail: unknown; createdAt: string }
