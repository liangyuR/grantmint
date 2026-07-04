/** Generates a demo-only device fingerprint, e.g. "fp_3f9a1c2b8e0d4a6f". */
export function randomFingerprint(): string {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return `fp_${hex}`;
}
