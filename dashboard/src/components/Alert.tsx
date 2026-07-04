import type { ReactNode } from 'react';

interface AlertProps {
  kind: 'success' | 'error' | 'info';
  children: ReactNode;
}

const KIND_STYLES: Record<AlertProps['kind'], string> = {
  success: 'bg-emerald-950 text-emerald-300 ring-1 ring-emerald-800',
  error: 'bg-red-950 text-red-300 ring-1 ring-red-800',
  info: 'bg-sky-950 text-sky-300 ring-1 ring-sky-800',
};

/** aria-live status message — screen readers announce it, not just a visual flash. */
export default function Alert({ kind, children }: AlertProps) {
  return (
    <div role="status" aria-live="polite" className={`rounded-md px-3 py-2 text-sm ${KIND_STYLES[kind]}`}>
      {children}
    </div>
  );
}
