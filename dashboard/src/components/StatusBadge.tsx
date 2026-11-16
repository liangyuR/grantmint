const STATUS_STYLES: Record<string, string> = {
  active: 'bg-emerald-950 text-emerald-300 ring-1 ring-emerald-800',
  created: 'bg-sky-950 text-sky-300 ring-1 ring-sky-800',
  expired: 'bg-gray-800 text-gray-300 ring-1 ring-gray-700',
  revoked: 'bg-red-950 text-red-300 ring-1 ring-red-800',
};

const DEFAULT_STYLE = 'bg-gray-800 text-gray-300 ring-1 ring-gray-700';

export const STATUS_LABELS: Record<string, string> = {
  active: '有效', created: '待激活', expired: '已到期', revoked: '已撤销',
};

/**
 * Status pill that always carries a text label (never color alone), per
 * docs/reference/ACCESSIBILITY.md's guidance on not relying on color to convey state.
 */
export default function StatusBadge({ status }: { status: string }) {
  const style = STATUS_STYLES[status.toLowerCase()] ?? DEFAULT_STYLE;
  return (
    <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium capitalize ${style}`}>
      {STATUS_LABELS[status.toLowerCase()] ?? status}
    </span>
  );
}
