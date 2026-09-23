import React from 'react';
import { TrendingUp } from 'lucide-react';

/**
 * StatCard — displays a single KPI statistic on the dashboard.
 * @param {string} title
 * @param {string|number} value
 * @param {string} subtitle  - small detail below the value
 * @param {React.ElementType} icon
 * @param {'default'|'accent'|'success'|'warning'|'danger'} tone
 */
export default function StatCard({ title, value, subtitle, icon: Icon, tone = 'default' }) {
  const toneMap = {
    default: { bg: 'bg-ncasa-surface2', icon: 'text-ncasa-muted', value: 'text-ncasa-text' },
    accent:  { bg: 'bg-ncasa-accent-l/50',  icon: 'text-ncasa-accent', value: 'text-ncasa-accent' },
    success: { bg: 'bg-status-pass-bg', icon: 'text-status-pass', value: 'text-status-pass' },
    warning: { bg: 'bg-sev-medium-bg',  icon: 'text-sev-medium',  value: 'text-sev-medium' },
    danger:  { bg: 'bg-sev-critical-bg',icon: 'text-sev-critical',value: 'text-sev-critical' },
  };
  const t = toneMap[tone] ?? toneMap.default;

  return (
    <div className="bg-ncasa-surface border border-ncasa-border rounded p-4 flex flex-col gap-3">
      <div className="flex items-start justify-between">
        <p className="text-xs font-semibold uppercase tracking-wider text-ncasa-muted">{title}</p>
        {Icon && (
          <div className={`p-2 rounded ${t.bg}`}>
            <Icon size={15} className={t.icon} />
          </div>
        )}
      </div>
      <div>
        <p className={`text-2xl font-bold ${t.value} leading-none`}>{value}</p>
        {subtitle && <p className="text-xs text-ncasa-muted mt-1">{subtitle}</p>}
      </div>
    </div>
  );
}
