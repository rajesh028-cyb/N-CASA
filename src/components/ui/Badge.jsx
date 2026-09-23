import React from 'react';

const severityStyles = {
  Critical: 'bg-sev-critical-bg text-sev-critical border border-sev-critical/30',
  High:     'bg-sev-high-bg text-sev-high border border-sev-high/30',
  Medium:   'bg-sev-medium-bg text-sev-medium border border-sev-medium/30',
  Low:      'bg-sev-low-bg text-sev-low border border-sev-low/30',
  // Status
  success:  'bg-status-pass-bg text-status-pass border border-status-pass/30',
  warning:  'bg-sev-medium-bg text-sev-medium border border-sev-medium/30',
  danger:   'bg-sev-critical-bg text-sev-critical border border-sev-critical/30',
  info:     'bg-blue-950 text-status-info border border-status-info/30',
  neutral:  'bg-ncasa-surface2 text-ncasa-subtle border border-ncasa-border',
};

// Vendor brand colors
const vendorStyles = {
  Cisco:    'bg-blue-950 text-blue-400 border border-blue-800/40',
  Fortinet: 'bg-red-950 text-red-400 border border-red-800/40',
  Juniper:  'bg-emerald-950 text-emerald-400 border border-emerald-800/40',
};

// Device status
const statusStyles = {
  Healthy:   'bg-status-pass-bg text-status-pass border border-status-pass/30',
  Attention: 'bg-sev-medium-bg text-sev-medium border border-sev-medium/30',
  Critical:  'bg-sev-critical-bg text-sev-critical border border-sev-critical/30',
  Completed: 'bg-status-pass-bg text-status-pass border border-status-pass/30',
  Review:    'bg-sev-medium-bg text-sev-medium border border-sev-medium/30',
  Open:      'bg-sev-critical-bg text-sev-critical border border-sev-critical/30',
  Approved:  'bg-status-pass-bg text-status-pass border border-status-pass/30',
  'Pending Review': 'bg-sev-medium-bg text-sev-medium border border-sev-medium/30',
};

/**
 * Badge — semantic status / severity / vendor indicator.
 * @param {'severity'|'vendor'|'status'|string} type  controls the colour lookup table
 */
export default function Badge({ label, type = 'neutral', className = '' }) {
  let style = '';
  if (type === 'severity') {
    style = severityStyles[label] ?? severityStyles.neutral;
  } else if (type === 'vendor') {
    style = vendorStyles[label] ?? severityStyles.neutral;
  } else if (type === 'status') {
    style = statusStyles[label] ?? severityStyles.neutral;
  } else {
    style = severityStyles[type] ?? severityStyles.neutral;
  }

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold uppercase tracking-wide whitespace-nowrap ${style} ${className}`}
    >
      {label}
    </span>
  );
}
