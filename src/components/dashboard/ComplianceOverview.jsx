import React from 'react';

/**
 * ComplianceOverview — visual breakdown of compliance controls.
 * @param {{ passed: number, failed: number, notVerifiable: number }} breakdown
 * @param {number} overallScore  - 0–100 percentage
 */
export default function ComplianceOverview({ breakdown, overallScore }) {
  const total = breakdown.passed + breakdown.failed + breakdown.notVerifiable;
  const passedPct = total ? Math.round((breakdown.passed / total) * 100) : 0;
  const failedPct = total ? Math.round((breakdown.failed / total) * 100) : 0;
  const nvPct     = total ? Math.round((breakdown.notVerifiable / total) * 100) : 0;

  const bars = [
    { label: 'Passed',         count: breakdown.passed,         pct: passedPct, color: 'bg-status-pass', text: 'text-status-pass' },
    { label: 'Failed',         count: breakdown.failed,         pct: failedPct, color: 'bg-sev-critical', text: 'text-sev-critical' },
    { label: 'Not Verifiable', count: breakdown.notVerifiable,  pct: nvPct,     color: 'bg-ncasa-muted',  text: 'text-ncasa-muted' },
  ];

  return (
    <div className="space-y-4">
      {/* Score ring substitute — simple percentage display */}
      <div className="flex items-center gap-6">
        <div className="flex flex-col items-center justify-center w-20 h-20 rounded-full border-4 border-ncasa-border2 shrink-0" style={{
          background: `conic-gradient(#16a34a ${overallScore * 3.6}deg, #1f2535 0deg)`,
        }}>
          <span className="text-lg font-bold text-ncasa-text">{overallScore}%</span>
        </div>
        <div className="space-y-1 text-xs text-ncasa-muted">
          <p>Overall Compliance Score</p>
          <p className="text-ncasa-subtle">{total} controls evaluated across all audits</p>
          <p className="text-[11px] mt-1">
            <span className="text-status-pass font-semibold">{breakdown.passed} passed</span>
            {' · '}
            <span className="text-sev-critical font-semibold">{breakdown.failed} failed</span>
            {' · '}
            <span className="text-ncasa-muted">{breakdown.notVerifiable} not verifiable</span>
          </p>
        </div>
      </div>

      {/* Stacked bar */}
      <div>
        <div className="flex h-2.5 rounded-full overflow-hidden gap-0.5">
          {bars.map((b) =>
            b.pct > 0 ? (
              <div
                key={b.label}
                className={`${b.color} rounded-sm transition-all`}
                style={{ width: `${b.pct}%` }}
                title={`${b.label}: ${b.count} (${b.pct}%)`}
              />
            ) : null
          )}
        </div>
        {/* Legend */}
        <div className="flex items-center gap-4 mt-2.5 flex-wrap">
          {bars.map((b) => (
            <div key={b.label} className="flex items-center gap-1.5">
              <div className={`w-2.5 h-2.5 rounded-sm ${b.color}`} />
              <span className="text-[11px] text-ncasa-muted">{b.label}</span>
              <span className={`text-[11px] font-semibold ${b.text}`}>{b.count}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
