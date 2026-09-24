import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { ClipboardList, AlertTriangle, CheckCircle2, ArrowRight, FilePlus2, Wrench, Activity, Database, Shield } from 'lucide-react';
import StatCard from '../components/dashboard/StatCard';
import RecentAudits from '../components/dashboard/RecentAudits';
import Button from '../components/ui/Button';
import PageHeader from '../components/layout/PageHeader';
import { getAudits, getAllFindings, getAllRemediation } from '../api/audits';
import { getHealthStatus } from '../api/client';

export default function Dashboard() {
  const [recentAudits, setRecentAudits] = useState([]);
  const [totalAudits, setTotalAudits] = useState(0);
  const [completedAudits, setCompletedAudits] = useState(0);
  const [findingsSummary, setFindingsSummary] = useState(null);
  const [remediationSummary, setRemediationSummary] = useState(null);
  const [health, setHealth] = useState({ status: 'checking', database: 'checking' });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadDashboardData() {
      setLoading(true);
      try {
        // Fetch health
        try {
          const h = await getHealthStatus();
          setHealth(h);
        } catch (e) {
          setHealth({ status: 'degraded', database: 'unavailable' });
        }

        // Fetch Audits
        try {
          const res = await getAudits({ page: 1, page_size: 5 });
          const items = res?.items || (Array.isArray(res) ? res : []);
          setTotalAudits(res?.total || items.length);

          const completed = items.filter((a) =>
            ['COMPLIANCE_COMPLETE', 'FINDINGS_COMPLETE', 'REMEDIATION_COMPLETE', 'AI_ANALYSIS_COMPLETE'].includes(a.status)
          ).length;
          setCompletedAudits(completed);

          const mapped = items.map((item) => ({
            id: item.audit_id,
            device: item.filename || item.audit_id,
            vendor: item.vendor || 'Detected',
            auditType: item.framework || 'CIS',
            findings: item.findings || 0,
            status: item.status || 'UPLOADED',
            date: item.created_at ? new Date(item.created_at).toLocaleDateString() : 'N/A',
          }));
          setRecentAudits(mapped);
        } catch (e) {
          setRecentAudits([]);
        }

        // Fetch Findings Summary
        try {
          const fData = await getAllFindings();
          setFindingsSummary(fData?.summary || null);
        } catch (e) {
          setFindingsSummary(null);
        }

        // Fetch Remediation Summary
        try {
          const rData = await getAllRemediation();
          setRemediationSummary(rData?.summary || null);
        } catch (e) {
          setRemediationSummary(null);
        }
      } finally {
        setLoading(false);
      }
    }
    loadDashboardData();
  }, []);

  const totalFindings = findingsSummary?.total_findings || 0;
  const criticalFindings = findingsSummary?.critical || 0;
  const highFindings = findingsSummary?.high || 0;
  const mediumFindings = findingsSummary?.medium || 0;
  const lowFindings = findingsSummary?.low || 0;

  const totalRemediations = remediationSummary?.total_findings || 0;

  const apiOk = health.status === 'healthy';
  const dbOk = health.database === 'connected';

  return (
    <div className="space-y-6 flex-1 flex flex-col">
      <PageHeader
        title="Dashboard"
        subtitle="Network security and compliance operational status"
        actions={
          <Link to="/audit/new">
            <Button variant="primary" icon={FilePlus2} size="sm">New Audit</Button>
          </Link>
        }
      />

      {/* Real Summary Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Audits"
          value={totalAudits}
          subtitle="Persisted in PostgreSQL"
          icon={ClipboardList}
          tone="default"
        />
        <StatCard
          title="Completed Audits"
          value={completedAudits}
          subtitle="Evaluated & verified"
          icon={CheckCircle2}
          tone="accent"
        />
        <StatCard
          title="Open Findings"
          value={totalFindings}
          subtitle={`${criticalFindings} Critical, ${highFindings} High`}
          icon={AlertTriangle}
          tone={totalFindings > 0 ? 'danger' : 'success'}
        />
        <StatCard
          title="Remediation Proposals"
          value={totalRemediations}
          subtitle="Generated proposed fixes"
          icon={Wrench}
          tone="warning"
        />
      </div>

      {/* System Status & Severity Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Real System Health Widget */}
        <div className="bg-ncasa-surface border border-ncasa-border rounded p-4 flex flex-col justify-between">
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-ncasa-muted mb-3">System Status</p>
            <div className="space-y-3 text-xs">
              <div className="flex items-center justify-between p-2.5 rounded bg-ncasa-surface2 border border-ncasa-border">
                <div className="flex items-center gap-2">
                  <Activity size={16} className={apiOk ? 'text-status-pass' : 'text-sev-critical'} />
                  <span className="font-semibold text-ncasa-text">Backend API Service</span>
                </div>
                <span className={`px-2 py-0.5 rounded font-bold ${apiOk ? 'bg-status-pass-bg text-status-pass' : 'bg-sev-critical-bg text-sev-critical'}`}>
                  {apiOk ? 'Healthy' : 'Degraded'}
                </span>

              </div>

              <div className="flex items-center justify-between p-2.5 rounded bg-ncasa-surface2 border border-ncasa-border">
                <div className="flex items-center gap-2">
                  <Database size={16} className={dbOk ? 'text-status-pass' : 'text-sev-critical'} />
                  <span className="font-semibold text-ncasa-text">PostgreSQL Database</span>
                </div>
                <span className={`px-2 py-0.5 rounded font-bold ${dbOk ? 'bg-status-pass-bg text-status-pass' : 'bg-sev-critical-bg text-sev-critical'}`}>
                  {dbOk ? 'Connected' : 'Unavailable'}
                </span>
              </div>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-ncasa-border flex items-center justify-between text-[11px] text-ncasa-muted">
            <span>Core Engines: Deterministic</span>
            <span className="font-mono text-ncasa-accent font-bold">N-CASA v1.0</span>
          </div>
        </div>

        {/* Real Findings by Severity Bar */}
        <div className="bg-ncasa-surface border border-ncasa-border rounded p-4 lg:col-span-2 flex flex-col justify-between">
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-ncasa-muted mb-3">Findings by Severity</p>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              {[
                { label: 'Critical', count: criticalFindings, color: 'text-sev-critical', bg: 'bg-sev-critical-bg border-sev-critical/20' },
                { label: 'High',     count: highFindings,     color: 'text-sev-high',     bg: 'bg-sev-high-bg border-sev-high/20' },
                { label: 'Medium',   count: mediumFindings,   color: 'text-sev-medium',   bg: 'bg-sev-medium-bg border-sev-medium/20' },
                { label: 'Low',      count: lowFindings,      color: 'text-sev-low',      bg: 'bg-sev-low-bg border-sev-low/20' },
              ].map(({ label, count, color, bg }) => (
                <div key={label} className={`flex items-center justify-between px-3 py-3 rounded border ${bg}`}>
                  <span className="text-xs font-medium text-ncasa-subtle">{label}</span>
                  <span className={`text-lg font-bold font-mono ${color}`}>{count}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Quick links */}
          <div className="mt-4 pt-3 border-t border-ncasa-border grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
            {[
              { to: '/audit/new',   label: 'New Audit', icon: FilePlus2 },
              { to: '/findings',    label: 'Findings', icon: AlertTriangle },
              { to: '/remediation', label: 'Remediation', icon: Wrench },
              { to: '/reports',     label: 'Reports', icon: ClipboardList },
            ].map(({ to, label, icon: Icon }) => (
              <Link
                key={to}
                to={to}
                className="flex items-center gap-1.5 p-2 rounded bg-ncasa-surface2 border border-ncasa-border hover:border-ncasa-accent/40 transition-colors"
              >
                <Icon size={13} className="text-ncasa-accent shrink-0" />
                <span className="font-medium text-ncasa-text truncate">{label}</span>
              </Link>
            ))}
          </div>
        </div>
      </div>

      {/* Recent audits table */}
      <div className="bg-ncasa-surface border border-ncasa-border rounded">
        <div className="flex items-center justify-between px-4 py-3 border-b border-ncasa-border">
          <p className="text-xs font-semibold uppercase tracking-wider text-ncasa-muted">Recent Audits (PostgreSQL Persisted)</p>
          <Link to="/reports" className="text-xs text-ncasa-accent hover:underline flex items-center gap-1">
            View Reports <ArrowRight size={11} />
          </Link>
        </div>
        <div className="p-4">
          <RecentAudits audits={recentAudits} />
        </div>
      </div>
    </div>
  );
}

