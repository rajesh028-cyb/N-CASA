import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  Server,
  Activity,
  Database,
  Cpu,
  Lock,
  Sparkles,
  RefreshCw,
} from 'lucide-react';
import { getHealthStatus } from '../api/client';
import Button from '../components/ui/Button';

export default function Settings() {
  const [health, setHealth] = useState({ status: 'checking', database: 'checking' });
  const [loading, setLoading] = useState(false);

  const fetchHealth = async () => {
    setLoading(true);
    try {
      const res = await getHealthStatus();
      setHealth(res);
    } catch (e) {
      setHealth({ status: 'degraded', database: 'unavailable' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHealth();
  }, []);

  const apiOk = health.status === 'healthy';
  const dbOk = health.database === 'connected';

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-ncasa-text">System Settings & Operational Status</h1>
          <p className="text-sm text-ncasa-muted mt-0.5">
            Overview of backend services, database persistence, supported vendors, and compliance guardrails.
          </p>
        </div>
        <Button variant="outline" size="sm" icon={RefreshCw} onClick={fetchHealth} disabled={loading}>
          Refresh Status
        </Button>
      </div>

      {/* Live System Health Section */}
      <div className="bg-ncasa-surface border border-ncasa-border rounded p-5 space-y-4">
        <h2 className="text-sm font-bold text-ncasa-text uppercase tracking-wider text-ncasa-muted">
          System Infrastructure Health
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div className="bg-ncasa-surface2 border border-ncasa-border p-4 rounded flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Activity size={20} className={apiOk ? 'text-status-pass' : 'text-sev-critical'} />
              <div>
                <p className="text-sm font-semibold text-ncasa-text">FastAPI Backend Service</p>
                <p className="text-xs text-ncasa-muted">Endpoint: /api/health</p>
              </div>
            </div>
            <span className={`px-2.5 py-1 rounded text-xs font-bold ${apiOk ? 'bg-status-pass-bg text-status-pass border border-status-pass/30' : 'bg-sev-critical-bg text-sev-critical'}`}>
              {apiOk ? 'Operational' : 'Degraded'}
            </span>
          </div>

          <div className="bg-ncasa-surface2 border border-ncasa-border p-4 rounded flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Database size={20} className={dbOk ? 'text-status-pass' : 'text-sev-critical'} />
              <div>
                <p className="text-sm font-semibold text-ncasa-text">PostgreSQL Database</p>
                <p className="text-xs text-ncasa-muted">Stateful persistence tier</p>
              </div>
            </div>
            <span className={`px-2.5 py-1 rounded text-xs font-bold ${dbOk ? 'bg-status-pass-bg text-status-pass border border-status-pass/30' : 'bg-sev-critical-bg text-sev-critical'}`}>
              {dbOk ? 'Connected' : 'Unavailable'}
            </span>
          </div>
        </div>
      </div>

      {/* Supported Frameworks & Deterministic Vendors */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-ncasa-surface border border-ncasa-border rounded p-5 space-y-3">
          <div className="flex items-center gap-2 border-b border-ncasa-border pb-2">
            <ShieldCheck size={18} className="text-ncasa-accent" />
            <h3 className="text-sm font-bold text-ncasa-text">Supported Compliance Frameworks</h3>
          </div>
          <ul className="space-y-2 text-xs">
            {[
              { name: 'CIS Benchmarks', ver: 'v8.0', status: 'Active (Rule-based)' },
              { name: 'NIST SP 800-53', ver: 'Rev 5', status: 'Active (Rule-based)' },
              { name: 'DISA STIG', ver: '2024.1', status: 'Active (Rule-based)' },
            ].map((fw) => (
              <li key={fw.name} className="flex items-center justify-between p-2.5 rounded bg-ncasa-surface2 border border-ncasa-border">
                <div>
                  <p className="font-semibold text-ncasa-text">{fw.name}</p>
                  <p className="text-[10px] text-ncasa-muted">Version: {fw.ver}</p>
                </div>
                <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-status-pass-bg text-status-pass border border-status-pass/30">
                  {fw.status}
                </span>
              </li>
            ))}
          </ul>
        </div>

        <div className="bg-ncasa-surface border border-ncasa-border rounded p-5 space-y-3">
          <div className="flex items-center gap-2 border-b border-ncasa-border pb-2">
            <Server size={18} className="text-ncasa-accent" />
            <h3 className="text-sm font-bold text-ncasa-text">Supported Deterministic Vendors</h3>
          </div>
          <ul className="space-y-2 text-xs">
            {[
              { vendor: 'Cisco Systems', syntax: 'IOS / IOS-XE / ASA', parser: 'Deterministic' },
              { vendor: 'Juniper Networks', syntax: 'Junos OS', parser: 'Deterministic' },
              { vendor: 'Fortinet', syntax: 'FortiGate / FortiOS', parser: 'Deterministic' },
            ].map((v) => (
              <li key={v.vendor} className="flex items-center justify-between p-2.5 rounded bg-ncasa-surface2 border border-ncasa-border">
                <div>
                  <p className="font-semibold text-ncasa-text">{v.vendor}</p>
                  <p className="text-[10px] text-ncasa-muted">{v.syntax}</p>
                </div>
                <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-blue-900/40 text-blue-300 border border-blue-700/50">
                  {v.parser}
                </span>
              </li>
            ))}
          </ul>
        </div>
      </div>

      {/* AI Guardrails & Security Policies */}
      <div className="bg-ncasa-surface border border-ncasa-border rounded p-5 space-y-3">
        <div className="flex items-center gap-2 border-b border-ncasa-border pb-2">
          <Lock size={18} className="text-ncasa-accent" />
          <h3 className="text-sm font-bold text-ncasa-text">Security & AI Assistance Architecture</h3>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
          <div className="p-3 bg-ncasa-surface2 rounded border border-ncasa-border space-y-1">
            <div className="flex items-center gap-1.5 font-bold text-ncasa-text">
              <Sparkles size={14} className="text-ncasa-accent" />
              <span>AI Pipeline Scope</span>
            </div>
            <p className="text-ncasa-muted text-[11px] leading-relaxed">
              AI analysis is strictly scoped to unknown/unsupported vendors and advisory finding explanations. Known vendor compliance remains 100% deterministic.
            </p>
          </div>

          <div className="p-3 bg-ncasa-surface2 rounded border border-ncasa-border space-y-1">
            <div className="flex items-center gap-1.5 font-bold text-ncasa-text">
              <Lock size={14} className="text-ncasa-accent" />
              <span>Secret Redaction</span>
            </div>
            <p className="text-ncasa-muted text-[11px] leading-relaxed">
              Passwords, pre-shared keys, SNMP strings, and private keys are scrubbed and replaced with <code className="text-amber-300">&lt;REDACTED&gt;</code> before persistence or report rendering.
            </p>
          </div>

          <div className="p-3 bg-ncasa-surface2 rounded border border-ncasa-border space-y-1">
            <div className="flex items-center gap-1.5 font-bold text-ncasa-text">
              <Cpu size={14} className="text-ncasa-accent" />
              <span>Non-Execution Enforcement</span>
            </div>
            <p className="text-ncasa-muted text-[11px] leading-relaxed">
              Remediation proposals are read-only configuration recommendations. N-CASA never connects via SSH or modifies device configurations automatically.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

