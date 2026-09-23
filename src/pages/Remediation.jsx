import React, { useState, useEffect } from 'react';
import { ShieldAlert, CheckCircle2, Eye, AlertCircle, Info, Loader2, FileCode, Check } from 'lucide-react';
import { getAllRemediation, reviewRemediation } from '../api/audits';
import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';
import EmptyState from '../components/ui/EmptyState';

const statuses = ['All', 'AVAILABLE', 'MANUAL_REVIEW_REQUIRED'];
const reviewStatuses = ['All', 'PENDING_REVIEW', 'REVIEWED'];

export default function Remediation() {
  const [remediationSummary, setRemediationSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [statusFilter, setStatusFilter] = useState('All');
  const [reviewFilter, setReviewFilter] = useState('All');

  const fetchRemediationData = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getAllRemediation({
        status: statusFilter !== 'All' ? statusFilter : undefined,
        review_status: reviewFilter !== 'All' ? reviewFilter : undefined,
      });
      setRemediationSummary(data);
    } catch (err) {
      console.error('Failed to load remediation proposals:', err);
      setError(err.message || 'Failed to fetch remediation proposals');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRemediationData();
  }, [statusFilter, reviewFilter]);

  const handleMarkReviewed = async (auditId, remediationId) => {
    try {
      await reviewRemediation(auditId, remediationId);
      await fetchRemediationData();
    } catch (err) {
      console.error('Failed to review remediation:', err);
      alert(err.message || 'Failed to update review status.');
    }
  };

  const items = remediationSummary?.remediations || [];
  const counts = remediationSummary?.summary || {
    total_findings: 0,
    remediations_available: 0,
    manual_review_required: 0,
    pending_review: 0,
    reviewed: 0,
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-xl font-bold text-ncasa-text">Security Remediation Proposals</h1>
        <p className="text-sm text-ncasa-muted mt-0.5">
          Review vendor-specific proposed configuration changes before applying through change-management pipelines.
        </p>
      </div>

      {/* Mandatory Safety Notice */}
      <div className="flex items-start gap-3 px-4 py-3 rounded border border-amber-500/30 bg-amber-950/20 text-sm">
        <AlertCircle size={18} className="text-amber-400 shrink-0 mt-0.5" />
        <div>
          <p className="font-semibold text-amber-300 text-xs uppercase tracking-wide">
            PROPOSED CONFIGURATION — NOT EXECUTED ON LIVE DEVICES
          </p>
          <p className="text-xs text-ncasa-subtle mt-0.5 leading-relaxed">
            All configuration changes generated below are human-reviewable proposals only. N-CASA never connects directly to network hardware, executes SSH commands, or modifies device configurations automatically.
          </p>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="bg-ncasa-surface border border-ncasa-border p-3.5 rounded flex justify-between items-center">
          <div>
            <p className="text-[10px] uppercase font-semibold text-ncasa-muted">Total Proposals</p>
            <p className="text-xl font-bold text-ncasa-text font-mono">{counts.total_findings}</p>
          </div>
          <FileCode size={20} className="text-ncasa-accent opacity-70" />
        </div>
        <div className="bg-ncasa-surface border border-status-pass/30 p-3.5 rounded flex justify-between items-center">
          <div>
            <p className="text-[10px] uppercase font-semibold text-ncasa-muted">Available Proposals</p>
            <p className="text-xl font-bold text-status-pass font-mono">{counts.remediations_available}</p>
          </div>
          <CheckCircle2 size={20} className="text-status-pass opacity-70" />
        </div>
        <div className="bg-ncasa-surface border border-amber-500/30 p-3.5 rounded flex justify-between items-center">
          <div>
            <p className="text-[10px] uppercase font-semibold text-ncasa-muted">Manual Review Required</p>
            <p className="text-xl font-bold text-amber-300 font-mono">{counts.manual_review_required}</p>
          </div>
          <AlertCircle size={20} className="text-amber-300 opacity-70" />
        </div>
        <div className="bg-ncasa-surface border border-blue-500/30 p-3.5 rounded flex justify-between items-center">
          <div>
            <p className="text-[10px] uppercase font-semibold text-ncasa-muted">Reviewed by Admin</p>
            <p className="text-xl font-bold text-blue-300 font-mono">{counts.reviewed}</p>
          </div>
          <Check size={20} className="text-blue-300 opacity-70" />
        </div>
      </div>

      {/* Filters Bar */}
      <div className="flex items-center gap-3 flex-wrap bg-ncasa-surface p-3 rounded border border-ncasa-border text-xs">
        <div className="flex items-center gap-1">
          <span className="font-semibold text-ncasa-muted mr-1">Proposal Status:</span>
          {statuses.map((s) => (
            <button
              key={s}
              onClick={() => setStatusFilter(s)}
              className={`px-2.5 py-1 text-xs font-medium rounded border transition-colors ${
                statusFilter === s
                  ? 'bg-ncasa-accent text-white border-ncasa-accent'
                  : 'bg-ncasa-surface2 text-ncasa-muted border-ncasa-border hover:text-ncasa-text'
              }`}
            >
              {s}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-1 ml-auto">
          <span className="font-semibold text-ncasa-muted mr-1">Admin Review:</span>
          {reviewStatuses.map((rs) => (
            <button
              key={rs}
              onClick={() => setReviewFilter(rs)}
              className={`px-2.5 py-1 text-xs font-medium rounded border transition-colors ${
                reviewFilter === rs
                  ? 'bg-ncasa-accent text-white border-ncasa-accent'
                  : 'bg-ncasa-surface2 text-ncasa-muted border-ncasa-border hover:text-ncasa-text'
              }`}
            >
              {rs}
            </button>
          ))}
        </div>
      </div>

      {/* Main Content Area */}
      {loading ? (
        <div className="py-12 flex flex-col items-center justify-center space-y-3 bg-ncasa-surface border border-ncasa-border rounded">
          <Loader2 size={24} className="animate-spin text-ncasa-accent" />
          <p className="text-sm text-ncasa-muted">Generating vendor-specific remediation suggestions...</p>
        </div>
      ) : error ? (
        <div className="p-4 bg-status-fail-bg border border-status-fail/30 rounded text-status-fail text-sm">
          {error}
        </div>
      ) : items.length === 0 ? (
        <EmptyState
          icon={FileCode}
          title="No Remediation Proposals Generated"
          description="Either no open findings exist for remediation, or no proposals match your filters."
        />
      ) : (
        <div className="space-y-4">
          <p className="text-xs text-ncasa-muted px-1">
            Showing <strong className="text-ncasa-text">{items.length}</strong> remediation proposals
          </p>

          {items.map((rem) => (
            <RemediationCard key={rem.remediation_id} rem={rem} onReview={handleMarkReviewed} />
          ))}
        </div>
      )}
    </div>
  );
}

function RemediationCard({ rem, onReview }) {
  const [expanded, setExpanded] = useState(false);
  const isReviewed = rem.review_status === 'REVIEWED';

  return (
    <div className="bg-ncasa-surface border border-ncasa-border rounded overflow-hidden">
      {/* Card Header */}
      <div className="flex items-start gap-4 p-4">
        <div className="shrink-0 mt-0.5">
          <ShieldAlert
            size={20}
            className={
              rem.status === 'AVAILABLE' ? 'text-status-pass' : 'text-amber-400'
            }
          />
        </div>

        {/* Info */}
        <div className="flex-1 min-w-0 space-y-1.5">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-bold text-ncasa-text leading-tight">{rem.title}</span>
            <span className="font-mono text-[10px] text-ncasa-accent font-bold px-1.5 py-0.5 bg-ncasa-surface2 rounded border border-ncasa-border">
              {rem.remediation_id}
            </span>
          </div>

          <div className="flex items-center gap-2 flex-wrap text-xs">
            <span className="font-mono text-ncasa-subtle bg-ncasa-surface2 px-1.5 py-0.5 rounded border border-ncasa-border">
              {rem.control_id}
            </span>
            <Badge label={rem.vendor} type="vendor" />
            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
              rem.status === 'AVAILABLE'
                ? 'bg-status-pass-bg text-status-pass border border-status-pass/30'
                : 'bg-amber-950/40 text-amber-300 border border-amber-700/40'
            }`}>
              {rem.status}
            </span>
            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
              isReviewed
                ? 'bg-blue-900/30 text-blue-300 border border-blue-700/40'
                : 'bg-ncasa-surface2 text-ncasa-muted border border-ncasa-border'
            }`}>
              {rem.review_status}
            </span>
          </div>

          <p className="text-xs text-ncasa-subtle leading-relaxed">{rem.description}</p>
        </div>

        {/* Actions */}
        <div className="flex items-center gap-2 shrink-0">
          <Button
            variant="ghost"
            size="sm"
            icon={Eye}
            onClick={() => setExpanded((e) => !e)}
          >
            {expanded ? 'Hide' : 'Review Proposal'}
          </Button>
          <Button
            variant={isReviewed ? 'secondary' : 'primary'}
            size="sm"
            icon={CheckCircle2}
            disabled={isReviewed}
            onClick={() => onReview(rem.audit_id, rem.remediation_id)}
          >
            {isReviewed ? 'Reviewed' : 'Mark Reviewed'}
          </Button>
        </div>
      </div>

      {/* Expanded: Configuration Diff & Details */}
      {expanded && (
        <div className="border-t border-ncasa-border px-4 py-4 bg-ncasa-bg space-y-4">
          {/* Status Alert Banner */}
          <div className="p-3 bg-ncasa-surface border border-ncasa-border rounded text-xs space-y-1">
            <p className="font-mono text-[10px] font-bold uppercase text-ncasa-accent">
              STATUS: {rem.status} — PROPOSED CONFIGURATION (NOT EXECUTED)
            </p>
            <p className="text-ncasa-muted">
              Target Device Type: <span className="text-ncasa-text font-semibold">{rem.device_type}</span> · Affected Files:{' '}
              <span className="font-mono text-ncasa-subtle">{rem.affected_files.join(', ')}</span>
            </p>
          </div>

          {/* Current vs Proposed Diff Boxes */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div className="bg-ncasa-surface border border-ncasa-border rounded p-3 space-y-1.5">
              <p className="text-[10px] font-bold uppercase tracking-wider text-sev-critical">Current Observed State</p>
              <pre className="text-xs font-mono text-ncasa-subtle whitespace-pre-wrap leading-relaxed overflow-x-auto">
                {rem.current_configuration || 'None / Not configured'}
              </pre>
            </div>

            <div className="bg-ncasa-surface border border-status-pass/40 rounded p-3 space-y-1.5">
              <p className="text-[10px] font-bold uppercase tracking-wider text-status-pass">Proposed Configuration Change</p>
              {rem.proposed_commands && rem.proposed_commands.length > 0 ? (
                <pre className="text-xs font-mono text-ncasa-accent font-semibold whitespace-pre-wrap leading-relaxed overflow-x-auto">
                  {rem.proposed_configuration}
                </pre>
              ) : (
                <p className="text-xs text-amber-300 italic">
                  No automated commands generated. Manual review required by network administrator.
                </p>
              )}
            </div>
          </div>

          {/* Required Inputs if MANUAL_REVIEW_REQUIRED */}
          {rem.manual_review_required && rem.required_inputs?.length > 0 && (
            <div className="bg-amber-950/20 border border-amber-500/30 rounded p-3 space-y-1.5">
              <p className="text-[10px] font-bold uppercase tracking-wider text-amber-300">
                Required Operator Inputs for Safe Deployment
              </p>
              <ul className="list-disc list-inside text-xs text-ncasa-subtle space-y-0.5">
                {rem.required_inputs.map((inp, idx) => (
                  <li key={idx} className="font-semibold text-ncasa-text">{inp}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Validation Steps */}
          {rem.validation_steps && rem.validation_steps.length > 0 && (
            <div className="bg-ncasa-surface border border-ncasa-border rounded p-3 space-y-1.5">
              <p className="text-[10px] font-bold uppercase tracking-wider text-ncasa-muted">Validation & Compliance Steps</p>
              <ol className="list-decimal list-inside text-xs text-ncasa-subtle space-y-1">
                {rem.validation_steps.map((step, idx) => (
                  <li key={idx}>{step}</li>
                ))}
              </ol>
            </div>
          )}

          {/* Rollback Guidance */}
          {rem.rollback_guidance && (
            <div className="text-xs text-ncasa-muted bg-ncasa-surface p-2.5 rounded border border-ncasa-border">
              <span className="font-semibold text-ncasa-subtle">Rollback Guidance: </span>
              {rem.rollback_guidance}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
