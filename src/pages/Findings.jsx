import React, { useState, useEffect } from 'react';
import { AlertTriangle, Search, Shield, Info, FileText, CheckCircle, HelpCircle, Loader2, Sparkles } from 'lucide-react';
import { getAllFindings, explainFindingAi } from '../api/audits';
import { Table, Tr, Td } from '../components/ui/Table';
import Badge from '../components/ui/Badge';
import Input from '../components/ui/Input';
import Modal from '../components/ui/Modal';
import EmptyState from '../components/ui/EmptyState';
import Button from '../components/ui/Button';
import PageHeader from '../components/layout/PageHeader';

const severities = ['All', 'Critical', 'High', 'Medium', 'Low'];
const frameworks = ['All', 'CIS', 'NIST', 'STIG'];
const statuses = ['All', 'OPEN', 'RESOLVED', 'ACCEPTED'];

export default function Findings() {
  const [findingsSummary, setFindingsSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('All');
  const [frameworkFilter, setFrameworkFilter] = useState('All');
  const [statusFilter, setStatusFilter] = useState('All');
  const [selectedFinding, setSelectedFinding] = useState(null);

  const fetchFindingsData = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getAllFindings({
        severity: severityFilter !== 'All' ? severityFilter : undefined,
        framework: frameworkFilter !== 'All' ? frameworkFilter : undefined,
        status: statusFilter !== 'All' ? statusFilter : undefined,
      });
      setFindingsSummary(data);
    } catch (err) {
      console.error('Failed to load findings:', err);
      setError(err.message || 'Failed to fetch security findings');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFindingsData();
  }, [severityFilter, frameworkFilter, statusFilter]);

  const allFindings = findingsSummary?.findings || [];
  const limitations = findingsSummary?.assessment_limitations || [];
  const summaryCounts = findingsSummary?.summary || {
    total_findings: 0,
    open: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    assessment_limitations: 0,
  };

  const filteredFindings = allFindings.filter((f) => {
    const matchSearch =
      f.title.toLowerCase().includes(search.toLowerCase()) ||
      f.control_id.toLowerCase().includes(search.toLowerCase()) ||
      f.finding_id.toLowerCase().includes(search.toLowerCase()) ||
      f.category.toLowerCase().includes(search.toLowerCase()) ||
      f.affected_files.some((file) => file.toLowerCase().includes(search.toLowerCase()));

    return matchSearch;
  });

  const sevColor = (label) => ({
    CRITICAL: { bg: 'bg-sev-critical-bg border-sev-critical/20', text: 'text-sev-critical' },
    HIGH: { bg: 'bg-sev-high-bg border-sev-high/20', text: 'text-sev-high' },
    MEDIUM: { bg: 'bg-sev-medium-bg border-sev-medium/20', text: 'text-sev-medium' },
    LOW: { bg: 'bg-sev-low-bg border-sev-low/20', text: 'text-sev-low' },
  }[label?.toUpperCase()] ?? { bg: 'bg-ncasa-surface2', text: 'text-ncasa-muted' });

  return (
    <div className="space-y-6 flex-1 flex flex-col">
      {/* Page Header */}
      <PageHeader
        title="Security Findings"
        subtitle="Review deduplicated security findings extracted from deterministic compliance checks."
      />

      {/* Summary Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        {[
          { label: 'Critical', count: summaryCounts.critical, sevKey: 'CRITICAL' },
          { label: 'High', count: summaryCounts.high, sevKey: 'HIGH' },
          { label: 'Medium', count: summaryCounts.medium, sevKey: 'MEDIUM' },
          { label: 'Low', count: summaryCounts.low, sevKey: 'LOW' },
          { label: 'Limitations', count: summaryCounts.assessment_limitations, sevKey: 'LIMITATIONS' },
        ].map(({ label, count, sevKey }) => {
          const isLimitation = sevKey === 'LIMITATIONS';
          const s = isLimitation
            ? { bg: 'bg-ncasa-surface border-ncasa-border', text: 'text-ncasa-accent' }
            : sevColor(sevKey);
          const isSelected = severityFilter.toUpperCase() === label.toUpperCase();

          return (
            <button
              key={label}
              onClick={() => {
                if (!isLimitation) {
                  setSeverityFilter(severityFilter.toUpperCase() === label.toUpperCase() ? 'All' : label);
                }
              }}
              className={`flex items-center justify-between px-4 py-3 rounded border transition-colors ${s.bg} ${
                isSelected ? 'ring-1 ring-offset-0 ring-current' : ''
              }`}
            >
              <span className="text-xs font-medium text-ncasa-subtle">{label}</span>
              <span className={`text-xl font-bold ${s.text}`}>{count}</span>
            </button>
          );
        })}
      </div>

      {/* Filters Bar */}
      <div className="flex items-center gap-3 flex-wrap bg-ncasa-surface p-3 rounded border border-ncasa-border">
        <Input
          id="findings-search"
          placeholder="Search findings, control IDs, files..."
          icon={Search}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          containerClass="flex-1 min-w-[220px] max-w-xs"
        />

        {/* Severity Filter Pills */}
        <div className="flex items-center gap-1">
          <span className="text-xs font-semibold text-ncasa-muted mr-1">Severity:</span>
          {severities.map((s) => (
            <button
              key={s}
              onClick={() => setSeverityFilter(s)}
              className={`px-2.5 py-1 text-xs font-medium rounded border transition-colors ${
                severityFilter === s
                  ? 'bg-ncasa-accent text-white border-ncasa-accent'
                  : 'bg-ncasa-surface2 text-ncasa-muted border-ncasa-border hover:text-ncasa-text'
              }`}
            >
              {s}
            </button>
          ))}
        </div>

        {/* Framework Filter Pills */}
        <div className="flex items-center gap-1">
          <span className="text-xs font-semibold text-ncasa-muted mr-1">Framework:</span>
          {frameworks.map((fw) => (
            <button
              key={fw}
              onClick={() => setFrameworkFilter(fw)}
              className={`px-2.5 py-1 text-xs font-medium rounded border transition-colors ${
                frameworkFilter === fw
                  ? 'bg-ncasa-accent text-white border-ncasa-accent'
                  : 'bg-ncasa-surface2 text-ncasa-muted border-ncasa-border hover:text-ncasa-text'
              }`}
            >
              {fw}
            </button>
          ))}
        </div>
      </div>

      {/* Main Content Area */}
      {loading ? (
        <div className="py-12 flex flex-col items-center justify-center space-y-3 bg-ncasa-surface border border-ncasa-border rounded">
          <Loader2 size={24} className="animate-spin text-ncasa-accent" />
          <p className="text-sm text-ncasa-muted">Extracting deduplicated security findings...</p>
        </div>
      ) : error ? (
        <div className="p-4 bg-status-fail-bg border border-status-fail/30 rounded text-status-fail text-sm">
          {error}
        </div>
      ) : filteredFindings.length === 0 ? (
        <EmptyState
          icon={Shield}
          title="No Actionable Findings Generated"
          description="Either all compliance controls passed, or no findings match your selected filters."
        />
      ) : (
        <div className="space-y-3">
          <div className="flex justify-between items-center text-xs text-ncasa-muted px-1">
            <span>
              Showing <strong className="text-ncasa-text">{filteredFindings.length}</strong> findings
            </span>
            {findingsSummary?.audit_id && (
              <span className="font-mono text-[11px]">Audit ID: {findingsSummary.audit_id}</span>
            )}
          </div>

          {/* Findings Table */}
          <Table headers={['Severity', 'Finding ID', 'Control ID', 'Title', 'Category', 'Affected Files', 'Status']}>
            {filteredFindings.map((f) => (
              <Tr key={f.finding_id} onClick={() => setSelectedFinding(f)}>
                <Td>
                  <Badge label={f.severity} type="severity" />
                </Td>
                <Td>
                  <span className="font-mono text-[11px] text-ncasa-subtle bg-ncasa-surface2 px-1.5 py-0.5 rounded">
                    {f.finding_id}
                  </span>
                </Td>
                <Td>
                  <span className="font-mono text-xs font-bold text-ncasa-accent">{f.control_id}</span>
                </Td>
                <Td>
                  <span className="text-sm font-semibold text-ncasa-text hover:text-ncasa-accent transition-colors">
                    {f.title}
                  </span>
                </Td>
                <Td>
                  <span className="text-xs text-ncasa-subtle font-medium">{f.category}</span>
                </Td>
                <Td>
                  <span className="font-mono text-xs text-ncasa-muted">
                    {f.affected_files.length} {f.affected_files.length === 1 ? 'file' : 'files'}
                  </span>
                </Td>
                <Td>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">
                    {f.status}
                  </span>
                </Td>
              </Tr>
            ))}
          </Table>
        </div>
      )}

      {/* Separate Section: Assessment Limitations (NOT_VERIFIABLE controls) */}
      {limitations.length > 0 && (
        <div className="bg-ncasa-surface border border-ncasa-border rounded p-5 space-y-3">
          <div className="flex items-center gap-2 border-b border-ncasa-border pb-2">
            <Info size={18} className="text-ncasa-accent" />
            <h3 className="text-sm font-bold text-ncasa-text">Assessment Limitations ({limitations.length})</h3>
            <span className="text-xs text-ncasa-muted">
              (Controls with insufficient configuration evidence — NOT security vulnerabilities)
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {limitations.map((lim) => (
              <div key={lim.control_id} className="bg-ncasa-surface2 p-3.5 rounded border border-ncasa-border space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs font-bold text-ncasa-accent">{lim.control_id}</span>
                  <span className="text-[10px] uppercase font-bold text-ncasa-muted px-1.5 py-0.5 bg-ncasa-surface rounded">
                    {lim.framework}
                  </span>
                </div>
                <h4 className="text-xs font-semibold text-ncasa-text">{lim.title}</h4>
                <p className="text-xs text-ncasa-muted">{lim.reason}</p>
                <p className="text-[10px] text-ncasa-subtle font-mono">
                  Affected: {lim.affected_files.join(', ')}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Finding Detail Modal */}
      <Modal
        isOpen={!!selectedFinding}
        onClose={() => setSelectedFinding(null)}
        title="Security Finding Detail"
        size="lg"
      >
        {selectedFinding && <FindingDetailDrawer finding={selectedFinding} />}
      </Modal>
    </div>
  );
}

function FindingDetailDrawer({ finding }) {
  const [aiExplanation, setAiExplanation] = useState(null);
  const [loadingAi, setLoadingAi] = useState(false);
  const [aiError, setAiError] = useState(null);

  const handleExplain = async () => {
    setLoadingAi(true);
    setAiError(null);
    try {
      const auditId = finding.audit_id || 'GLOBAL';
      const result = await explainFindingAi(auditId, finding.finding_id);
      setAiExplanation(result);
    } catch (err) {
      setAiError(err.message || 'Failed to generate AI explanation');
    } finally {
      setLoadingAi(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Header Info */}
      <div className="pb-3 border-b border-ncasa-border">
        <div className="flex items-center justify-between">
          <span className="font-mono text-xs text-ncasa-accent font-bold">{finding.finding_id}</span>
          <Badge label={finding.severity} type="severity" />
        </div>
        <h3 className="text-base font-bold text-ncasa-text mt-1">{finding.title}</h3>
        <p className="text-xs text-ncasa-muted mt-1">{finding.description}</p>
      </div>

      {/* Meta Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-ncasa-surface2 p-3 rounded border border-ncasa-border text-xs">
        <div>
          <p className="text-[10px] uppercase font-semibold text-ncasa-muted">Control ID</p>
          <p className="font-mono font-bold text-ncasa-text">{finding.control_id}</p>
        </div>
        <div>
          <p className="text-[10px] uppercase font-semibold text-ncasa-muted">Framework</p>
          <p className="font-bold text-ncasa-text">{finding.framework}</p>
        </div>
        <div>
          <p className="text-[10px] uppercase font-semibold text-ncasa-muted">Category</p>
          <p className="font-bold text-ncasa-text">{finding.category}</p>
        </div>
        <div>
          <p className="text-[10px] uppercase font-semibold text-ncasa-muted">Status</p>
          <p className="font-bold text-amber-300 font-mono">{finding.status}</p>
        </div>
      </div>

      {/* Expected vs Observed */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div className="bg-ncasa-surface border border-status-pass/30 rounded p-3 space-y-1">
          <p className="text-[10px] font-bold uppercase tracking-wider text-status-pass">Expected Requirement</p>
          <p className="text-xs text-ncasa-subtle leading-relaxed font-mono">{finding.expected}</p>
        </div>
        <div className="bg-ncasa-surface border border-sev-critical/30 rounded p-3 space-y-1">
          <p className="text-[10px] font-bold uppercase tracking-wider text-sev-critical">Observed State</p>
          <p className="text-xs text-ncasa-subtle leading-relaxed font-mono">{finding.observed}</p>
        </div>
      </div>

      {/* Affected Files */}
      <div className="space-y-1">
        <p className="text-[10px] font-bold uppercase tracking-wider text-ncasa-muted">Affected Configuration Files</p>
        <div className="flex flex-wrap gap-1.5">
          {finding.affected_files.map((file, idx) => (
            <span key={idx} className="font-mono text-xs px-2 py-0.5 rounded bg-ncasa-surface2 text-ncasa-text border border-ncasa-border">
              {file}
            </span>
          ))}
        </div>
      </div>

      {/* Traceable Line Evidence Chain */}
      <div className="space-y-1.5">
        <p className="text-[10px] font-bold uppercase tracking-wider text-ncasa-muted">
          Line Evidence Chain ({finding.evidence?.length || 0} items)
        </p>
        <div className="max-h-40 overflow-y-auto space-y-1 font-mono text-[11px] bg-ncasa-surface p-2.5 rounded border border-ncasa-border">
          {finding.evidence?.map((ev, idx) => (
            <div key={idx} className="flex items-center justify-between text-ncasa-subtle border-b border-ncasa-border/40 pb-0.5">
              <div className="flex items-center gap-2">
                <span className="text-ncasa-accent font-bold">Line {ev.source_line}:</span>
                <span className="text-ncasa-muted">[{ev.field}]</span>
                <span className="text-ncasa-text">{ev.source_text}</span>
              </div>
              <span className="text-[9px] uppercase px-1 rounded bg-ncasa-surface2 text-ncasa-muted">
                {ev.source_file}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Block 10 AI Explanation Trigger & Card */}
      <div className="border-t border-ncasa-border pt-3 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs font-bold text-ncasa-accent">
            <Sparkles size={16} />
            <span>AI-Assisted Security Explanation</span>
          </div>
          <Button
            variant="secondary"
            size="sm"
            onClick={handleExplain}
            disabled={loadingAi}
            icon={loadingAi ? Loader2 : Sparkles}
          >
            {loadingAi ? 'Analyzing Risk…' : 'Explain Finding (AI)'}
          </Button>
        </div>

        {aiError && (
          <p className="text-xs text-sev-critical bg-sev-critical-bg p-2 rounded border border-sev-critical/30">{aiError}</p>
        )}

        {aiExplanation && (
          <div className="bg-ncasa-surface border border-ncasa-accent/40 rounded p-4 space-y-3 text-xs">
            <div className="flex items-center justify-between border-b border-ncasa-border pb-2">
              <span className="font-bold text-ncasa-text">{aiExplanation.summary}</span>
              <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-ncasa-accent/20 text-ncasa-accent font-bold">
                Confidence: {Math.round(aiExplanation.confidence * 100)}%
              </span>
            </div>

            <div className="space-y-1">
              <p className="text-[10px] font-bold uppercase tracking-wider text-ncasa-accent">Technical Security Impact</p>
              <p className="text-ncasa-subtle leading-relaxed">{aiExplanation.security_impact}</p>
            </div>

            <div className="space-y-1">
              <p className="text-[10px] font-bold uppercase tracking-wider text-ncasa-muted">Line Evidence Interpretation</p>
              <p className="text-ncasa-subtle leading-relaxed font-mono text-[11px]">{aiExplanation.evidence_interpretation}</p>
            </div>

            <div className="space-y-1 bg-ncasa-surface2 p-2.5 rounded border border-ncasa-border">
              <p className="text-[10px] font-bold uppercase tracking-wider text-status-pass">Recommended Manual Review Steps</p>
              <p className="text-ncasa-subtle leading-relaxed">{aiExplanation.recommended_review}</p>
            </div>
          </div>
        )}
      </div>

      {/* Remediation Status */}
      <div className="bg-ncasa-surface2 border border-ncasa-border rounded p-3 space-y-1">
        <div className="flex items-center justify-between">
          <p className="text-[10px] font-bold uppercase tracking-wider text-ncasa-muted">Remediation Status</p>
          <span className="font-mono text-[10px] font-bold px-2 py-0.5 rounded bg-ncasa-surface text-ncasa-accent border border-ncasa-border">
            {finding.remediation_status}
          </span>
        </div>
        <p className="text-xs text-ncasa-muted leading-relaxed">
          Remediation script generation and execution is handled in Block 9. Administrator validation is required before any configuration changes are applied.
        </p>
      </div>
    </div>
  );
}

