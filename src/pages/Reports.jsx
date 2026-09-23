import React, { useState, useEffect } from 'react';
import { Eye, Download, FileText, CheckCircle2, AlertTriangle, RefreshCw } from 'lucide-react';
import { getAudits } from '../api/audits';
import { fetchAuditReports, generateReport, getReportHtmlUrl, getReportPdfUrl } from '../api/reports';
import { Table, Tr, Td } from '../components/ui/Table';
import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';

export default function Reports() {
  const [reportsList, setReportsList] = useState([]);
  const [audits, setAudits] = useState([]);
  const [loading, setLoading] = useState(true);
  const [generatingFor, setGeneratingFor] = useState(null);
  const [error, setError] = useState(null);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await getAudits({ page: 1, page_size: 100 });
      const items = res.items || (Array.isArray(res) ? res : []);
      setAudits(items);

      const allReports = [];
      for (const a of (items || [])) {
        try {
          const r_list = await fetchAuditReports(a.audit_id);
          for (const r of r_list) {
            allReports.push({
              ...r,
              audit_filename: a.filename,
              framework: a.framework,
              audit_status: a.status,
            });
          }
        } catch (e) {
          // ignore audit without reports
        }
      }
      setReportsList(allReports);
    } catch (err) {
      setError(err.message || 'Failed to load reports data.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleGenerate = async (auditId) => {
    setGeneratingFor(auditId);
    try {
      await generateReport(auditId);
      await loadData();
    } catch (err) {
      alert(`Report Generation Failed: ${err.message}`);
    } finally {
      setGeneratingFor(null);
    }
  };

  return (
    <div className="space-y-5">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-ncasa-text">Security Audit Reports</h1>
          <p className="text-sm text-ncasa-muted mt-0.5">
            Persistent point-in-time HTML and PDF audit snapshots generated from PostgreSQL state.
          </p>
        </div>
        <Button variant="outline" size="sm" icon={RefreshCw} onClick={loadData} disabled={loading}>
          Refresh
        </Button>
      </div>

      {/* Safety Notice Strip */}
      <div className="flex items-start gap-3 px-4 py-3 rounded border border-ncasa-border bg-ncasa-surface2 text-xs text-ncasa-muted">
        <AlertTriangle size={14} className="shrink-0 mt-0.5 text-sev-medium" />
        <p>
          <span className="font-semibold text-ncasa-subtle">Read-Only Safety Guarantee:</span>{' '}
          Reports are snapshots of database state. Generating a report does not alter compliance rules, findings, or device configurations.
        </p>
      </div>

      {/* Summary strip */}
      <div className="flex gap-3 flex-wrap">
        {[
          { label: 'Generated Reports', count: reportsList.length, color: 'text-ncasa-text' },
          { label: 'Audits Ready', count: audits.filter((a) => a.status === 'COMPLIANCE_COMPLETE' || a.status === 'FINDINGS_COMPLETE' || a.status === 'REMEDIATION_COMPLETE' || a.status === 'AI_ANALYSIS_COMPLETE').length, color: 'text-status-pass' },
        ].map(({ label, count, color }) => (
          <div key={label} className="flex items-center gap-2 bg-ncasa-surface border border-ncasa-border rounded px-3 py-1.5">
            <span className="text-xs text-ncasa-muted">{label}</span>
            <span className={`text-sm font-bold ${color}`}>{count}</span>
          </div>
        ))}
      </div>

      {/* Generated Reports Table */}
      <div>
        <h2 className="text-base font-semibold text-ncasa-text mb-3">Persistent Report Snapshots</h2>
        {loading ? (
          <div className="p-8 text-center text-sm text-ncasa-muted">Loading audit reports...</div>
        ) : reportsList.length === 0 ? (
          <div className="p-8 text-center text-sm text-ncasa-muted bg-ncasa-surface border border-ncasa-border rounded">
            No report snapshots generated yet. Select an audit below to generate a new report.
          </div>
        ) : (
          <Table headers={['Report ID', 'Audit ID', 'File Name', 'Framework', 'Generated At', 'Version', 'Actions']}>
            {reportsList.map((r) => (
              <Tr key={r.report_id}>
                <Td>
                  <span className="font-mono text-xs font-semibold text-ncasa-accent">{r.report_id}</span>
                </Td>
                <Td>
                  <span className="font-mono text-xs text-ncasa-subtle">{r.audit_id}</span>
                </Td>
                <Td>
                  <span className="text-xs text-ncasa-text">{r.audit_filename}</span>
                </Td>
                <Td>
                  <Badge label={r.framework || 'CIS'} type="vendor" />
                </Td>
                <Td>
                  <span className="text-xs text-ncasa-muted">
                    {r.generated_at ? new Date(r.generated_at).toLocaleString() : 'N/A'}
                  </span>
                </Td>
                <Td>
                  <span className="text-xs text-ncasa-subtle">v{r.report_version}</span>
                </Td>
                <Td>
                  <div className="flex items-center gap-2">
                    <a
                      href={getReportHtmlUrl(r.audit_id, r.report_id)}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1.5 text-xs font-medium text-ncasa-accent hover:underline px-2 py-1 rounded bg-ncasa-surface2"
                    >
                      <Eye size={12} /> View HTML
                    </a>
                    <a
                      href={getReportPdfUrl(r.audit_id, r.report_id)}
                      target="_blank"
                      rel="noreferrer"
                      download={`N-CASA-${r.report_id}.pdf`}
                      className="inline-flex items-center gap-1.5 text-xs font-medium text-status-pass hover:underline px-2 py-1 rounded bg-ncasa-surface2"
                    >
                      <Download size={12} /> PDF
                    </a>
                  </div>
                </Td>
              </Tr>
            ))}
          </Table>
        )}
      </div>

      {/* Available Audits to Generate Reports */}
      <div className="pt-4">
        <h2 className="text-base font-semibold text-ncasa-text mb-3">Available Audits for Report Generation</h2>
        <Table headers={['Audit ID', 'File Name', 'Framework', 'Status', 'Action']}>
          {audits.map((a) => {
            const isReady = ['COMPLIANCE_COMPLETE', 'FINDINGS_COMPLETE', 'REMEDIATION_COMPLETE', 'AI_ANALYSIS_COMPLETE'].includes(a.status);
            return (
              <Tr key={a.audit_id}>
                <Td>
                  <span className="font-mono text-xs text-ncasa-accent">{a.audit_id}</span>
                </Td>
                <Td>
                  <span className="text-xs text-ncasa-text">{a.filename}</span>
                </Td>
                <Td>
                  <Badge label={a.framework} type="vendor" />
                </Td>
                <Td>
                  <Badge label={a.status} type="status" />
                </Td>
                <Td>
                  <Button
                    variant="outline"
                    size="sm"
                    icon={FileText}
                    onClick={() => handleGenerate(a.audit_id)}
                    disabled={!isReady || generatingFor === a.audit_id}
                  >
                    {generatingFor === a.audit_id ? 'Generating...' : 'Generate Report'}
                  </Button>
                </Td>
              </Tr>
            );
          })}
        </Table>
      </div>
    </div>
  );
}
