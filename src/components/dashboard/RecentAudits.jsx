import React from 'react';
import { Link } from 'react-router-dom';
import { Table, Tr, Td } from '../ui/Table';
import Badge from '../ui/Badge';
import { Eye, FileText, FilePlus2 } from 'lucide-react';
import Button from '../ui/Button';

/**
 * RecentAudits — dashboard table showing latest audit records from PostgreSQL.
 * @param {Array} audits - audit objects
 */
export default function RecentAudits({ audits = [] }) {
  const headers = ['Audit ID / File', 'Framework', 'Created', 'Status', 'Findings', 'Actions'];

  if (!audits || audits.length === 0) {
    return (
      <div className="py-10 text-center flex flex-col items-center justify-center space-y-3">
        <p className="text-sm font-semibold text-ncasa-text">No audits yet</p>
        <p className="text-xs text-ncasa-muted max-w-sm">
          No security audit records found in the database. Ingest a configuration package to begin deterministic compliance analysis.
        </p>
        <Link to="/audit/new" className="pt-1">
          <Button variant="primary" size="sm" icon={FilePlus2}>
            Start New Audit
          </Button>
        </Link>
      </div>
    );
  }

  return (
    <Table headers={headers}>
      {audits.map((audit) => (
        <Tr key={audit.id}>
          <Td>
            <div>
              <span className="font-mono text-xs font-bold text-ncasa-accent block">{audit.id}</span>
              <span className="text-xs text-ncasa-subtle truncate max-w-[180px] block">{audit.device}</span>
            </div>
          </Td>
          <Td>
            <Badge label={audit.auditType} type="vendor" />
          </Td>
          <Td>
            <span className="text-ncasa-muted text-xs">{audit.date}</span>
          </Td>
          <Td>
            <Badge label={audit.status} type="status" />
          </Td>
          <Td>
            <span className="font-mono text-xs font-semibold text-ncasa-text">{audit.findings}</span>
          </Td>
          <Td>
            <div className="flex items-center gap-2">
              <Link
                to="/findings"
                className="inline-flex items-center gap-1 text-xs font-medium text-ncasa-accent hover:underline px-2 py-1 rounded bg-ncasa-surface2"
                title="View Findings"
              >
                <Eye size={12} /> View
              </Link>
              <Link
                to="/reports"
                className="inline-flex items-center gap-1 text-xs font-medium text-status-pass hover:underline px-2 py-1 rounded bg-ncasa-surface2"
                title="View Reports"
              >
                <FileText size={12} /> Reports
              </Link>
            </div>
          </Td>
        </Tr>
      ))}
    </Table>
  );
}

