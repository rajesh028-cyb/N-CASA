import React, { useState, useEffect } from 'react';
import { Search, Server, Info, Loader2 } from 'lucide-react';
import { getAudits, getDetectionResults } from '../api/audits';
import { Table, Tr, Td } from '../components/ui/Table';
import Badge from '../components/ui/Badge';
import Input from '../components/ui/Input';
import EmptyState from '../components/ui/EmptyState';

export default function Devices() {
  const [deviceList, setDeviceList] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [vendorFilter, setVendorFilter] = useState('All');

  useEffect(() => {
    async function loadDiscoveredDevices() {
      setLoading(true);
      try {
        const res = await getAudits({ page: 1, page_size: 50 });
        const items = res?.items || (Array.isArray(res) ? res : []);

        const list = [];
        for (const audit of items) {
          try {
            const det = await getDetectionResults(audit.audit_id);
            if (det && det.files) {
              for (const f of det.files) {
                list.push({
                  id: `${audit.audit_id}-${f.file_id}`,
                  audit_id: audit.audit_id,
                  filename: f.relative_path || f.filename,
                  hostname: f.hostname || f.relative_path || f.filename,
                  vendor: f.vendor || 'Unknown',
                  deviceType: f.device_type || 'Unknown',
                  confidence: f.confidence !== undefined ? `${Math.round(f.confidence * 100)}%` : 'N/A',
                  status: audit.status || 'DETECTED',
                  framework: audit.framework,
                  created_at: audit.created_at ? new Date(audit.created_at).toLocaleDateString() : 'N/A',
                });
              }
            } else {
              list.push({
                id: audit.audit_id,
                audit_id: audit.audit_id,
                filename: audit.relative_path || audit.filename,
                hostname: audit.relative_path || audit.filename,
                vendor: audit.vendor || 'Pending Detection',
                deviceType: 'Configuration',
                confidence: 'N/A',
                status: audit.status,
                framework: audit.framework,
                created_at: audit.created_at ? new Date(audit.created_at).toLocaleDateString() : 'N/A',
              });
            }
          } catch (e) {
            list.push({
              id: audit.audit_id,
              audit_id: audit.audit_id,
              filename: audit.relative_path || audit.filename,
              hostname: audit.relative_path || audit.filename,
              vendor: audit.vendor || 'Detected',
              deviceType: 'Configuration',
              confidence: 'N/A',
              status: audit.status,
              framework: audit.framework,
              created_at: audit.created_at ? new Date(audit.created_at).toLocaleDateString() : 'N/A',
            });
          }
        }
        setDeviceList(list);
      } catch (err) {
        console.error('Failed to load device inventory:', err);
      } finally {
        setLoading(false);
      }
    }
    loadDiscoveredDevices();
  }, []);

  const filtered = deviceList.filter((d) => {
    const matchSearch =
      (d.hostname || '').toLowerCase().includes(search.toLowerCase()) ||
      (d.filename || '').toLowerCase().includes(search.toLowerCase()) ||
      (d.vendor || '').toLowerCase().includes(search.toLowerCase()) ||
      (d.deviceType || '').toLowerCase().includes(search.toLowerCase()) ||
      (d.audit_id || '').toLowerCase().includes(search.toLowerCase());
    const matchVendor = vendorFilter === 'All' || (d.vendor || '').toUpperCase() === vendorFilter.toUpperCase();
    return matchSearch && matchVendor;
  });

  const uniqueVendors = ['All', ...new Set(deviceList.map((d) => d.vendor).filter(Boolean))];

  return (
    <div className="space-y-5">
      {/* Page header */}
      <div>
        <h1 className="text-xl font-bold text-ncasa-text">Discovered Network Devices & Configurations</h1>
        <p className="text-sm text-ncasa-muted mt-0.5">
          Configurations and detected device profiles extracted from ingested audit packages.
        </p>
      </div>

      {/* Mode Disclaimer Banner */}
      <div className="flex items-start gap-3 px-4 py-3 rounded border border-ncasa-border bg-ncasa-surface2 text-xs text-ncasa-muted">
        <Info size={16} className="text-ncasa-accent shrink-0 mt-0.5" />
        <div>
          <p className="font-semibold text-ncasa-subtle uppercase tracking-wider text-[11px]">
            OFFLINE CONFIGURATION ANALYSIS ONLY
          </p>
          <p className="text-ncasa-muted mt-0.5 leading-relaxed">
            N-CASA analyzes uploaded configuration files (.cfg, .conf, .txt, .zip). Live network scanning, SSH connections, and active SNMP polling are intentionally disabled for security compliance.
          </p>
        </div>
      </div>

      {/* Summary strip */}
      <div className="flex gap-3 flex-wrap">
        {[
          { label: 'Discovered Configurations', count: deviceList.length, color: 'text-ncasa-text' },
          { label: 'Deterministic Parsed', count: deviceList.filter((d) => ['Cisco', 'Juniper', 'Fortinet'].includes(d.vendor)).length, color: 'text-status-pass' },
          { label: 'Unknown Vendors', count: deviceList.filter((d) => d.vendor === 'Unknown' || d.vendor === 'UNKNOWN').length, color: 'text-amber-300' },
        ].map(({ label, count, color }) => (
          <div key={label} className="flex items-center gap-2 bg-ncasa-surface border border-ncasa-border rounded px-3 py-1.5">
            <span className="text-xs text-ncasa-muted">{label}</span>
            <span className={`text-sm font-bold font-mono ${color}`}>{count}</span>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap bg-ncasa-surface p-3 rounded border border-ncasa-border">
        <Input
          id="devices-search"
          placeholder="Search hostname, file, vendor, audit ID..."
          icon={Search}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          containerClass="flex-1 min-w-[220px] max-w-xs"
        />
        <div className="flex gap-1.5 flex-wrap">
          {uniqueVendors.map((v) => (
            <button
              key={v}
              onClick={() => setVendorFilter(v)}
              className={`px-3 py-1.5 text-xs font-medium rounded border transition-colors duration-100 ${
                vendorFilter === v
                  ? 'bg-ncasa-accent text-white border-ncasa-accent'
                  : 'bg-ncasa-surface2 text-ncasa-muted border-ncasa-border hover:border-ncasa-border2 hover:text-ncasa-subtle'
              }`}
            >
              {v}
            </button>
          ))}
        </div>
      </div>

      {/* Table Area */}
      {loading ? (
        <div className="py-12 flex flex-col items-center justify-center space-y-3 bg-ncasa-surface border border-ncasa-border rounded">
          <Loader2 size={24} className="animate-spin text-ncasa-accent" />
          <p className="text-sm text-ncasa-muted">Loading device inventory from PostgreSQL...</p>
        </div>
      ) : filtered.length === 0 ? (
        <EmptyState
          icon={Server}
          title="No Devices Discovered"
          description="Create a new audit and upload configuration files to discover network devices."
        />
      ) : (
        <Table headers={['Hostname / File', 'Vendor', 'Device Type', 'Confidence', 'Audit ID', 'Framework', 'Audit Status']}>
          {filtered.map((device) => (
            <Tr key={device.id}>
              <Td>
                <div>
                  <span className="font-mono text-xs font-semibold text-ncasa-text block">{device.hostname}</span>
                  {device.filename !== device.hostname && (
                    <span className="font-mono text-[10px] text-ncasa-muted truncate block">{device.filename}</span>
                  )}
                </div>
              </Td>
              <Td>
                <Badge label={device.vendor} type="vendor" />
              </Td>
              <Td>
                <span className="text-xs text-ncasa-subtle font-medium">{device.deviceType}</span>
              </Td>
              <Td>
                <span className="font-mono text-xs font-bold text-ncasa-accent">{device.confidence}</span>
              </Td>
              <Td>
                <span className="font-mono text-xs text-ncasa-subtle">{device.audit_id}</span>
              </Td>
              <Td>
                <span className="text-xs text-ncasa-muted">{device.framework}</span>
              </Td>
              <Td>
                <Badge label={device.status} type="status" />
              </Td>
            </Tr>
          ))}
        </Table>
      )}
    </div>
  );
}

