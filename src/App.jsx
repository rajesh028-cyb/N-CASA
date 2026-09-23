import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/layout/Layout';
import Dashboard from './pages/Dashboard';
import NewAudit from './pages/NewAudit';
import Devices from './pages/Devices';
import Findings from './pages/Findings';
import Remediation from './pages/Remediation';
import Reports from './pages/Reports';
import Settings from './pages/Settings';

// ══════════════════════════════════════════════════════════════════
// N-CASA — App Router
// ══════════════════════════════════════════════════════════════════
// Route map:
//   /                → Dashboard
//   /audit/new       → New Audit
//   /devices         → Device Inventory
//   /findings        → Security Findings
//   /remediation     → Remediation Management
//   /reports         → Audit Reports
//   /settings        → Application Settings
//
// Block 2+: protected routes (auth) will be layered on top here.
// ══════════════════════════════════════════════════════════════════

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Dashboard />} />
          <Route path="audit/new" element={<NewAudit />} />
          <Route path="devices" element={<Devices />} />
          <Route path="findings" element={<Findings />} />
          <Route path="remediation" element={<Remediation />} />
          <Route path="reports" element={<Reports />} />
          <Route path="settings" element={<Settings />} />
          {/* Catch-all: redirect unknown routes to dashboard */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
