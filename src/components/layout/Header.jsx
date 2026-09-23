import React, { useEffect, useState } from 'react';
import { Bell, ChevronDown, Shield, Database, Activity } from 'lucide-react';
import { getHealthStatus } from '../../api/client';

/**
 * Header — top application bar with system health and user badge.
 * @param {() => void} onMobileMenuToggle
 */
export default function Header({ onMobileMenuToggle }) {
  const [health, setHealth] = useState({ status: 'checking', database: 'checking' });

  useEffect(() => {
    let mounted = true;
    async function checkHealth() {
      try {
        const res = await getHealthStatus();
        if (mounted) {
          setHealth(res);
        }
      } catch (err) {
        if (mounted) {
          setHealth({ status: 'degraded', database: 'unavailable' });
        }
      }
    }
    checkHealth();
    const timer = setInterval(checkHealth, 30000);
    return () => {
      mounted = false;
      clearInterval(timer);
    };
  }, []);

  const apiOk = health.status === 'healthy';
  const dbOk = health.database === 'connected';

  return (
    <header className="h-[57px] shrink-0 flex items-center justify-between px-5 bg-ncasa-surface border-b border-ncasa-border">
      {/* Left: Mobile menu toggle + Brand Title */}
      <div className="flex items-center gap-3">
        <button
          onClick={onMobileMenuToggle}
          className="lg:hidden text-ncasa-muted hover:text-ncasa-text transition-colors p-1 rounded"
          aria-label="Toggle navigation"
        >
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <line x1="3" y1="6" x2="21" y2="6" />
            <line x1="3" y1="12" x2="21" y2="12" />
            <line x1="3" y1="18" x2="21" y2="18" />
          </svg>
        </button>

        <div className="flex items-center gap-2">
          <div className="hidden lg:flex items-center justify-center w-6 h-6 bg-ncasa-accent rounded">
            <Shield size={14} className="text-white" />
          </div>
          <div>
            <span className="text-sm font-bold text-ncasa-text tracking-tight">N-CASA</span>
            <span className="hidden md:inline text-xs text-ncasa-muted ml-2 border-l border-ncasa-border pl-2">
              Network Configuration Automated Security Auditor
            </span>
          </div>
        </div>
      </div>

      {/* Right: Live System Status & User Badge */}
      <div className="flex items-center gap-3">
        {/* System & DB Status Pill */}
        <div className="hidden sm:flex items-center gap-3 text-xs bg-ncasa-surface2 border border-ncasa-border px-3 py-1 rounded">
          <div className="flex items-center gap-1.5" title={`API Service: ${health.status}`}>
            <Activity size={12} className={apiOk ? 'text-status-pass' : 'text-sev-critical'} />
            <span className="text-ncasa-muted">API</span>
            <span className={`font-semibold ${apiOk ? 'text-ncasa-text' : 'text-sev-critical'}`}>
              {apiOk ? 'Operational' : 'Degraded'}
            </span>
          </div>
          <div className="w-px h-3 bg-ncasa-border" />
          <div className="flex items-center gap-1.5" title={`PostgreSQL Database: ${health.database}`}>
            <Database size={12} className={dbOk ? 'text-status-pass' : 'text-sev-critical'} />
            <span className="text-ncasa-muted">Database</span>
            <span className={`font-semibold ${dbOk ? 'text-ncasa-text' : 'text-sev-critical'}`}>
              {dbOk ? 'Connected' : 'Unavailable'}
            </span>
          </div>
        </div>

        {/* Notification bell */}
        <button
          className="relative text-ncasa-muted hover:text-ncasa-text transition-colors p-2 rounded hover:bg-ncasa-surface2 focus:outline-none focus:ring-2 focus:ring-ncasa-accent"
          aria-label="Notifications"
          id="header-notifications-btn"
        >
          <Bell size={16} />
          <span className="absolute top-1.5 right-1.5 w-1.5 h-1.5 rounded-full bg-status-pass" />
        </button>

        {/* Divider */}
        <div className="w-px h-5 bg-ncasa-border" />

        {/* Admin user */}
        <button
          className="flex items-center gap-2 text-sm text-ncasa-subtle hover:text-ncasa-text transition-colors px-2 py-1.5 rounded hover:bg-ncasa-surface2 focus:outline-none focus:ring-2 focus:ring-ncasa-accent"
          id="header-user-btn"
        >
          <div className="w-6 h-6 rounded bg-ncasa-accent-l border border-ncasa-accent/40 flex items-center justify-center">
            <span className="text-[10px] font-bold text-ncasa-accent">A</span>
          </div>
          <span className="hidden sm:inline font-medium">Admin</span>
          <ChevronDown size={12} className="text-ncasa-muted" />
        </button>
      </div>
    </header>
  );
}

