import React, { useEffect, useState } from 'react';
import { Bell, ChevronDown } from 'lucide-react';
import { getHealthStatus } from '../../api/client';

/**
 * Header — Top application navigation bar.
 * Provides subtle application context, live infrastructure status indicators,
 * and user profile actions without duplicating sidebar branding.
 *
 * @param {() => void} onMobileMenuToggle - Mobile drawer menu toggle handler
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
    <header className="h-14 shrink-0 flex items-center justify-between px-6 bg-ncasa-surface border-b border-ncasa-border select-none">
      {/* Left: Mobile Toggle + Subtle Application Context */}
      <div className="flex items-center gap-3 min-w-0">
        <button
          onClick={onMobileMenuToggle}
          className="lg:hidden text-ncasa-muted hover:text-ncasa-text transition-colors p-1.5 rounded hover:bg-ncasa-surface2 focus:outline-none focus:ring-2 focus:ring-ncasa-accent"
          aria-label="Toggle navigation menu"
        >
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <line x1="3" y1="6" x2="21" y2="6" />
            <line x1="3" y1="12" x2="21" y2="12" />
            <line x1="3" y1="18" x2="21" y2="18" />
          </svg>
        </button>

        {/* Subtle context label — no duplicate brand */}
        <div className="flex items-center gap-2 truncate">
          <span className="text-xs sm:text-sm font-medium text-ncasa-muted tracking-wide truncate">
            AI-Driven Multi-Vendor Network Security Auditor
          </span>
        </div>
      </div>

      {/* Right: Live System Status & User Actions */}
      <div className="flex items-center gap-2.5 sm:gap-3 shrink-0">
        {/* Status Indicators */}
        <div className="hidden md:flex items-center gap-2">
          {/* API Status */}
          <div
            className="flex items-center gap-2 text-xs bg-ncasa-surface2 border border-ncasa-border px-2.5 py-1 rounded transition-colors"
            title={`Backend Service: ${health.status}`}
          >
            <span
              className={`w-2 h-2 rounded-full shrink-0 ${
                apiOk
                  ? 'bg-status-pass shadow-[0_0_6px_rgba(22,163,74,0.6)]'
                  : 'bg-sev-critical shadow-[0_0_6px_rgba(220,38,38,0.6)]'
              }`}
            />
            <span className="text-ncasa-muted font-medium">API</span>
            <span className={`font-semibold ${apiOk ? 'text-ncasa-text' : 'text-sev-critical'}`}>
              {apiOk ? 'Operational' : 'Degraded'}
            </span>
          </div>

          {/* Database Status */}
          <div
            className="flex items-center gap-2 text-xs bg-ncasa-surface2 border border-ncasa-border px-2.5 py-1 rounded transition-colors"
            title={`PostgreSQL Database: ${health.database}`}
          >
            <span
              className={`w-2 h-2 rounded-full shrink-0 ${
                dbOk
                  ? 'bg-status-pass shadow-[0_0_6px_rgba(22,163,74,0.6)]'
                  : 'bg-sev-critical shadow-[0_0_6px_rgba(220,38,38,0.6)]'
              }`}
            />
            <span className="text-ncasa-muted font-medium">Database</span>
            <span className={`font-semibold ${dbOk ? 'text-ncasa-text' : 'text-sev-critical'}`}>
              {dbOk ? 'Connected' : 'Unavailable'}
            </span>
          </div>
        </div>

        {/* Notifications */}
        <button
          className="relative text-ncasa-muted hover:text-ncasa-text transition-colors p-2 rounded hover:bg-ncasa-surface2 focus:outline-none focus:ring-2 focus:ring-ncasa-accent"
          aria-label="System notifications"
          id="header-notifications-btn"
          title="Notifications"
        >
          <Bell size={16} />
          <span className="absolute top-1.5 right-1.5 w-1.5 h-1.5 rounded-full bg-status-pass" />
        </button>

        {/* Divider */}
        <div className="w-px h-4 bg-ncasa-border" />

        {/* Admin User Profile */}
        <button
          className="flex items-center gap-2 text-sm text-ncasa-subtle hover:text-ncasa-text transition-colors px-2 py-1.5 rounded hover:bg-ncasa-surface2 focus:outline-none focus:ring-2 focus:ring-ncasa-accent"
          id="header-user-btn"
          aria-label="User profile settings"
        >
          <div className="w-6 h-6 rounded bg-ncasa-accent-l border border-ncasa-accent/40 flex items-center justify-center">
            <span className="text-[10px] font-bold text-ncasa-accent leading-none">A</span>
          </div>
          <span className="hidden sm:inline font-medium text-xs text-ncasa-text">Admin</span>
          <ChevronDown size={12} className="text-ncasa-muted shrink-0" />
        </button>
      </div>
    </header>
  );
}
