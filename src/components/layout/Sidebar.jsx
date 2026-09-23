import React, { useState } from 'react';
import { NavLink, Link } from 'react-router-dom';
import {
  LayoutDashboard,
  FilePlus2,
  Server,
  AlertTriangle,
  Wrench,
  FileText,
  Settings,
  Shield,
  ChevronLeft,
  ChevronRight,
  Menu,
} from 'lucide-react';

const navItems = [
  { to: '/',             label: 'Dashboard',    icon: LayoutDashboard },
  { to: '/audit/new',    label: 'New Audit',    icon: FilePlus2 },
  { to: '/devices',      label: 'Devices',      icon: Server },
  { to: '/findings',     label: 'Findings',     icon: AlertTriangle },
  { to: '/remediation',  label: 'Remediation',  icon: Wrench },
  { to: '/reports',      label: 'Reports',      icon: FileText },
];

export default function Sidebar({ collapsed, setCollapsed }) {
  return (
    <aside
      className={`
        flex flex-col h-full bg-ncasa-surface border-r border-ncasa-border
        transition-all duration-200 shrink-0
        ${collapsed ? 'w-[60px]' : 'w-[220px]'}
      `}
    >
      {/* Logo area */}
      <div className={`flex items-center border-b border-ncasa-border px-4 h-[57px] shrink-0 ${collapsed ? 'justify-center px-2' : ''}`}>
        <div className="flex items-center gap-2.5 min-w-0">
          <div className="shrink-0 flex items-center justify-center w-8 h-8 bg-ncasa-accent rounded">
            <Shield size={16} className="text-white" />
          </div>
          {!collapsed && (
            <div className="min-w-0">
              <p className="text-sm font-bold text-ncasa-text tracking-tight leading-none">N-CASA</p>
              <p className="text-[10px] text-ncasa-muted leading-tight mt-0.5 truncate">Security Auditor</p>
            </div>
          )}
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 overflow-y-auto py-3 px-2 space-y-0.5">
        {!collapsed && (
          <p className="section-label mt-1 mb-2">Navigation</p>
        )}
        {navItems.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              `nav-item ${isActive ? 'active' : ''}`
            }
            title={collapsed ? label : undefined}
          >
            <Icon size={16} className="shrink-0" />
            {!collapsed && <span className="truncate">{label}</span>}
          </NavLink>
        ))}
      </nav>

      {/* Bottom: Settings + collapse toggle */}
      <div className="border-t border-ncasa-border px-2 py-3 space-y-0.5">
        <NavLink
          to="/settings"
          className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
          title={collapsed ? 'Settings' : undefined}
        >
          <Settings size={16} className="shrink-0" />
          {!collapsed && <span className="truncate">Settings</span>}
        </NavLink>

        <button
          onClick={() => setCollapsed((c) => !c)}
          className="nav-item w-full"
          title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {collapsed
            ? <ChevronRight size={16} className="shrink-0" />
            : <><ChevronLeft size={16} className="shrink-0" /><span className="truncate text-xs">Collapse</span></>
          }
        </button>
      </div>
    </aside>
  );
}
