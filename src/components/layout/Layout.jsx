import React, { useState } from 'react';
import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar';
import Header from './Header';

/**
 * Layout — root application layout wrapping Sidebar + Header + page content.
 */
export default function Layout() {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);

  return (
    <div className="flex h-screen overflow-hidden bg-ncasa-bg">
      {/* ── Mobile overlay ── */}
      {mobileSidebarOpen && (
        <div
          className="fixed inset-0 z-30 bg-black/60 lg:hidden"
          onClick={() => setMobileSidebarOpen(false)}
        />
      )}

      {/* ── Sidebar ── */}
      {/* Desktop: always visible, collapsible */}
      <div className="hidden lg:flex h-full">
        <Sidebar collapsed={sidebarCollapsed} setCollapsed={setSidebarCollapsed} />
      </div>

      {/* Mobile: slide-in drawer */}
      <div
        className={`
          fixed inset-y-0 left-0 z-40 flex h-full lg:hidden
          transition-transform duration-200
          ${mobileSidebarOpen ? 'translate-x-0' : '-translate-x-full'}
        `}
      >
        <Sidebar collapsed={false} setCollapsed={() => {}} />
      </div>

      {/* ── Main area ── */}
      <div className="flex flex-col flex-1 min-w-0 overflow-hidden">
        <Header onMobileMenuToggle={() => setMobileSidebarOpen((o) => !o)} />

        {/* Scrollable page content */}
        <main className="flex-1 overflow-y-auto bg-ncasa-bg">
          <div className="max-w-screen-xl mx-auto px-5 py-6">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
