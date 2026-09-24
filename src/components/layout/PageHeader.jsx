import React from 'react';

/**
 * PageHeader — Unified header for all N-CASA pages.
 * Enforces consistent page shell title geometry, typography, line-height,
 * subtitle spacing, and action element alignment across every route.
 *
 * @param {string|React.ReactNode} title - Page title
 * @param {string|React.ReactNode} [subtitle] - Page subtitle / description
 * @param {React.ReactNode} [actions] - Action buttons or elements (right aligned)
 * @param {string} [className] - Optional extra class names
 */
export default function PageHeader({ title, subtitle, actions, className = '' }) {
  return (
    <div className={`flex items-start justify-between gap-4 flex-wrap pb-1 ${className}`}>
      <div className="min-w-0 flex-1">
        <h1 className="text-xl font-bold text-ncasa-text tracking-tight leading-tight">
          {title}
        </h1>
        {subtitle && (
          <p className="text-sm text-ncasa-muted mt-1 leading-normal">
            {subtitle}
          </p>
        )}
      </div>
      {actions && (
        <div className="flex items-center gap-2.5 shrink-0 pt-0.5">
          {actions}
        </div>
      )}
    </div>
  );
}
