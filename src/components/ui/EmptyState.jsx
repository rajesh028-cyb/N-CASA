import React from 'react';
import { Inbox } from 'lucide-react';

/**
 * EmptyState — shown when a list/table has no data.
 */
export default function EmptyState({
  icon: Icon = Inbox,
  title = 'No data available',
  description = '',
  action,
}) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      <div className="mb-4 p-4 rounded-full bg-ncasa-surface2 border border-ncasa-border">
        <Icon size={28} className="text-ncasa-muted" />
      </div>
      <p className="text-sm font-medium text-ncasa-subtle mb-1">{title}</p>
      {description && (
        <p className="text-xs text-ncasa-muted max-w-xs">{description}</p>
      )}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}
