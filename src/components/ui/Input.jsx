import React from 'react';

/**
 * Input — styled text input with optional label and error.
 */
export default function Input({
  id,
  label,
  error,
  className = '',
  containerClass = '',
  icon: Icon,
  ...props
}) {
  return (
    <div className={`flex flex-col gap-1 ${containerClass}`}>
      {label && (
        <label htmlFor={id} className="text-xs font-medium text-ncasa-subtle">
          {label}
        </label>
      )}
      <div className="relative">
        {Icon && (
          <span className="absolute left-3 top-1/2 -translate-y-1/2 text-ncasa-muted">
            <Icon size={14} />
          </span>
        )}
        <input
          id={id}
          className={`
            w-full bg-ncasa-surface2 border border-ncasa-border rounded
            px-3 py-2 text-sm text-ncasa-text placeholder:text-ncasa-muted
            focus:outline-none focus:ring-2 focus:ring-ncasa-accent focus:border-transparent
            transition-colors duration-150
            ${Icon ? 'pl-9' : ''}
            ${error ? 'border-sev-critical focus:ring-sev-critical' : ''}
            ${className}
          `}
          {...props}
        />
      </div>
      {error && <p className="text-xs text-sev-critical">{error}</p>}
    </div>
  );
}
