import React from 'react';

/**
 * Select — styled select dropdown.
 */
export default function Select({
  id,
  label,
  options = [],
  className = '',
  containerClass = '',
  ...props
}) {
  return (
    <div className={`flex flex-col gap-1 ${containerClass}`}>
      {label && (
        <label htmlFor={id} className="text-xs font-medium text-ncasa-subtle">
          {label}
        </label>
      )}
      <select
        id={id}
        className={`
          w-full bg-ncasa-surface2 border border-ncasa-border rounded
          px-3 py-2 text-sm text-ncasa-text
          focus:outline-none focus:ring-2 focus:ring-ncasa-accent focus:border-transparent
          transition-colors duration-150 cursor-pointer
          ${className}
        `}
        {...props}
      >
        {options.map((opt) => (
          <option key={opt.value} value={opt.value} className="bg-ncasa-surface2">
            {opt.label}
          </option>
        ))}
      </select>
    </div>
  );
}
