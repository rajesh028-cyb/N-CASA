import React from 'react';

const variants = {
  primary:   'bg-ncasa-accent hover:bg-ncasa-accent-h text-white border border-transparent',
  secondary: 'bg-ncasa-surface2 hover:bg-ncasa-border text-ncasa-text border border-ncasa-border',
  ghost:     'bg-transparent hover:bg-ncasa-surface2 text-ncasa-subtle border border-transparent',
  danger:    'bg-sev-critical hover:bg-red-700 text-white border border-transparent',
};

const sizes = {
  sm:  'px-3 py-1.5 text-xs',
  md:  'px-4 py-2 text-sm',
  lg:  'px-5 py-2.5 text-sm',
};

/**
 * Button — N-CASA reusable button component.
 * @param {'primary'|'secondary'|'ghost'|'danger'} variant
 * @param {'sm'|'md'|'lg'} size
 */
export default function Button({
  children,
  variant = 'primary',
  size = 'md',
  className = '',
  disabled = false,
  onClick,
  type = 'button',
  icon: Icon,
  ...props
}) {
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className={`
        inline-flex items-center gap-2 font-medium rounded
        transition-colors duration-150 focus:outline-none
        focus:ring-2 focus:ring-ncasa-accent focus:ring-offset-1 focus:ring-offset-ncasa-bg
        disabled:opacity-40 disabled:cursor-not-allowed
        ${variants[variant] ?? variants.primary}
        ${sizes[size] ?? sizes.md}
        ${className}
      `}
      {...props}
    >
      {Icon && <Icon size={14} />}
      {children}
    </button>
  );
}
