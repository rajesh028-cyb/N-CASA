import React from 'react';

/**
 * Card — container with N-CASA surface styling.
 * @param {'default'|'interactive'|'highlighted'} variant
 */
export default function Card({ children, className = '', variant = 'default', onClick }) {
  const base = 'bg-ncasa-surface border border-ncasa-border rounded p-4';
  const variantClass = {
    default:     '',
    interactive: 'transition-colors duration-150 hover:border-ncasa-border2 cursor-pointer',
    highlighted: 'border-ncasa-accent/40 bg-ncasa-accent-l/30',
  }[variant] ?? '';

  return (
    <div className={`${base} ${variantClass} ${className}`} onClick={onClick}>
      {children}
    </div>
  );
}
