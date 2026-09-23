import React, { useEffect, useRef } from 'react';
import { X } from 'lucide-react';

/**
 * Modal — accessible overlay modal.
 * @param {boolean} isOpen
 * @param {() => void} onClose
 * @param {string} title
 * @param {'sm'|'md'|'lg'|'xl'} size
 */
export default function Modal({ isOpen, onClose, title, children, size = 'md' }) {
  const overlayRef = useRef(null);

  const widths = {
    sm: 'max-w-md',
    md: 'max-w-2xl',
    lg: 'max-w-3xl',
    xl: 'max-w-5xl',
  };

  useEffect(() => {
    if (!isOpen) return;
    const handleKey = (e) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', handleKey);
    document.body.style.overflow = 'hidden';
    return () => {
      document.removeEventListener('keydown', handleKey);
      document.body.style.overflow = '';
    };
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div
      ref={overlayRef}
      className="fixed inset-0 z-50 flex items-start justify-center bg-black/70 backdrop-blur-sm overflow-y-auto py-10 px-4"
      onClick={(e) => { if (e.target === overlayRef.current) onClose(); }}
    >
      <div className={`w-full ${widths[size] ?? widths.md} bg-ncasa-surface2 border border-ncasa-border2 rounded shadow-2xl`}>
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-ncasa-border">
          <h2 className="text-base font-semibold text-ncasa-text">{title}</h2>
          <button
            onClick={onClose}
            className="text-ncasa-muted hover:text-ncasa-text transition-colors p-1 rounded focus:outline-none focus:ring-2 focus:ring-ncasa-accent"
            aria-label="Close modal"
          >
            <X size={18} />
          </button>
        </div>
        {/* Body */}
        <div className="px-5 py-4">{children}</div>
      </div>
    </div>
  );
}
