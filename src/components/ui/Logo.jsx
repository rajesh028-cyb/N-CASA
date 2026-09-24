import React from 'react';

/**
 * ShieldLogo — Custom modern cybersecurity & compliance shield logo.
 * Features geometric facets, gradient accents, and auditing node elements.
 *
 * @param {number} [size=32] - Width and height in pixels
 * @param {string} [className=''] - Additional CSS classes
 */
export default function ShieldLogo({ size = 32, className = '' }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={`shrink-0 ${className}`}
      aria-label="N-CASA Security Shield Logo"
    >
      <defs>
        <linearGradient id="ncasaShieldBorder" x1="4" y1="3" x2="28" y2="29" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#3b82f6" />
          <stop offset="50%" stopColor="#2563eb" />
          <stop offset="100%" stopColor="#06b6d4" />
        </linearGradient>
        <linearGradient id="ncasaShieldFill" x1="16" y1="3" x2="16" y2="29" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#131926" />
          <stop offset="100%" stopColor="#0b0f19" />
        </linearGradient>
        <linearGradient id="ncasaFacet" x1="16" y1="3" x2="28" y2="15" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.25" />
          <stop offset="100%" stopColor="#2563eb" stopOpacity="0.05" />
        </linearGradient>
      </defs>

      {/* Main Outer Shield Container */}
      <path
        d="M16 3L5 7.6V14.8C5 21.6 9.7 27.9 16 29.5C22.3 27.9 27 21.6 27 14.8V7.6L16 3Z"
        fill="url(#ncasaShieldFill)"
        stroke="url(#ncasaShieldBorder)"
        strokeWidth="1.75"
        strokeLinecap="round"
        strokeLinejoin="round"
      />

      {/* Right Facet Depth Highlight */}
      <path
        d="M16 4.8V27.4C21.2 25.8 25.2 20.4 25.2 14.8V8.6L16 4.8Z"
        fill="url(#ncasaFacet)"
      />

      {/* Internal Security Audit Check & Crossbar */}
      <path
        d="M10.5 15.2L14.2 18.8L21.5 11.5"
        stroke="#38bdf8"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />

      {/* Top Core Security Node */}
      <circle cx="16" cy="8.2" r="1.2" fill="#60a5fa" />
    </svg>
  );
}
