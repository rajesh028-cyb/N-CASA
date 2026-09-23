/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // N-CASA Design System
        // Backgrounds
        'ncasa-bg':        '#0a0b0e',   // near-black page background
        'ncasa-surface':   '#111318',   // card / panel surface
        'ncasa-surface2':  '#181c24',   // elevated surface (modals, dropdowns)
        'ncasa-border':    '#1f2535',   // subtle border
        'ncasa-border2':   '#2a3248',   // slightly brighter border for hover

        // Text
        'ncasa-text':      '#e2e8f0',   // primary text
        'ncasa-muted':     '#64748b',   // secondary / muted text
        'ncasa-subtle':    '#94a3b8',   // tertiary / label text

        // Accent (primary action / brand)
        'ncasa-accent':    '#2563eb',   // blue-600
        'ncasa-accent-h':  '#1d4ed8',   // blue-700 hover
        'ncasa-accent-l':  '#1e3a8a',   // blue-900 subtle bg

        // Severity
        'sev-critical':    '#dc2626',   // red-600
        'sev-critical-bg': '#1c0a0a',
        'sev-high':        '#ea580c',   // orange-600
        'sev-high-bg':     '#1c0d07',
        'sev-medium':      '#ca8a04',   // yellow-600
        'sev-medium-bg':   '#1a1505',
        'sev-low':         '#2563eb',   // blue-600 (informational)
        'sev-low-bg':      '#0d1526',

        // Status
        'status-pass':     '#16a34a',   // green-600
        'status-pass-bg':  '#0a1a0f',
        'status-fail':     '#dc2626',
        'status-warn':     '#ca8a04',
        'status-info':     '#0891b2',   // cyan-600
        'status-neutral':  '#475569',
      },
      fontFamily: {
        sans: ['Inter', 'Segoe UI', 'system-ui', 'sans-serif'],
        mono: ['Consolas', 'JetBrains Mono', 'Menlo', 'monospace'],
      },
      borderRadius: {
        DEFAULT: '6px',
      },
    },
  },
  plugins: [],
}
