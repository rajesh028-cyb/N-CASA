import React from 'react';

/**
 * Table — reusable table shell.
 * Usage:
 *   <Table headers={['Name', 'Status']}>
 *     <tr><td>...</td></tr>
 *   </Table>
 */
export function Table({ headers = [], children, className = '' }) {
  return (
    <div className={`overflow-x-auto rounded border border-ncasa-border ${className}`}>
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-ncasa-border bg-ncasa-surface2">
            {headers.map((h) => (
              <th
                key={h}
                className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-ncasa-muted whitespace-nowrap"
              >
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-ncasa-border">{children}</tbody>
      </table>
    </div>
  );
}

/**
 * Td — styled table cell.
 */
export function Td({ children, className = '' }) {
  return (
    <td className={`px-4 py-3 text-ncasa-text whitespace-nowrap ${className}`}>
      {children}
    </td>
  );
}

/**
 * Tr — styled table row.
 */
export function Tr({ children, onClick, className = '' }) {
  return (
    <tr
      onClick={onClick}
      className={`bg-ncasa-surface transition-colors duration-100 hover:bg-ncasa-surface2 ${onClick ? 'cursor-pointer' : ''} ${className}`}
    >
      {children}
    </tr>
  );
}
