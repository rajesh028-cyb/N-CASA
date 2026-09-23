/**
 * N-CASA Frontend API Client — Reports Module
 */

import { request } from "./client";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000/api";

/**
 * Generate a new security report snapshot for an audit.
 */
export async function generateReport(auditId) {
  return request(`/audits/${auditId}/reports`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  });
}

/**
 * Retrieve all reports generated for a specific audit.
 */
export async function fetchAuditReports(auditId) {
  return request(`/audits/${auditId}/reports`);
}

/**
 * Get direct HTML report viewing URL.
 */
export function getReportHtmlUrl(auditId, reportId) {
  return `${API_BASE_URL}/audits/${auditId}/reports/${reportId}/html`;
}

/**
 * Get direct PDF report download URL.
 */
export function getReportPdfUrl(auditId, reportId) {
  return `${API_BASE_URL}/audits/${auditId}/reports/${reportId}/pdf`;
}
