/**
 * N-CASA Audit API Functions
 * ============================
 * Wraps all audit-related API calls.
 *
 * These functions map 1-to-1 with backend endpoints:
 *   uploadAudit  → POST /api/audits
 *   getAudit     → GET  /api/audits/{audit_id}
 *   getAudits    → GET  /api/audits
 *
 * Block 2: upload + retrieval.
 * Block 3+: add triggerIngestion(), getAuditStatus(), etc.
 */

import { request } from "./client";

/**
 * Upload a configuration file and start a new audit.
 *
 * @param {File} file              - The configuration file object
 * @param {string} frameworkValue  - Backend framework value: "CIS" | "NIST" | "STIG"
 * @returns {Promise<AuditCreateResponse>}
 *
 * @typedef {Object} AuditCreateResponse
 * @property {string} audit_id
 * @property {string} filename
 * @property {string} framework
 * @property {string} status
 * @property {string} message
 */
export async function uploadAudit(file, frameworkValue) {
  const formData = new FormData();
  formData.append("file", file);
  formData.append("framework", frameworkValue);

  // Note: do NOT set Content-Type header manually — the browser sets it
  // automatically with the correct multipart boundary when using FormData.
  return request("/audits", {
    method: "POST",
    body: formData,
  });
}

/**
 * Retrieve a single audit by ID.
 *
 * @param {string} auditId
 * @returns {Promise<AuditDetailResponse>}
 *
 * @typedef {Object} AuditDetailResponse
 * @property {string} audit_id
 * @property {string} filename
 * @property {string} framework
 * @property {string} status
 * @property {string} created_at
 * @property {number} file_size
 * @property {string|null} vendor
 * @property {string|null} device
 * @property {number} findings
 */
export async function getAudit(auditId) {
  return request(`/audits/${encodeURIComponent(auditId)}`);
}

/**
 * Retrieve all audits or paginated audit history.
 *
 * @param {Object} [params] - Filter/pagination parameters: { page, page_size, status, framework }
 * @returns {Promise<AuditListResponse>}
 */
export async function getAudits(params = {}) {
  const queryParts = [];
  if (params.page) queryParts.push(`page=${encodeURIComponent(params.page)}`);
  if (params.page_size) queryParts.push(`page_size=${encodeURIComponent(params.page_size)}`);
  if (params.status) queryParts.push(`status=${encodeURIComponent(params.status)}`);
  if (params.framework) queryParts.push(`framework=${encodeURIComponent(params.framework)}`);
  const query = queryParts.length > 0 ? `?${queryParts.join("&")}` : "";
  return request(`/audits${query}`);
}

/**
 * Get configuration inventory for an audit.
 * @param {string} auditId
 */
export async function getAuditInventory(auditId) {
  return request(`/audits/${encodeURIComponent(auditId)}/inventory`);
}

/**
 * Trigger deterministic vendor & device type detection.
 * @param {string} auditId
 */
export async function triggerVendorDetection(auditId) {
  return request(`/audits/${encodeURIComponent(auditId)}/detect`, {
    method: "POST",
  });
}

/**
 * Get vendor detection results and evidence.
 * @param {string} auditId
 */
export async function getDetectionResults(auditId) {
  return request(`/audits/${encodeURIComponent(auditId)}/detection`);
}

/**
 * Trigger vendor configuration parsing for an audit.
 * @param {string} auditId
 */
export async function triggerConfigurationParsing(auditId) {
  return request(`/audits/${encodeURIComponent(auditId)}/parse`, {
    method: "POST",
  });
}

/**
 * Get configuration parsing summary for an audit.
 * @param {string} auditId
 */
export async function getParsingResults(auditId) {
  return request(`/audits/${encodeURIComponent(auditId)}/parsing`);
}

/**
 * Get parsed configuration for a single file.
 * @param {string} auditId
 * @param {string} fileId
 */
export async function getFileParsing(auditId, fileId) {
  return request(`/audits/${encodeURIComponent(auditId)}/parsing/${encodeURIComponent(fileId)}`);
}

/**
 * Trigger vendor-neutral configuration normalization for an audit.
 * @param {string} auditId
 */
export async function triggerConfigurationNormalization(auditId) {
  return request(`/audits/${encodeURIComponent(auditId)}/normalize`, {
    method: "POST",
  });
}

/**
 * Get configuration normalization summary for an audit.
 * @param {string} auditId
 */
export async function getNormalizationResults(auditId) {
  return request(`/audits/${encodeURIComponent(auditId)}/normalization`);
}

/**
 * Get normalized configuration detail and evidence for a single file.
 * @param {string} auditId
 * @param {string} fileId
 */
export async function getFileNormalization(auditId, fileId) {
  return request(`/audits/${encodeURIComponent(auditId)}/normalization/${encodeURIComponent(fileId)}`);
}

/**
 * Trigger deterministic compliance evaluation for an audit.
 * @param {string} auditId
 * @param {string} [framework] - Optional framework filter (CIS | NIST | STIG)
 */
export async function triggerComplianceEvaluation(auditId, framework) {
  const query = framework ? `?framework=${encodeURIComponent(framework)}` : "";
  return request(`/audits/${encodeURIComponent(auditId)}/compliance${query}`, {
    method: "POST",
  });
}

/**
 * Get compliance evaluation summary and results for an audit.
 * @param {string} auditId
 * @param {string} [framework] - Optional framework filter (CIS | NIST | STIG)
 */
export async function getComplianceResults(auditId, framework) {
  const query = framework ? `?framework=${encodeURIComponent(framework)}` : "";
  return request(`/audits/${encodeURIComponent(auditId)}/compliance${query}`);
}

/**
 * Get single compliance control result by control ID.
 * @param {string} auditId
 * @param {string} controlId
 */
export async function getComplianceControl(auditId, controlId) {
  return request(`/audits/${encodeURIComponent(auditId)}/compliance/${encodeURIComponent(controlId)}`);
}

/**
 * Trigger security findings extraction for an audit (Block 8).
 * @param {string} auditId
 */
export async function triggerFindingsGeneration(auditId) {
  return request(`/audits/${encodeURIComponent(auditId)}/findings`, {
    method: "POST",
  });
}

/**
 * Get security findings and assessment limitations for an audit (Block 8).
 * @param {string} auditId
 * @param {Object} [params] - Filter params: { severity, framework, status, category }
 */
export async function getAuditFindings(auditId, params = {}) {
  const queryParts = [];
  if (params.severity) queryParts.push(`severity=${encodeURIComponent(params.severity)}`);
  if (params.framework) queryParts.push(`framework=${encodeURIComponent(params.framework)}`);
  if (params.status) queryParts.push(`status_filter=${encodeURIComponent(params.status)}`);
  if (params.category) queryParts.push(`category=${encodeURIComponent(params.category)}`);
  const query = queryParts.length > 0 ? `?${queryParts.join("&")}` : "";
  return request(`/audits/${encodeURIComponent(auditId)}/findings${query}`);
}

/**
 * Get single detailed finding record by finding ID (Block 8).
 * @param {string} auditId
 * @param {string} findingId
 */
export async function getFindingDetail(auditId, findingId) {
  return request(`/audits/${encodeURIComponent(auditId)}/findings/${encodeURIComponent(findingId)}`);
}

/**
 * Get findings across all audits or latest completed audit (Block 8).
 * @param {Object} [params] - Filter params: { severity, framework, status, category }
 */
export async function getAllFindings(params = {}) {
  const queryParts = [];
  if (params.severity) queryParts.push(`severity=${encodeURIComponent(params.severity)}`);
  if (params.framework) queryParts.push(`framework=${encodeURIComponent(params.framework)}`);
  if (params.status) queryParts.push(`status_filter=${encodeURIComponent(params.status)}`);
  if (params.category) queryParts.push(`category=${encodeURIComponent(params.category)}`);
  const query = queryParts.length > 0 ? `?${queryParts.join("&")}` : "";
  return request(`/findings${query}`);
}

/**
 * Trigger vendor-specific remediation generation for an audit (Block 9).
 * @param {string} auditId
 */
export async function triggerRemediationGeneration(auditId) {
  return request(`/audits/${encodeURIComponent(auditId)}/remediation`, {
    method: "POST",
  });
}

/**
 * Get remediation proposals for an audit (Block 9).
 * @param {string} auditId
 * @param {Object} [params] - Filter params: { vendor, status, review_status }
 */
export async function getAuditRemediation(auditId, params = {}) {
  const queryParts = [];
  if (params.vendor) queryParts.push(`vendor=${encodeURIComponent(params.vendor)}`);
  if (params.status) queryParts.push(`status_filter=${encodeURIComponent(params.status)}`);
  if (params.review_status) queryParts.push(`review_status=${encodeURIComponent(params.review_status)}`);
  const query = queryParts.length > 0 ? `?${queryParts.join("&")}` : "";
  return request(`/audits/${encodeURIComponent(auditId)}/remediation${query}`);
}

/**
 * Get single detailed remediation record by remediation ID (Block 9).
 * @param {string} auditId
 * @param {string} remediationId
 */
export async function getRemediationDetail(auditId, remediationId) {
  return request(`/audits/${encodeURIComponent(auditId)}/remediation/${encodeURIComponent(remediationId)}`);
}

/**
 * Mark a remediation proposal as reviewed by an administrator (Block 9).
 * @param {string} auditId
 * @param {string} remediationId
 */
export async function reviewRemediation(auditId, remediationId) {
  return request(`/audits/${encodeURIComponent(auditId)}/remediation/${encodeURIComponent(remediationId)}/review`, {
    method: "POST",
  });
}

/**
 * Get remediation proposals across all audits (Block 9).
 * @param {Object} [params] - Filter params: { vendor, status, review_status }
 */
export async function getAllRemediation(params = {}) {
  const queryParts = [];
  if (params.vendor) queryParts.push(`vendor=${encodeURIComponent(params.vendor)}`);
  if (params.status) queryParts.push(`status_filter=${encodeURIComponent(params.status)}`);
  if (params.review_status) queryParts.push(`review_status=${encodeURIComponent(params.review_status)}`);
  const query = queryParts.length > 0 ? `?${queryParts.join("&")}` : "";
  return request(`/remediation${query}`);
}

/**
 * Trigger AI-assisted configuration understanding for unknown vendors (Block 10).
 * @param {string} auditId
 */
export async function triggerAiAnalysis(auditId) {
  return request(`/audits/${encodeURIComponent(auditId)}/ai/analyze`, {
    method: "POST",
  });
}

/**
 * Get AI configuration understanding summary for an audit (Block 10).
 * @param {string} auditId
 */
export async function getAiAnalysis(auditId) {
  return request(`/audits/${encodeURIComponent(auditId)}/ai-analysis`);
}

/**
 * Generate AI-assisted explanation for a security finding (Block 10).
 * @param {string} auditId
 * @param {string} findingId
 */
export async function explainFindingAi(auditId, findingId) {
  return request(`/audits/${encodeURIComponent(auditId)}/ai/explain/${encodeURIComponent(findingId)}`, {
    method: "POST",
  });
}



