/**
 * N-CASA API Client — Base layer
 * ================================
 * All API calls go through this module.
 *
 * Configuration:
 *   Set VITE_API_BASE_URL in the frontend/.env file.
 *   Default: http://localhost:8000/api
 *
 * Block 2: simple fetch wrapper.
 * Future blocks: add auth headers, refresh token logic, etc.
 */

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://localhost:8000/api";

/**
 * Generic request helper.
 *
 * @param {string} path   - API path relative to API_BASE_URL (e.g. "/audits")
 * @param {RequestInit} options - fetch options
 * @returns {Promise<any>} - parsed JSON response
 * @throws {ApiError} on non-2xx responses or network failures
 */
async function request(path, options = {}) {
  const url = `${API_BASE_URL}${path}`;

  let response;
  try {
    response = await fetch(url, options);
  } catch (networkError) {
    // Network failure (backend down, DNS, CORS preflight failed, etc.)
    throw new ApiError(
      0,
      "Backend unavailable. Please make sure the N-CASA API server is running.",
      null
    );
  }

  // Parse response body (JSON or text fallback)
  let body = null;
  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    body = await response.json();
  } else {
    body = await response.text();
  }

  if (!response.ok) {
    const detail =
      typeof body === "object" && body?.detail
        ? body.detail
        : `HTTP ${response.status}`;
    throw new ApiError(response.status, detail, body);
  }

  return body;
}

/**
 * Structured API error — always has .status and .message.
 * Never exposes raw Python stack traces.
 */
export class ApiError extends Error {
  constructor(status, message, raw) {
    super(message);
    this.name = "ApiError";
    this.status = status;   // HTTP status code (0 = network failure)
    this.raw = raw;         // Full response body for debugging
  }
}

/**
 * Fetch health status of the N-CASA backend API and database.
 * @returns {Promise<{ status: string, service: string, database: string }>}
 */
export async function getHealthStatus() {
  return request("/health");
}

export { request, API_BASE_URL };

