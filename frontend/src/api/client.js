import { getCurrentIdToken } from "../firebase/auth";

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");
const DEV_IDENTITY = import.meta.env.VITE_DEV_IDENTITY || "";
const EMAIL_VERIFICATION_DETAIL = "Email verification is required";

/**
 * Builds the API request function.
 *
 * - Sends the current Firebase ID token. Firebase returns its cached token,
 *   which is the force-refreshed one once confirmEmailVerification() ran.
 * - If the backend still answers 403 "Email verification is required" (for
 *   example the email was verified in another tab and this tab's token is
 *   stale), the token is force-refreshed once and the request retried.
 * - Without Firebase (local development), sends the configured development
 *   identity header instead.
 */
export function createRequest({
  fetchImpl = (...args) => fetch(...args),
  getToken = getCurrentIdToken,
  baseUrl = API_BASE_URL,
  devIdentity = DEV_IDENTITY,
  timeoutMs = 10000,
} = {}) {
  async function request(path, options = {}, attempt = 0) {
    const controller = new AbortController();
    const timeoutId = globalThis.setTimeout(() => controller.abort(), timeoutMs);
    try {
      const idToken = await getToken(attempt > 0);
      const authHeaders = idToken
        ? { Authorization: `Bearer ${idToken}` }
        : devIdentity
          ? { "X-AgentShield-Dev-User": devIdentity }
          : {};
      const response = await fetchImpl(`${baseUrl}${path}`, {
        ...options,
        signal: controller.signal,
        headers: {
          "Content-Type": "application/json",
          ...authHeaders,
          ...(options.headers || {}),
        },
      });
      if (!response.ok) {
        let detail = `Request failed (${response.status})`;
        try {
          const body = await response.json();
          detail = body.detail || detail;
        } catch {
          // Keep the status-based message.
        }
        if (
          response.status === 403 &&
          idToken &&
          attempt === 0 &&
          String(detail).includes(EMAIL_VERIFICATION_DETAIL)
        ) {
          return request(path, options, attempt + 1);
        }
        const error = new Error(detail);
        error.status = response.status;
        throw error;
      }
      return response.json();
    } finally {
      globalThis.clearTimeout(timeoutId);
    }
  }
  return request;
}

const request = createRequest();

export const api = {
  getHealth: () => request("/health"),
  getEvents: (params = {}) => {
    const query = new URLSearchParams(params).toString();
    return request(`/api/v1/events${query ? `?${query}` : ""}`);
  },
  getEvent: (eventId) => request(`/api/v1/events/${encodeURIComponent(eventId)}`),
  getApprovals: (params = {}) => {
    const query = new URLSearchParams(params).toString();
    return request(`/api/v1/approvals${query ? `?${query}` : ""}`);
  },
  // The backend records the authenticated identity as reviewer.
  decideApproval: (approvalId, decision) =>
    request(`/api/v1/approvals/${encodeURIComponent(approvalId)}/decision`, {
      method: "POST",
      body: JSON.stringify({ decision }),
    }),
  getPolicy: () => request("/api/v1/policies/current"),
  runDemo: (scenario) =>
    request(`/api/v1/demo/run/${encodeURIComponent(scenario)}`, { method: "POST" }),
};
