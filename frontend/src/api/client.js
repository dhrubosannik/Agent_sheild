const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");
import { getCurrentIdToken } from "../firebase/auth";

async function request(path, options = {}) {
  const controller = new AbortController();
  const timeoutId = window.setTimeout(() => controller.abort(), 10000);
  try {
    const idToken = await getCurrentIdToken();
    const authHeaders = idToken ? { Authorization: `Bearer ${idToken}` } : {};
    const response = await fetch(`${API_BASE_URL}${path}`, {
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
      throw new Error(detail);
    }
    return response.json();
  } finally {
    window.clearTimeout(timeoutId);
  }
}

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
  decideApproval: (approvalId, decision, reviewer) =>
    request(`/api/v1/approvals/${encodeURIComponent(approvalId)}/decision`, {
      method: "POST",
      body: JSON.stringify({ decision, reviewer }),
    }),
  getPolicy: () => request("/api/v1/policies/current"),
  runDemo: (scenario) =>
    request(`/api/v1/demo/run/${encodeURIComponent(scenario)}`, { method: "POST" }),
};
