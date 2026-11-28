import { describe, expect, it, vi } from "vitest";
import { createRequest } from "./client";

function response(status, body) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

describe("API client token handling", () => {
  it("retries once with a force-refreshed token on a stale email-verification 403", async () => {
    const getToken = vi.fn(async (force) => (force ? "fresh-token" : "stale-token"));
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(response(403, { detail: "Email verification is required to access protected operations." }))
      .mockResolvedValueOnce(response(200, { items: [] }));
    const request = createRequest({ fetchImpl, getToken, baseUrl: "" });

    await expect(request("/api/v1/events")).resolves.toEqual({ items: [] });
    expect(getToken.mock.calls).toEqual([[false], [true]]);
    expect(fetchImpl.mock.calls[0][1].headers.Authorization).toBe("Bearer stale-token");
    expect(fetchImpl.mock.calls[1][1].headers.Authorization).toBe("Bearer fresh-token");
  });

  it("does not loop when the refreshed token is still rejected", async () => {
    const getToken = vi.fn(async () => "token");
    const fetchImpl = vi.fn(async () => response(403, { detail: "Email verification is required to access protected operations." }));
    const request = createRequest({ fetchImpl, getToken, baseUrl: "" });
    await expect(request("/x")).rejects.toMatchObject({ status: 403 });
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it("does not retry other 403 responses", async () => {
    const fetchImpl = vi.fn(async () => response(403, { detail: "Insufficient role permissions." }));
    const request = createRequest({ fetchImpl, getToken: async () => "t", baseUrl: "" });
    await expect(request("/x")).rejects.toThrow("Insufficient role permissions.");
    expect(fetchImpl).toHaveBeenCalledOnce();
  });

  it("sends the development identity header only when there is no Firebase token", async () => {
    const fetchImpl = vi.fn(async () => response(200, {}));
    await createRequest({ fetchImpl, getToken: async () => null, baseUrl: "", devIdentity: "local-admin" })("/x");
    expect(fetchImpl.mock.calls[0][1].headers["X-AgentShield-Dev-User"]).toBe("local-admin");
    await createRequest({ fetchImpl, getToken: async () => "t", baseUrl: "", devIdentity: "local-admin" })("/x");
    expect(fetchImpl.mock.calls[1][1].headers["X-AgentShield-Dev-User"]).toBeUndefined();
  });

  it("decision requests carry no client-supplied reviewer", async () => {
    vi.resetModules();
    const fetchSpy = vi.fn(async () => response(200, {}));
    vi.stubGlobal("fetch", fetchSpy);
    const { api } = await import("./client");
    await api.decideApproval("apr-1", "APPROVED");
    expect(JSON.parse(fetchSpy.mock.calls[0][1].body)).toEqual({ decision: "APPROVED" });
    vi.unstubAllGlobals();
  });
});
