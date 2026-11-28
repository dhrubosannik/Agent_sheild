import { describe, expect, it } from "vitest";
import { renderToString } from "react-dom/server";
import AuthScreen, { MESSAGES } from "./AuthScreen";

describe("AuthScreen messages", () => {
  it("does not claim an email was sent when an unverified user returns", () => {
    const html = renderToString(<AuthScreen user={{ email: "u@example.org", emailVerified: false }} />);
    expect(html).toContain("Verify your email");
    expect(html).toContain("has not been verified yet");
    expect(html).not.toContain("has been sent");
  });

  it("keeps the sent message only for actual sends", () => {
    expect(MESSAGES.notVerified).not.toMatch(/sent/);
    expect(MESSAGES.verificationSent).toMatch(/sent/);
  });
});
