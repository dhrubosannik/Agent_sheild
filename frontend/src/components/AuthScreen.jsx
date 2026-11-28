import { useEffect, useState } from "react";
import {
  confirmEmailVerification,
  loginWithEmail,
  logoutFirebase,
  registerWithEmail,
  resetPassword,
  sendVerificationEmail,
} from "../firebase/auth";

export const MESSAGES = {
  notVerified:
    "Your email address has not been verified yet. Open the verification link we emailed you, or resend it below.",
  verificationSent: "A verification email has been sent to your registered email address.",
  verificationSendFailed:
    "Your account was created, but the verification email could not be sent. Use \"Resend Verification Email\".",
  stillUnverified: "Your email is not verified yet. Please check your inbox and click the verification link.",
  staleToken:
    "Your email is verified, but your session could not be refreshed. Sign out and sign in again to continue.",
  noSession: "Your session has expired. Please sign in again.",
  verified: "Email verified successfully! Loading your workspace...",
};

export default function AuthScreen({ user: initialUser = null, onVerified = null }) {
  const [currentUser, setCurrentUser] = useState(initialUser);
  const [mode, setMode] = useState(() => (initialUser && !initialUser.emailVerified ? "verify" : "login"));
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState(
    initialUser && !initialUser.emailVerified ? MESSAGES.notVerified : ""
  );
  const [messageType, setMessageType] = useState("info");
  const [busy, setBusy] = useState(false);
  const [resendCooldown, setResendCooldown] = useState(0);

  useEffect(() => {
    if (initialUser) {
      setCurrentUser(initialUser);
      if (!initialUser.emailVerified) {
        setMode("verify");
      }
    }
  }, [initialUser]);

  useEffect(() => {
    if (resendCooldown <= 0) return undefined;
    const timer = window.setInterval(() => {
      setResendCooldown((prev) => (prev > 0 ? prev - 1 : 0));
    }, 1000);
    return () => window.clearInterval(timer);
  }, [resendCooldown]);

  function formatFirebaseError(error) {
    if (!error) return "An unexpected error occurred.";
    const code = error.code || "";
    if (code === "auth/too-many-requests") {
      return "Too many requests. Please wait a few moments before trying again.";
    }
    if (code === "auth/user-token-expired" || code === "auth/invalid-user-token") {
      return "Your session has expired. Please sign in again.";
    }
    if (code === "auth/email-already-in-use") {
      return "This email is already registered. Please sign in instead.";
    }
    if (code === "auth/invalid-credential" || code === "auth/wrong-password" || code === "auth/user-not-found") {
      return "Invalid email or password.";
    }
    if (code === "auth/weak-password") {
      return "Password is too weak. Please use at least 6 characters.";
    }
    return error.message || "Operation failed.";
  }

  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setMessage("");
    setMessageType("info");

    try {
      if (mode === "reset") {
        await resetPassword(email);
        setMessage("Password reset email sent. Please check your inbox.");
        setMessageType("success");
      } else if (mode === "register") {
        const registration = await registerWithEmail(email, password);
        setCurrentUser(registration.user);
        setMode("verify");
        if (registration.verificationEmailSent) {
          setMessage(MESSAGES.verificationSent);
          setMessageType("success");
          setResendCooldown(30);
        } else {
          setMessage(MESSAGES.verificationSendFailed);
          setMessageType("error");
        }
      } else {
        const credential = await loginWithEmail(email, password);
        setCurrentUser(credential.user);
        if (!credential.user.emailVerified) {
          // Signing in does not send an email; say so accurately.
          setMode("verify");
          setMessage(MESSAGES.notVerified);
          setMessageType("info");
        } else if (onVerified) {
          onVerified(credential.user);
        }
      }
    } catch (error) {
      setMessage(formatFirebaseError(error));
      setMessageType("error");
    } finally {
      setBusy(false);
    }
  }

  async function handleCheckVerification() {
    setBusy(true);
    setMessage("");
    setMessageType("info");
    try {
      // Reloads the user, then force-refreshes the ID token so API requests
      // carry email_verified=true. Never assumes verification on failure.
      const outcome = await confirmEmailVerification();
      setCurrentUser(outcome.user);
      if (outcome.verified) {
        setMessage(MESSAGES.verified);
        setMessageType("success");
        if (onVerified) {
          onVerified(outcome.user);
        }
      } else {
        const text =
          outcome.reason === "STALE_TOKEN"
            ? MESSAGES.staleToken
            : outcome.reason === "NO_SESSION"
              ? MESSAGES.noSession
              : MESSAGES.stillUnverified;
        setMessage(text);
        setMessageType("error");
      }
    } catch (error) {
      setMessage(formatFirebaseError(error));
      setMessageType("error");
    } finally {
      setBusy(false);
    }
  }

  async function handleResendVerification() {
    if (resendCooldown > 0 || busy) return;
    setBusy(true);
    setMessage("");
    try {
      await sendVerificationEmail(currentUser);
      setMessage(MESSAGES.verificationSent);
      setMessageType("success");
      setResendCooldown(30);
    } catch (error) {
      setMessage(formatFirebaseError(error));
      setMessageType("error");
    } finally {
      setBusy(false);
    }
  }

  async function handleSignOut() {
    setBusy(true);
    try {
      await logoutFirebase();
      setCurrentUser(null);
      setMode("login");
      setMessage("");
    } catch (error) {
      setMessage(formatFirebaseError(error));
    } finally {
      setBusy(false);
    }
  }

  const activeEmail = currentUser?.email || email;

  return (
    <main className="auth-screen">
      <section className="auth-card">
        <div className="auth-brand">
          <strong>AGENTSHIELD</strong>
          <span>// SECURE WORKSPACE</span>
        </div>

        <h1>
          {mode === "verify"
            ? "Verify your email"
            : mode === "register"
            ? "Create account"
            : mode === "reset"
            ? "Reset password"
            : "Sign in"}
        </h1>

        {mode === "verify" ? (
          <div className="verify-flow">
            <p className="auth-email-badge">
              Registered email: <strong>{activeEmail}</strong>
            </p>
            {message && <p className={`auth-message ${messageType}`}>{message}</p>}
            <div className="auth-actions">
              <button
                type="button"
                className="button primary"
                onClick={handleCheckVerification}
                disabled={busy}
              >
                {busy ? "Checking status..." : "I've Verified My Email"}
              </button>
              <button
                type="button"
                className="button"
                onClick={handleResendVerification}
                disabled={busy || resendCooldown > 0}
              >
                {resendCooldown > 0
                  ? `Resend available in ${resendCooldown}s`
                  : "Resend Verification Email"}
              </button>
            </div>
            <div className="auth-links">
              <button type="button" onClick={handleSignOut} disabled={busy}>
                Sign in with another account
              </button>
            </div>
          </div>
        ) : (
          <form onSubmit={submit}>
            <label>
              Email
              <input
                type="email"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                required
              />
            </label>
            {mode !== "reset" && (
              <label>
                Password
                <input
                  type="password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  required
                  minLength={6}
                />
              </label>
            )}
            {message && <p className={`auth-message ${messageType}`}>{message}</p>}
            <button type="submit" className="button primary" disabled={busy}>
              {busy
                ? "Please wait..."
                : mode === "register"
                ? "Register"
                : mode === "reset"
                ? "Send reset email"
                : "Sign in"}
            </button>
            <div className="auth-links">
              {mode !== "login" && (
                <button type="button" onClick={() => { setMode("login"); setMessage(""); }}>
                  Sign in
                </button>
              )}
              {mode !== "register" && (
                <button type="button" onClick={() => { setMode("register"); setMessage(""); }}>
                  Register
                </button>
              )}
              {mode !== "reset" && (
                <button type="button" onClick={() => { setMode("reset"); setMessage(""); }}>
                  Reset password
                </button>
              )}
            </div>
          </form>
        )}
      </section>
    </main>
  );
}
