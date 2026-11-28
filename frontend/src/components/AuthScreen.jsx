import { useEffect, useState } from "react";
import {
  loginWithEmail,
  logoutFirebase,
  registerWithEmail,
  reloadCurrentUser,
  resetPassword,
  sendVerificationEmail,
} from "../firebase/auth";

export default function AuthScreen({ user: initialUser = null, onVerified = null }) {
  const [currentUser, setCurrentUser] = useState(initialUser);
  const [mode, setMode] = useState(() => (initialUser && !initialUser.emailVerified ? "verify" : "login"));
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState(
    initialUser && !initialUser.emailVerified
      ? "A verification email has been sent to your registered email address."
      : ""
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
        const credential = await registerWithEmail(email, password);
        setCurrentUser(credential.user);
        setMode("verify");
        setMessage("A verification email has been sent to your registered email address.");
        setMessageType("success");
        setResendCooldown(30);
      } else {
        const credential = await loginWithEmail(email, password);
        setCurrentUser(credential.user);
        if (!credential.user.emailVerified) {
          setMode("verify");
          setMessage("A verification email has been sent to your registered email address.");
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
      const refreshedUser = await reloadCurrentUser();
      setCurrentUser(refreshedUser);
      if (refreshedUser?.emailVerified) {
        setMessage("Email verified successfully! Loading your workspace...");
        setMessageType("success");
        if (onVerified) {
          onVerified(refreshedUser);
        }
      } else {
        setMessage("Your email is not verified yet. Please check your inbox and click the verification link.");
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
      setMessage("A verification email has been sent to your registered email address.");
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
