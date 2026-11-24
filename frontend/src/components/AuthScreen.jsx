import { useState } from "react";
import { loginWithEmail, registerWithEmail, resetPassword } from "../firebase/auth";

export default function AuthScreen() {
  const [mode, setMode] = useState("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setMessage("");
    try {
      if (mode === "reset") {
        await resetPassword(email);
        setMessage("Password reset email sent.");
      } else if (mode === "register") {
        await registerWithEmail(email, password);
      } else {
        await loginWithEmail(email, password);
      }
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Authentication failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="auth-screen">
      <section className="auth-card">
        <div className="auth-brand">
          <strong>AGENTSHTIELD</strong>
          <span>// SECURE WORKSPACE</span>
        </div>
        <h1>{mode === "register" ? "Create account" : mode === "reset" ? "Reset password" : "Sign in"}</h1>
        <form onSubmit={submit}>
          <label>
            Email
            <input type="email" value={email} onChange={(event) => setEmail(event.target.value)} required />
          </label>
          {mode !== "reset" && (
            <label>
              Password
              <input type="password" value={password} onChange={(event) => setPassword(event.target.value)} required minLength={6} />
            </label>
          )}
          {message && <p className="auth-message">{message}</p>}
          <button type="submit" className="button primary" disabled={busy}>
            {busy ? "Please wait..." : mode === "register" ? "Register" : mode === "reset" ? "Send reset email" : "Sign in"}
          </button>
        </form>
        <div className="auth-links">
          {mode !== "login" && <button type="button" onClick={() => setMode("login")}>Sign in</button>}
          {mode !== "register" && <button type="button" onClick={() => setMode("register")}>Register</button>}
          {mode !== "reset" && <button type="button" onClick={() => setMode("reset")}>Reset password</button>}
        </div>
      </section>
    </main>
  );
}
