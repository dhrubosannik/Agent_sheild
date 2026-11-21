import { Moon, Sun } from "lucide-react";

export default function Topbar({ connected, loading, onRefresh, theme, onToggleTheme }) {
  return (
    <header className="topbar">
      <div className="topbar-brand">
        <strong>AGENTSHTIELD</strong>
        <span>// POLICY GATEWAY</span>
      </div>
      <div className="topbar-meta">
        <span>ENV: PROD-SANDBOX</span>
        <i />
        <span>TRACK: CYBER / AI SECURITY</span>
        <i />
        <span>TEAM: HAXTHON</span>
      </div>
      <div className="topbar-controls">
        <button type="button" className="theme-toggle" onClick={onToggleTheme} title={`Switch to ${theme === "light" ? "dark" : "light"} theme`}>
          {theme === "light" ? <Moon size={12} /> : <Sun size={12} />}
          <span>{theme === "light" ? "DARK" : "LIGHT"}</span>
        </button>
        <button type="button" className={`enforcement-status ${connected ? "online" : "offline"}`} onClick={onRefresh} disabled={loading}>
          <b />
          <span>{connected ? "ENFORCEMENT: ACTIVE" : "ENFORCEMENT: OFFLINE"}</span>
        </button>
      </div>
    </header>
  );
}
