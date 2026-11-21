import { RefreshCw, Wifi, WifiOff } from "lucide-react";

export default function Topbar({ title, connected, loading, onRefresh }) {
  return (
    <header className="topbar">
      <div>
        <p className="eyebrow">AgentShield Console</p>
        <h1>{title}</h1>
      </div>
      <div className="topbar-actions">
        <span className={`connection ${connected ? "online" : "offline"}`}>
          {connected ? <Wifi size={14} /> : <WifiOff size={14} />}
          {connected ? "Backend connected" : "Backend unavailable"}
        </span>
        <button type="button" className="icon-button" onClick={onRefresh} disabled={loading} title="Refresh data">
          <RefreshCw size={16} className={loading ? "spinning" : ""} />
        </button>
        <div className="profile">
          <div className="avatar">AS</div>
          <div>
            <strong>Demo Reviewer</strong>
            <span>Security team</span>
          </div>
        </div>
      </div>
    </header>
  );
}
