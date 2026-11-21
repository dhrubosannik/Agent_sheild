import { useCallback, useEffect, useMemo, useState } from "react";
import { X } from "lucide-react";
import { api } from "./api/client";
import Sidebar from "./components/Sidebar";
import Topbar from "./components/Topbar";
import StatusBadge from "./components/StatusBadge";
import Overview from "./pages/Overview";
import Events from "./pages/Events";
import Threats from "./pages/Threats";
import Tools from "./pages/Tools";
import Approvals from "./pages/Approvals";
import Policies from "./pages/Policies";
import Demo from "./pages/Demo";
import Settings from "./pages/Settings";

const pageTitles = {
  overview: "Overview",
  events: "Security Events",
  threats: "Threat Monitoring",
  tools: "Tool Activity",
  approvals: "Approvals",
  policies: "Policies",
  demo: "Demo Scenarios",
  settings: "Settings",
};

export default function App() {
  const [activePage, setActivePage] = useState("overview");
  const [collapsed, setCollapsed] = useState(false);
  const [events, setEvents] = useState([]);
  const [approvals, setApprovals] = useState([]);
  const [policy, setPolicy] = useState(null);
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [busyApproval, setBusyApproval] = useState("");
  const [runningDemo, setRunningDemo] = useState(null);
  const [lastRun, setLastRun] = useState(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [healthResult, eventResult, approvalResult, policyResult] = await Promise.all([
        api.getHealth(),
        api.getEvents({ limit: 100 }),
        api.getApprovals({ limit: 100 }),
        api.getPolicy(),
      ]);
      setHealth(healthResult);
      setEvents(eventResult.items || []);
      setApprovals((approvalResult.items || []).filter((item) => item.status === "PENDING"));
      setPolicy(policyResult);
    } catch (err) {
      setHealth(null);
      setError(err.message || "Unable to retrieve dashboard data.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    if (!notice) return undefined;
    const timeout = window.setTimeout(() => setNotice(""), 4000);
    return () => window.clearTimeout(timeout);
  }, [notice]);

  const connected = Boolean(health);

  const handleApproval = async (approval, decision) => {
    const confirmed = window.confirm(`${decision === "APPROVED" ? "Approve" : "Reject"} ${approval.approval_id}?`);
    if (!confirmed) return;
    setBusyApproval(approval.approval_id);
    try {
      await api.decideApproval(approval.approval_id, decision, "demo-reviewer");
      setNotice(`Approval ${decision.toLowerCase()} successfully.`);
      await refresh();
    } catch (err) {
      setNotice(err.message || "Approval action failed.");
    } finally {
      setBusyApproval("");
    }
  };

  const handleDemo = async (scenario) => {
    setRunningDemo(scenario);
    setNotice("");
    try {
      const result = await api.runDemo(scenario);
      setLastRun(result);
      setNotice(`${scenario} scenario completed.`);
      await refresh();
    } catch (err) {
      setNotice(err.message || "Demo scenario failed.");
    } finally {
      setRunningDemo(null);
    }
  };

  const page = useMemo(() => {
    if (loading && !events.length) return <div className="loading-state">Loading security data...</div>;
    if (error) return <div className="error-state"><strong>Dashboard data unavailable</strong><span>{error}</span></div>;

    switch (activePage) {
      case "events":
        return <Events events={events} onSelectEvent={setSelectedEvent} />;
      case "threats":
        return <Threats events={events} onSelectEvent={setSelectedEvent} />;
      case "tools":
        return <Tools events={events} />;
      case "approvals":
        return <Approvals approvals={approvals} onDecision={handleApproval} busyId={busyApproval} />;
      case "policies":
        return <Policies policy={policy} />;
      case "demo":
        return <Demo onRun={handleDemo} running={runningDemo} lastRun={lastRun} />;
      case "settings":
        return <Settings health={health} />;
      default:
        return <Overview events={events} approvals={approvals} onSelectEvent={setSelectedEvent} />;
    }
  }, [activePage, approvals, busyApproval, error, events, health, loading, lastRun, policy, runningDemo]);

  return (
    <div className="app-shell">
      <Sidebar activePage={activePage} onNavigate={setActivePage} collapsed={collapsed} onCollapse={() => setCollapsed((value) => !value)} />
      <main className="main-area">
        <Topbar title={pageTitles[activePage]} connected={connected} loading={loading} onRefresh={refresh} />
        {notice && <div className="toast">{notice}</div>}
        <div className="content">{page}</div>
      </main>

      {selectedEvent && (
        <div className="drawer-backdrop" onMouseDown={() => setSelectedEvent(null)}>
          <aside className="event-drawer" onMouseDown={(event) => event.stopPropagation()}>
            <div className="drawer-heading">
              <div><p>Security inspection</p><h2>Event details</h2></div>
              <button type="button" className="icon-button" onClick={() => setSelectedEvent(null)}><X size={16} /></button>
            </div>
            <div className="drawer-status">
              <StatusBadge decision={selectedEvent.decision} />
              <code>{selectedEvent.event_id}</code>
            </div>
            <dl className="detail-grid">
              <div><dt>Timestamp</dt><dd>{selectedEvent.timestamp}</dd></div>
              <div><dt>Tool name</dt><dd><code>{selectedEvent.tool_name}</code></dd></div>
              <div><dt>Matched policy</dt><dd><code>{selectedEvent.policy_id}</code></dd></div>
              <div><dt>Destination</dt><dd>{selectedEvent.destination_class}</dd></div>
              <div><dt>Execution</dt><dd>{selectedEvent.execution_status}</dd></div>
              <div><dt>Payload fingerprint</dt><dd><code>{selectedEvent.payload_fingerprint || "Not available"}</code></dd></div>
            </dl>
            <section>
              <h3>Reason codes</h3>
              <div className="tag-list">{selectedEvent.reason_codes?.map((reason) => <code key={reason}>{reason}</code>)}</div>
            </section>
            <section>
              <h3>Detected data labels</h3>
              <div className="tag-list">{selectedEvent.data_labels?.length ? selectedEvent.data_labels.map((label) => <code key={label}>{label}</code>) : <span>None detected</span>}</div>
            </section>
            <section>
              <h3>Risk signals</h3>
              {selectedEvent.risk_signals?.length ? selectedEvent.risk_signals.map((signal) => (
                <div className="risk-row" key={typeof signal === "string" ? signal : signal.name}>
                  <code>{typeof signal === "string" ? signal : signal.name}</code>
                  {typeof signal !== "string" && <span>{signal.reason}</span>}
                </div>
              )) : <span className="muted">No heuristic risk signals recorded.</span>}
            </section>
          </aside>
        </div>
      )}
    </div>
  );
}
