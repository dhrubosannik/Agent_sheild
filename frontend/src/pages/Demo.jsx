import { Activity, AlertTriangle, Ban, CheckCircle2, Filter } from "lucide-react";

const scenarios = [
  { id: "safe", title: "Safe Scenario", description: "Send a benign vendor summary to an approved destination.", icon: CheckCircle2 },
  { id: "malicious", title: "Malicious Scenario", description: "Attempt exfiltration of a synthetic protected canary.", icon: Ban },
  { id: "redaction", title: "Redaction Scenario", description: "Replace a protected value before the mock tool executes.", icon: Filter },
  { id: "approval", title: "Approval Scenario", description: "Create review records and demonstrate approve/reject states.", icon: AlertTriangle },
];

export default function Demo({ onRun, running, lastRun }) {
  return (
    <div className="page-stack">
      <article className="demo-banner">
        <div className="demo-icon"><Activity size={20} /></div>
        <div>
          <p>Offline simulation</p>
          <h2>AgentShield scenario laboratory</h2>
          <span>Runs actual SDK, policy, mock-tool, and audit components. No external email or network calls.</span>
        </div>
      </article>

      {lastRun && (
        <article className="run-result">
          <span>Last execution</span>
          {lastRun.results.map((result) => (
            <div key={result.event_id}>
              <code>{result.tool_name}</code>
              <strong>{result.decision}</strong>
              <span>{result.execution_status}</span>
            </div>
          ))}
        </article>
      )}

      <section className="demo-grid">
        {scenarios.map(({ id, title, description, icon: Icon }) => (
          <article className="demo-card" key={id}>
            <div className={`demo-card-icon demo-${id}`}><Icon size={20} /></div>
            <h3>{title}</h3>
            <p>{description}</p>
            <button type="button" className="button primary" disabled={running !== null} onClick={() => onRun(id)}>
              {running === id ? "Running..." : `Run ${title.replace(" Scenario", "")}`}
            </button>
          </article>
        ))}
      </section>

      <article className="panel demo-all">
        <div>
          <p>Complete verification</p>
          <h2>Run all scenarios</h2>
        </div>
        <button type="button" className="button primary" disabled={running !== null} onClick={() => onRun("all")}>
          {running === "all" ? "Running all..." : "Run all scenarios"}
        </button>
      </article>
    </div>
  );
}
