import { Ban, CheckCircle2, Filter, ShieldAlert, UserCheck } from "lucide-react";
import EventTable from "../components/EventTable";
import StatusBadge from "../components/StatusBadge";

export default function Overview({ events, approvals, onSelectEvent }) {
  const counts = events.reduce((result, event) => {
    result.total += 1;
    if (event.decision === "ALLOW") result.allow += 1;
    if (event.decision === "BLOCK") result.block += 1;
    if (event.decision === "REDACT") result.redact += 1;
    return result;
  }, { total: 0, allow: 0, block: 0, redact: 0 });

  const cards = [
    { label: "Total Tool Calls", value: counts.total, icon: ShieldAlert, tone: "neutral" },
    { label: "Allowed Actions", value: counts.allow, icon: CheckCircle2, tone: "green" },
    { label: "Blocked Actions", value: counts.block, icon: Ban, tone: "red" },
    { label: "Redacted Actions", value: counts.redact, icon: Filter, tone: "amber" },
    { label: "Pending Approvals", value: approvals.length, icon: UserCheck, tone: "blue" },
  ];

  const decisions = ["ALLOW", "BLOCK", "REDACT", "REQUIRE_APPROVAL"];
  const max = Math.max(1, ...decisions.map((decision) => events.filter((event) => event.decision === decision).length));

  return (
    <div className="page-stack">
      <section className="stat-grid">
        {cards.map(({ label, value, icon: Icon, tone }) => (
          <article className="stat-card" key={label}>
            <div className={`stat-icon ${tone}`}><Icon size={18} /></div>
            <div>
              <span>{label}</span>
              <strong>{value}</strong>
            </div>
          </article>
        ))}
      </section>

      <section className="grid-two">
        <article className="panel">
          <div className="panel-heading">
            <div><p>Security activity</p><h2>Decision volume</h2></div>
            <span className="panel-caption">Retrieved events</span>
          </div>
          <div className="bar-chart">
            {decisions.map((decision) => {
              const count = events.filter((event) => event.decision === decision).length;
              return (
                <div className="bar-row" key={decision}>
                  <StatusBadge decision={decision} />
                  <div className="bar-track">
                    <div className={`bar bar-${decision.toLowerCase()}`} style={{ width: `${(count / max) * 100}%` }} />
                  </div>
                  <strong>{count}</strong>
                </div>
              );
            })}
          </div>
        </article>

        <article className="panel">
          <div className="panel-heading">
            <div><p>Review queue</p><h2>Pending approvals</h2></div>
            <span className="count-pill">{approvals.length}</span>
          </div>
          {approvals.length ? (
            <div className="approval-preview">
              {approvals.slice(0, 4).map((approval) => (
                <div className="approval-preview-row" key={approval.approval_id}>
                  <div><code>{approval.tool_name}</code><span>{approval.requested_action}</span></div>
                  <StatusBadge decision="REQUIRE_APPROVAL" />
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state compact">No pending approvals.</div>
          )}
        </article>
      </section>

      <article className="panel">
        <div className="panel-heading">
          <div><p>Latest records</p><h2>Recent security events</h2></div>
        </div>
        <EventTable events={events.slice(0, 8)} onSelect={onSelectEvent} compact />
      </article>
    </div>
  );
}
