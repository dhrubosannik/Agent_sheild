import EventTable from "../components/EventTable";

export default function Threats({ events, onSelectEvent }) {
  const blocked = events.filter((event) => event.decision === "BLOCK");
  const signals = events.filter((event) => (event.risk_signals || []).length > 0);
  const protectedAttempts = blocked.filter((event) => (event.data_labels || []).includes("PROTECTED"));
  const unapproved = blocked.filter((event) => event.destination_class === "UNAPPROVED");

  return (
    <div className="page-stack">
      <section className="threat-summary">
        <article><span>Blocked actions</span><strong>{blocked.length}</strong></article>
        <article><span>Heuristic risk signals</span><strong>{signals.length}</strong></article>
        <article><span>Protected-data attempts</span><strong>{protectedAttempts.length}</strong></article>
        <article><span>Unapproved destinations</span><strong>{unapproved.length}</strong></article>
      </section>
      <article className="panel">
        <div className="panel-heading">
          <div><p>Policy and heuristic findings</p><h2>High-risk events</h2></div>
        </div>
        {blocked.length || signals.length ? (
          <EventTable
            events={events.filter((event) => event.decision === "BLOCK" || (event.risk_signals || []).length)}
            onSelect={onSelectEvent}
          />
        ) : (
          <div className="empty-state">No blocked actions or heuristic risk signals are present in retrieved events.</div>
        )}
      </article>
    </div>
  );
}
