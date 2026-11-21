export default function Policies({ policy }) {
  if (!policy) return <div className="empty-state">Policy configuration is unavailable.</div>;

  return (
    <div className="page-stack">
      <section className="policy-summary">
        <article><span>Policy version</span><strong>{policy.version}</strong></article>
        <article><span>Approved domains</span><strong>{policy.approved_domains.length}</strong></article>
        <article><span>Security rules</span><strong>{policy.rules.length}</strong></article>
      </section>
      <article className="panel">
        <div className="panel-heading">
          <div><p>Trust configuration</p><h2>Approved domains</h2></div>
        </div>
        <div className="domain-list">
          {policy.approved_domains.map((domain) => <code key={domain}>{domain}</code>)}
        </div>
      </article>
      <article className="panel">
        <div className="panel-heading">
          <div><p>Deterministic enforcement</p><h2>Security rules</h2></div>
        </div>
        <div className="policy-rules">
          {policy.rules.map((rule) => (
            <div className="policy-rule" key={rule.id}>
              <div><code>{rule.id}</code><span className={`rule-decision decision-${rule.decision.toLowerCase()}`}>{rule.decision}</span></div>
              <p>{rule.description}</p>
              <dl>
                <div><dt>Tools</dt><dd>{rule.tools.join(", ") || "All"}</dd></div>
                <div><dt>Data labels</dt><dd>{rule.data_labels.join(", ") || "None"}</dd></div>
                <div><dt>Destinations</dt><dd>{rule.destination_classes.join(", ") || "All"}</dd></div>
              </dl>
            </div>
          ))}
        </div>
      </article>
    </div>
  );
}
