export default function Tools({ events }) {
  const tools = Object.values(events.reduce((result, event) => {
    const item = result[event.tool_name] || {
      name: event.tool_name,
      total: 0,
      ALLOW: 0,
      BLOCK: 0,
      REDACT: 0,
      REQUIRE_APPROVAL: 0,
    };
    item.total += 1;
    item[event.decision] = (item[event.decision] || 0) + 1;
    result[event.tool_name] = item;
    return result;
  }, {}));

  return (
    <article className="panel">
      <div className="panel-heading">
        <div><p>Observed tools</p><h2>Tool activity</h2></div>
        <span className="count-pill">{tools.length}</span>
      </div>
      {tools.length ? (
        <div className="tool-grid">
          {tools.sort((a, b) => b.total - a.total).map((tool) => (
            <article className="tool-card" key={tool.name}>
              <div><code>{tool.name}</code><strong>{tool.total} calls</strong></div>
              <dl>
                <div><dt>Allowed</dt><dd>{tool.ALLOW || 0}</dd></div>
                <div><dt>Blocked</dt><dd>{tool.BLOCK || 0}</dd></div>
                <div><dt>Redacted</dt><dd>{tool.REDACT || 0}</dd></div>
                <div><dt>Approval</dt><dd>{tool.REQUIRE_APPROVAL || 0}</dd></div>
              </dl>
            </article>
          ))}
        </div>
      ) : (
        <div className="empty-state">No tool activity is available from retrieved events.</div>
      )}
    </article>
  );
}
