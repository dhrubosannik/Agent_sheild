export default function Settings({ health }) {
  return (
    <article className="panel">
      <div className="panel-heading">
        <div><p>Runtime</p><h2>System status</h2></div>
      </div>
      <dl className="settings-list">
        <div><dt>Application</dt><dd>{health?.name || "Unavailable"}</dd></div>
        <div><dt>Status</dt><dd>{health?.status || "Unavailable"}</dd></div>
        <div><dt>Version</dt><dd>{health?.version || "Unavailable"}</dd></div>
        <div><dt>API base</dt><dd>{import.meta.env.VITE_API_BASE_URL || "Same-origin / Vite proxy"}</dd></div>
      </dl>
    </article>
  );
}
