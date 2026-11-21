const labels = {
  ALLOW: "Allowed",
  BLOCK: "Blocked",
  REDACT: "Redacted",
  REQUIRE_APPROVAL: "Approval",
};

export default function StatusBadge({ decision }) {
  return (
    <span className={`status-badge status-${String(decision).toLowerCase()}`}>
      <span className="status-dot" />
      {labels[decision] || decision}
    </span>
  );
}
