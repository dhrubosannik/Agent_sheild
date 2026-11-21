import { Check, X } from "lucide-react";
import { formatTimestamp } from "../components/EventTable";

export default function Approvals({ approvals, onDecision, busyId }) {
  if (!approvals.length) {
    return <article className="panel"><div className="empty-state">No pending approval records.</div></article>;
  }

  return (
    <article className="panel">
      <div className="panel-heading">
        <div><p>Human review</p><h2>Pending approvals</h2></div>
        <span className="count-pill">{approvals.length}</span>
      </div>
      <div className="approval-list">
        {approvals.map((approval) => (
          <div className="approval-row" key={approval.approval_id}>
            <div className="approval-primary">
              <code>{approval.approval_id}</code>
              <strong>{approval.tool_name}</strong>
              <span>{approval.requested_action}</span>
            </div>
            <div className="approval-meta">
              <span><small>Event</small><code>{approval.event_id}</code></span>
              <span><small>Destination</small>{approval.destination_class}</span>
              <span><small>Created</small>{formatTimestamp(approval.created_at)}</span>
            </div>
            {approval.status === "PENDING" && (
              <div className="approval-actions">
                <button type="button" className="button approve" disabled={busyId === approval.approval_id} onClick={() => onDecision(approval, "APPROVED")}>
                  <Check size={15} /> Approve
                </button>
                <button type="button" className="button reject" disabled={busyId === approval.approval_id} onClick={() => onDecision(approval, "REJECTED")}>
                  <X size={15} /> Reject
                </button>
              </div>
            )}
          </div>
        ))}
      </div>
    </article>
  );
}
