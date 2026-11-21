import { ChevronRight } from "lucide-react";
import StatusBadge from "./StatusBadge";

export function formatTimestamp(value) {
  if (!value) return "Unknown";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export default function EventTable({ events, onSelect, compact = false }) {
  if (!events.length) {
    return <div className="empty-state">No security events match the current view.</div>;
  }

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Tool</th>
            <th>Decision</th>
            <th>Destination</th>
            {!compact && <th>Policy</th>}
            <th>Execution</th>
            <th aria-label="Details" />
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <tr key={event.event_id} onClick={() => onSelect(event)}>
              <td>{formatTimestamp(event.timestamp)}</td>
              <td><code>{event.tool_name}</code></td>
              <td><StatusBadge decision={event.decision} /></td>
              <td>{event.destination_class}</td>
              {!compact && <td><code>{event.policy_id}</code></td>}
              <td>{event.execution_status}</td>
              <td><ChevronRight size={16} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
