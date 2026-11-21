import { useMemo, useState } from "react";
import { Search } from "lucide-react";
import EventTable from "../components/EventTable";

export default function Events({ events, onSelectEvent }) {
  const [search, setSearch] = useState("");
  const [decision, setDecision] = useState("");
  const [destination, setDestination] = useState("");

  const filtered = useMemo(() => events
    .filter((event) => {
      const needle = search.trim().toLowerCase();
      return !needle || event.event_id.toLowerCase().includes(needle) || event.tool_name.toLowerCase().includes(needle);
    })
    .filter((event) => !decision || event.decision === decision)
    .filter((event) => !destination || event.destination_class === destination)
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)), [events, search, decision, destination]);

  return (
    <article className="panel">
      <div className="panel-heading">
        <div><p>Audit stream</p><h2>Security events</h2></div>
        <span className="count-pill">{filtered.length}</span>
      </div>
      <div className="filters">
        <label className="search-field">
          <Search size={16} />
          <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search event or tool" />
        </label>
        <select value={decision} onChange={(event) => setDecision(event.target.value)}>
          <option value="">All decisions</option>
          <option value="ALLOW">ALLOW</option>
          <option value="BLOCK">BLOCK</option>
          <option value="REDACT">REDACT</option>
          <option value="REQUIRE_APPROVAL">REQUIRE_APPROVAL</option>
        </select>
        <select value={destination} onChange={(event) => setDestination(event.target.value)}>
          <option value="">All destinations</option>
          <option value="APPROVED">APPROVED</option>
          <option value="UNAPPROVED">UNAPPROVED</option>
          <option value="INTERNAL">INTERNAL</option>
          <option value="UNKNOWN">UNKNOWN</option>
        </select>
      </div>
      <EventTable events={filtered} onSelect={onSelectEvent} />
    </article>
  );
}
