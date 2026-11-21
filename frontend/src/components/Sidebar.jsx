import {
  Activity,
  ChevronLeft,
  Gauge,
  History,
  KeyRound,
  Settings,
  ShieldCheck,
  Siren,
  TerminalSquare,
  UserCheck,
} from "lucide-react";

const navigation = [
  { id: "overview", label: "Overview", icon: Gauge },
  { id: "events", label: "Security Events", icon: History },
  { id: "threats", label: "Threat Monitoring", icon: Siren },
  { id: "tools", label: "Tool Activity", icon: TerminalSquare },
  { id: "approvals", label: "Approvals", icon: UserCheck },
  { id: "policies", label: "Policies", icon: KeyRound },
  { id: "demo", label: "Demo Scenarios", icon: Activity },
  { id: "settings", label: "Settings", icon: Settings },
];

export default function Sidebar({ activePage, onNavigate, collapsed, onCollapse }) {
  return (
    <aside className={`sidebar ${collapsed ? "collapsed" : ""}`}>
      <div className="brand">
        <div className="brand-mark"><ShieldCheck size={21} /></div>
        {!collapsed && (
          <div>
            <strong>AgentShield</strong>
            <span>Security operations</span>
          </div>
        )}
      </div>

      <nav className="sidebar-nav" aria-label="Primary navigation">
        {!collapsed && <div className="nav-label">Monitor</div>}
        {navigation.slice(0, 5).map(({ id, label, icon: Icon }) => (
          <button key={id} type="button" className={activePage === id ? "active" : ""} onClick={() => onNavigate(id)} title={collapsed ? label : undefined}>
            <Icon size={17} /><span>{!collapsed && label}</span>
          </button>
        ))}
        {!collapsed && <div className="nav-label nav-label-secondary">Configure</div>}
        {navigation.slice(5).map(({ id, label, icon: Icon }) => (
          <button key={id} type="button" className={activePage === id ? "active" : ""} onClick={() => onNavigate(id)} title={collapsed ? label : undefined}>
            <Icon size={17} /><span>{!collapsed && label}</span>
          </button>
        ))}
      </nav>

      {!collapsed && (
        <div className="sidebar-context">
          <span>Workspace</span>
          <strong>Local demo</strong>
        </div>
      )}
      <button type="button" className="collapse-button" onClick={onCollapse} aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}>
        <ChevronLeft size={16} className={collapsed ? "rotated" : ""} />
        {!collapsed && <span>Collapse</span>}
      </button>
    </aside>
  );
}
