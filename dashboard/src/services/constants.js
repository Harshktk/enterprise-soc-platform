// Shared constants matching the backend OCSF schema

export const SEVERITY = {
  0: { label: 'Unknown',       color: 'var(--text-3)',   bg: 'rgba(71,85,105,0.2)',  short: 'UNK' },
  1: { label: 'Info',          color: 'var(--cyan)',     bg: 'var(--cyan-dim)',      short: 'INFO' },
  2: { label: 'Low',           color: 'var(--green)',    bg: 'var(--green-dim)',     short: 'LOW' },
  3: { label: 'Medium',        color: 'var(--yellow)',   bg: 'var(--yellow-dim)',    short: 'MED' },
  4: { label: 'High',          color: 'var(--orange)',   bg: 'var(--orange-dim)',    short: 'HIGH' },
  5: { label: 'Critical',      color: 'var(--red)',      bg: 'var(--red-dim)',       short: 'CRIT' },
  6: { label: 'Fatal',         color: '#ff0000',         bg: 'rgba(255,0,0,0.15)',   short: 'FATAL' },
};

export const STATUS = {
  new:         { label: 'New',         color: 'var(--cyan)',   bg: 'var(--cyan-dim)' },
  in_progress: { label: 'In Progress', color: 'var(--yellow)', bg: 'var(--yellow-dim)' },
  resolved:    { label: 'Resolved',    color: 'var(--green)',  bg: 'var(--green-dim)' },
  suppressed:  { label: 'Suppressed',  color: 'var(--text-3)', bg: 'rgba(71,85,105,0.2)' },
  escalated:   { label: 'Escalated',   color: 'var(--red)',    bg: 'var(--red-dim)' },
};

export const SIEM_COLORS = {
  splunk:   '#ff6b35',
  qradar:   '#0f62fe',
  wazuh:    '#00b4d8',
  sentinel: '#7b2fff',
  elastic:  '#f04e98',
  default:  '#94a3b8',
};

export function getSiemColor(siem) {
  return SIEM_COLORS[siem?.toLowerCase()] || SIEM_COLORS.default;
}

export function getSeverity(level) {
  return SEVERITY[level] || SEVERITY[0];
}

export function getStatus(s) {
  return STATUS[s] || STATUS.new;
}

export function formatTs(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleTimeString('en-US', {
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
  });
}

export function formatDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

export function timeAgo(iso) {
  if (!iso) return '—';
  const secs = Math.floor((Date.now() - new Date(iso)) / 1000);
  if (secs < 60)  return `${secs}s ago`;
  if (secs < 3600) return `${Math.floor(secs/60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs/3600)}h ago`;
  return `${Math.floor(secs/86400)}d ago`;
}

// Generate mock alerts for demo when API is unreachable
export function generateMockAlert(i) {
  const siems = ['splunk', 'qradar', 'wazuh'];
  const titles = [
    'Brute Force Attack Detected',
    'Lateral Movement — Pass-the-Hash',
    'Ransomware Behavior Identified',
    'C2 Beacon Outbound Traffic',
    'Privilege Escalation Attempt',
    'Suspicious PowerShell Execution',
    'Data Exfiltration — Large Transfer',
    'Port Scan Detected',
    'SQL Injection Attempt',
    'Malware Dropper Executed',
    'Unauthorized Admin Login',
    'DNS Tunneling Suspected',
  ];
  const severities = [0, 1, 2, 2, 3, 3, 3, 4, 4, 5];
  const statuses = ['new', 'new', 'new', 'in_progress', 'resolved', 'escalated'];
  const sev = severities[Math.floor(Math.random() * severities.length)];
  const siem = siems[Math.floor(Math.random() * siems.length)];
  return {
    uid: `mock-${Date.now()}-${i}`,
    source_siem: siem,
    source_uid: `${siem.toUpperCase()}-${100 + i}`,
    timestamp: new Date(Date.now() - Math.random() * 3600000).toISOString(),
    ingested_at: new Date().toISOString(),
    severity: sev,
    severity_label: SEVERITY[sev]?.label || 'Unknown',
    title: titles[Math.floor(Math.random() * titles.length)],
    description: 'Suspicious activity detected by correlation engine.',
    status: statuses[Math.floor(Math.random() * statuses.length)],
    risk_score: Math.round(Math.random() * 100),
    tags: [siem, SEVERITY[sev]?.label?.toLowerCase()],
    src_endpoint: { ip: `192.168.${Math.floor(Math.random()*254)}.${Math.floor(Math.random()*254)}` },
    dst_endpoint: { ip: `10.0.${Math.floor(Math.random()*10)}.${Math.floor(Math.random()*254)}` },
    attack_techniques: sev >= 4 ? [{ technique_id: 'T1059', technique_name: 'Command & Scripting' }] : [],
  };
}
