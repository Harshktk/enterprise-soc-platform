// API + WebSocket base URLs
// In dev, CRA proxies /api → http://api:8000 via package.json "proxy"
export const API_BASE = process.env.REACT_APP_API_URL || '';
export const WS_URL   = process.env.REACT_APP_WS_URL  || 'ws://localhost:8000/ws/alerts';

export const SEVERITY = {
  0: { label: 'Unknown',       color: '#4d6282',  bg: 'rgba(77,98,130,0.15)'   },
  1: { label: 'Info',          color: '#00d4ff',  bg: 'rgba(0,212,255,0.12)'   },
  2: { label: 'Low',           color: '#00e896',  bg: 'rgba(0,232,150,0.10)'   },
  3: { label: 'Medium',        color: '#ffaa00',  bg: 'rgba(255,170,0,0.12)'   },
  4: { label: 'High',          color: '#ff7a30',  bg: 'rgba(255,122,48,0.12)'  },
  5: { label: 'Critical',      color: '#ff4060',  bg: 'rgba(255,64,96,0.12)'   },
  6: { label: 'Fatal',         color: '#cc00ff',  bg: 'rgba(204,0,255,0.12)'   },
};

export const SIEM_COLORS = {
  splunk:   '#00d4ff',
  qradar:   '#ffaa00',
  wazuh:    '#00e896',
  sentinel: '#a855f7',
  elastic:  '#ff7a30',
  default:  '#4d6282',
};

export function getSeverity(level) {
  return SEVERITY[level] ?? SEVERITY[0];
}

export function getSiemColor(siem) {
  return SIEM_COLORS[siem?.toLowerCase()] ?? SIEM_COLORS.default;
}

export function timeAgo(isoString) {
  const diff = Date.now() - new Date(isoString).getTime();
  const s = Math.floor(diff / 1000);
  if (s < 60)  return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60)  return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24)  return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

export function formatTime(isoString) {
  if (!isoString) return '—';
  const d = new Date(isoString);
  return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export function formatDate(isoString) {
  if (!isoString) return '—';
  const d = new Date(isoString);
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}
