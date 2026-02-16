// API base — uses CRA proxy in dev (see package.json "proxy")
const API = process.env.REACT_APP_API_URL || '';
const WS  = process.env.REACT_APP_WS_URL  || `ws://${window.location.host}/ws/alerts`;

// ── REST ──────────────────────────────────────────────────────────────────────

async function request(path, opts = {}) {
  const res = await fetch(`${API}${path}`, {
    headers: { 'Content-Type': 'application/json', ...opts.headers },
    ...opts,
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${path}`);
  return res.json();
}

export const api = {
  getAlerts: (params = {}) => {
    const qs = new URLSearchParams(
      Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== '')
    ).toString();
    return request(`/api/alerts${qs ? '?' + qs : ''}`);
  },
  getAlert:        (uid) => request(`/api/alerts/${uid}`),
  updateStatus:    (uid, status) =>
    request(`/api/alerts/${uid}/status?status=${status}`, { method: 'PATCH' }),
  getStats:        () => request('/api/stats'),
  health:          () => request('/api/health'),
};

// ── WebSocket ─────────────────────────────────────────────────────────────────

export class AlertWebSocket {
  constructor(onAlert, onStatusChange) {
    this.onAlert        = onAlert;
    this.onStatusChange = onStatusChange;
    this.ws             = null;
    this.retries        = 0;
    this.maxRetries     = 10;
    this.retryDelay     = 2000;
    this._dead          = false;
  }

  connect() {
    if (this._dead) return;
    try {
      this.ws = new WebSocket(WS);

      this.ws.onopen = () => {
        this.retries = 0;
        this.onStatusChange('connected');
      };

      this.ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data);
          if (msg.type === 'ping') return;
          this.onAlert(msg);
        } catch {}
      };

      this.ws.onerror = () => this.onStatusChange('error');

      this.ws.onclose = () => {
        this.onStatusChange('disconnected');
        if (!this._dead && this.retries < this.maxRetries) {
          this.retries++;
          setTimeout(() => this.connect(), this.retryDelay * Math.min(this.retries, 5));
        }
      };
    } catch {
      this.onStatusChange('error');
    }
  }

  disconnect() {
    this._dead = true;
    this.ws?.close();
  }
}
