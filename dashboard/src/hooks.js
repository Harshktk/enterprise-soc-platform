import { useState, useEffect, useCallback, useRef } from 'react';
import axios from 'axios';
import { API_BASE, WS_URL } from './config';

// ─── useAlerts ────────────────────────────────────────────────────────────────
// Fetches initial alert list and streams live updates via WebSocket.
export function useAlerts({ limit = 200, severityMin = 0, sourceSiem, status } = {}) {
  const [alerts, setAlerts]   = useState([]);
  const [loading, setLoading] = useState(true);
  const [wsStatus, setWsStatus] = useState('connecting'); // connecting | live | disconnected
  const wsRef = useRef(null);
  const alertsRef = useRef([]);

  // Initial fetch
  const fetchAlerts = useCallback(async () => {
    try {
      const params = { limit, severity_min: severityMin };
      if (sourceSiem) params.source_siem = sourceSiem;
      if (status)     params.status      = status;
      const res = await axios.get(`${API_BASE}/api/alerts`, { params });
      alertsRef.current = res.data;
      setAlerts(res.data);
    } catch (e) {
      console.error('Failed to fetch alerts:', e);
    } finally {
      setLoading(false);
    }
  }, [limit, severityMin, sourceSiem, status]);

  // WebSocket live stream
  useEffect(() => {
    fetchAlerts();

    function connect() {
      const ws = new WebSocket(WS_URL);
      wsRef.current = ws;

      ws.onopen  = () => setWsStatus('live');
      ws.onclose = () => {
        setWsStatus('disconnected');
        // Reconnect after 3s
        setTimeout(connect, 3000);
      };
      ws.onerror = () => ws.close();
      ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data);
          if (msg.type === 'ping') return;
          // Prepend new alert
          alertsRef.current = [msg, ...alertsRef.current].slice(0, limit);
          setAlerts([...alertsRef.current]);
        } catch { /* ignore */ }
      };
    }

    connect();
    return () => wsRef.current?.close();
  }, [fetchAlerts, limit]);

  const updateStatus = useCallback(async (uid, newStatus) => {
    await axios.patch(`${API_BASE}/api/alerts/${uid}/status`, null, {
      params: { status: newStatus }
    });
    setAlerts(prev =>
      prev.map(a => a.uid === uid ? { ...a, status: newStatus } : a)
    );
  }, []);

  return { alerts, loading, wsStatus, refetch: fetchAlerts, updateStatus };
}

// ─── useStats ─────────────────────────────────────────────────────────────────
export function useStats(refreshInterval = 15000) {
  const [stats, setStats]   = useState(null);
  const [loading, setLoading] = useState(true);

  const fetch = useCallback(async () => {
    try {
      const res = await axios.get(`${API_BASE}/api/stats`);
      setStats(res.data);
    } catch (e) {
      console.error('Failed to fetch stats:', e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetch();
    const t = setInterval(fetch, refreshInterval);
    return () => clearInterval(t);
  }, [fetch, refreshInterval]);

  return { stats, loading, refetch: fetch };
}

// ─── useAlert (single) ────────────────────────────────────────────────────────
export function useAlert(uid) {
  const [alert, setAlert]   = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!uid) { setAlert(null); setLoading(false); return; }
    setLoading(true);
    axios.get(`${API_BASE}/api/alerts/${uid}`)
      .then(r => setAlert(r.data))
      .catch(() => setAlert(null))
      .finally(() => setLoading(false));
  }, [uid]);

  return { alert, loading };
}

// ─── useMockData (dev fallback when API is offline) ──────────────────────────
export function useMockAlerts(count = 60) {
  const siems     = ['splunk', 'qradar', 'wazuh'];
  const titles    = [
    'Brute Force Attack Detected', 'Ransomware Signature Match',
    'Lateral Movement via SMB', 'Privilege Escalation Attempt',
    'C2 Beacon Detected', 'SQL Injection in Web App',
    'Suspicious PowerShell Execution', 'Anomalous Data Exfiltration',
    'Failed Login Spike', 'Malware Dropper Activity',
    'Unauthorized RDP Access', 'DNS Tunneling Suspected',
    'DDoS Traffic Pattern', 'Rootkit Detection',
    'Credential Dumping (LSASS)', 'Port Scan from Internal Host',
    'Unusual Admin Account Usage', 'Zero-day Exploit Attempt',
  ];
  const techniques = [
    { technique_id: 'T1110', technique_name: 'Brute Force',        tactic_name: 'Credential Access' },
    { technique_id: 'T1059', technique_name: 'Command Scripting',  tactic_name: 'Execution' },
    { technique_id: 'T1021', technique_name: 'Remote Services',    tactic_name: 'Lateral Movement' },
    { technique_id: 'T1055', technique_name: 'Process Injection',  tactic_name: 'Defense Evasion' },
    { technique_id: 'T1071', technique_name: 'C2 Protocol',        tactic_name: 'Command & Control' },
  ];

  return Array.from({ length: count }, (_, i) => {
    const severity = Math.floor(Math.random() * 7);
    const siem     = siems[i % siems.length];
    const now      = new Date(Date.now() - i * 47000);
    return {
      uid:           `mock-${String(i).padStart(4,'0')}`,
      source_uid:    `src-${1000 + i}`,
      source_siem:   siem,
      timestamp:     new Date(now.getTime() - 5000).toISOString(),
      ingested_at:   now.toISOString(),
      severity,
      severity_label: ['Unknown','Info','Low','Medium','High','Critical','Fatal'][severity],
      title:         titles[i % titles.length],
      description:   `Detected suspicious activity originating from internal network segment. Investigation required.`,
      status:        ['new','new','new','in_progress','resolved'][i % 5],
      risk_score:    Math.round(Math.random() * 100),
      tags:          [siem, 'phase1'],
      src_endpoint:  { ip: `192.168.${(i*7)%255}.${(i*13)%255}`, hostname: `host-${i%20}` },
      dst_endpoint:  { ip: `10.0.${(i*3)%10}.${(i*17)%255}` },
      attack_techniques: severity >= 3 ? [techniques[i % techniques.length]] : [],
      enrichments:   { agent_name: `agent-${i%10}`, rule_level: severity * 2 },
    };
  });
}
