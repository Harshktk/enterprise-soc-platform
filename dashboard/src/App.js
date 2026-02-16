import React, { useState, useEffect, useRef, useMemo } from 'react';
import TopBar from './components/TopBar';
import StatCard from './components/StatCard';
import AlertTable from './components/AlertTable';
import AlertDetail from './components/AlertDetail';
import { SeverityChart, SiemChart, TimelineChart } from './components/Charts';
import { useMockAlerts } from './hooks';
import styles from './App.module.css';

const USE_MOCK = true;

function useDashboardData() {
  const mockAlerts = useMockAlerts(80);
  const [alerts, setAlerts]     = useState(mockAlerts);
  const [wsStatus, setWsStatus] = useState('live');
  const [newUids, setNewUids]   = useState(new Set());
  const newUidTimer             = useRef({});

  useEffect(() => {
    if (!USE_MOCK) return;
    const interval = setInterval(() => {
      if (Math.random() > 0.55) return;
      const siems  = ['splunk', 'qradar', 'wazuh'];
      const titles = [
        'Brute Force Attempt', 'Malware Download', 'Port Scan Detected',
        'Privilege Escalation', 'Data Exfiltration Attempt', 'C2 Beacon',
        'SQL Injection', 'Suspicious RDP', 'Lateral Movement',
      ];
      const severity = Math.random() < 0.15 ? 5 : Math.random() < 0.3 ? 4 : Math.floor(Math.random() * 4) + 1;
      const uid = `live-${Date.now()}`;
      const newAlert = {
        uid,
        source_uid: `src-${Date.now()}`,
        source_siem: siems[Math.floor(Math.random() * siems.length)],
        timestamp: new Date().toISOString(),
        ingested_at: new Date().toISOString(),
        severity,
        severity_label: ['Unknown','Info','Low','Medium','High','Critical','Fatal'][severity],
        title: titles[Math.floor(Math.random() * titles.length)],
        description: 'Live alert detected — investigate immediately.',
        status: 'new',
        risk_score: Math.round(Math.random() * 100),
        tags: ['live'],
        src_endpoint: { ip: `10.0.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}` },
        dst_endpoint: null,
        attack_techniques: severity >= 4 ? [{ technique_id: 'T1059', technique_name: 'Command Scripting', tactic_name: 'Execution' }] : [],
        enrichments: {},
        raw_event: {},
      };
      setAlerts(prev => [newAlert, ...prev].slice(0, 300));
      setNewUids(prev => new Set([...prev, uid]));
      newUidTimer.current[uid] = setTimeout(() => {
        setNewUids(prev => { const s = new Set(prev); s.delete(uid); return s; });
      }, 3000);
    }, 4000);
    return () => clearInterval(interval);
  }, []);

  const updateStatus = (uid, status) => {
    setAlerts(prev => prev.map(a => a.uid === uid ? { ...a, status } : a));
  };

  return { alerts, wsStatus, newUids, updateStatus };
}

export default function App() {
  const { alerts, wsStatus, newUids, updateStatus } = useDashboardData();
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [view, setView] = useState('queue');

  const stats = useMemo(() => {
    const total    = alerts.length;
    const critical = alerts.filter(a => a.severity >= 5).length;
    const high     = alerts.filter(a => a.severity === 4).length;
    const newCount = alerts.filter(a => a.status === 'new').length;
    const last1h   = alerts.filter(a => (Date.now() - new Date(a.ingested_at).getTime()) < 3600000).length;
    return { total, critical, high, newCount, last1h };
  }, [alerts]);

  function handleSelect(alert) {
    setSelectedAlert(prev => prev?.uid === alert.uid ? null : alert);
  }

  return (
    <div className={styles.app}>
      <TopBar wsStatus={wsStatus} totalAlerts={stats.total} criticalCount={stats.critical} />

      <div className={styles.body}>
        <div className={styles.main}>

          <div className={styles.statBar}>
            <StatCard label="Total Alerts"   value={stats.total}    color="var(--cyan)"  pulse={wsStatus === 'live'} sub="in memory" />
            <StatCard label="Last 1 Hour"    value={stats.last1h}   color="var(--text)"  sub="ingested" />
            <StatCard label="Unacknowledged" value={stats.newCount} color="var(--amber)" sub="status: new" />
            <StatCard label="High Severity"  value={stats.high}     color="var(--amber)" sub="severity ≥ 4" />
            <StatCard label="Critical"       value={stats.critical} color="var(--red)"   pulse={stats.critical > 0} sub="severity ≥ 5" />
          </div>

          <div className={styles.viewToggle}>
            <button className={`${styles.toggleBtn} ${view === 'queue'  ? styles.toggleActive : ''}`} onClick={() => setView('queue')}>ALERT QUEUE</button>
            <button className={`${styles.toggleBtn} ${view === 'charts' ? styles.toggleActive : ''}`} onClick={() => setView('charts')}>ANALYTICS</button>
          </div>

          {view === 'queue' && (
            <AlertTable alerts={alerts} selectedUid={selectedAlert?.uid} onSelect={handleSelect} newUids={newUids} />
          )}

          {view === 'charts' && (
            <div className={styles.chartsGrid}>
              <SeverityChart alerts={alerts} />
              <SiemChart     alerts={alerts} />
              <TimelineChart alerts={alerts} />
            </div>
          )}
        </div>

        {selectedAlert && (
          <AlertDetail
            alert={selectedAlert}
            onClose={() => setSelectedAlert(null)}
            onStatusChange={(uid, status) => {
              updateStatus(uid, status);
              setSelectedAlert(prev => prev?.uid === uid ? { ...prev, status } : prev);
            }}
          />
        )}
      </div>
    </div>
  );
}
