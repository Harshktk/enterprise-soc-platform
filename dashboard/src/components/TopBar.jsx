import React, { useState, useEffect } from 'react';
import styles from './TopBar.module.css';

export default function TopBar({ wsStatus, totalAlerts, criticalCount }) {
  const [time, setTime] = useState(new Date());
  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  const wsColor = wsStatus === 'live' ? 'var(--green)' : wsStatus === 'connecting' ? 'var(--amber)' : 'var(--red)';

  return (
    <header className={styles.bar}>
      <div className={styles.left}>
        <div className={styles.logo}>
          <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
            <polygon points="9,1 17,5 17,13 9,17 1,13 1,5" stroke="var(--cyan)" strokeWidth="1.2" fill="none"/>
            <polygon points="9,5 13,7 13,11 9,13 5,11 5,7" stroke="var(--cyan)" strokeWidth="0.8" fill="rgba(0,212,255,0.1)"/>
          </svg>
          <span className={styles.brand}>SOC <span>PLATFORM</span></span>
        </div>
        <div className={styles.divider} />
        <span className={styles.phase}>PHASE 1 — PIPELINE</span>
      </div>

      <div className={styles.center}>
        {criticalCount > 0 && (
          <div className={styles.criticalAlert}>
            <span className={styles.critPulse} />
            <span>{criticalCount} CRITICAL ALERT{criticalCount > 1 ? 'S' : ''} ACTIVE</span>
          </div>
        )}
      </div>

      <div className={styles.right}>
        <div className={styles.wsIndicator} style={{ color: wsColor }}>
          <span className={styles.wsDot} style={{ background: wsColor }} />
          {wsStatus.toUpperCase()}
        </div>
        <div className={styles.divider} />
        <div className={styles.clock}>
          <span className={styles.clockDate}>{time.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}</span>
          <span className={styles.clockTime}>{time.toLocaleTimeString('en-US', { hour12: false })}</span>
        </div>
      </div>
    </header>
  );
}
