import React from 'react';
import styles from './StatCard.module.css';

export default function StatCard({ label, value, sub, color = 'var(--cyan)', icon, pulse }) {
  return (
    <div className={styles.card}>
      <div className={styles.top}>
        <span className={styles.label}>{label}</span>
        {icon && <span className={styles.icon}>{icon}</span>}
      </div>
      <div className={styles.value} style={{ color }}>
        {pulse && <span className={styles.pulse} style={{ background: color }} />}
        {value ?? '—'}
      </div>
      {sub && <div className={styles.sub}>{sub}</div>}
    </div>
  );
}
