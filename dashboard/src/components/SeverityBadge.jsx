import React from 'react';
import { getSeverity } from '../config';
import styles from './SeverityBadge.module.css';

export default function SeverityBadge({ level, label, size = 'sm' }) {
  const sev = getSeverity(level);
  return (
    <span
      className={`${styles.badge} ${styles[size]}`}
      style={{ color: sev.color, background: sev.bg, borderColor: sev.color + '40' }}
    >
      <span className={styles.dot} style={{ background: sev.color }} />
      {label || sev.label}
    </span>
  );
}
