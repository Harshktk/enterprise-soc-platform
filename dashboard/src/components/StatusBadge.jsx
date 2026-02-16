import React from 'react';
import styles from './StatusBadge.module.css';

const STATUS = {
  new:         { label: 'NEW',         color: '#ff4060' },
  in_progress: { label: 'IN PROGRESS', color: '#ffaa00' },
  resolved:    { label: 'RESOLVED',    color: '#00e896' },
  suppressed:  { label: 'SUPPRESSED',  color: '#4d6282' },
  escalated:   { label: 'ESCALATED',   color: '#a855f7' },
};

export default function StatusBadge({ status }) {
  const s = STATUS[status] ?? STATUS.new;
  return (
    <span className={styles.badge} style={{ color: s.color, borderColor: s.color + '40' }}>
      {s.label}
    </span>
  );
}
