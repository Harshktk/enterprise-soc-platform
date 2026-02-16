import React from 'react';
import { getSiemColor } from '../config';
import styles from './SiemTag.module.css';

export default function SiemTag({ siem }) {
  const color = getSiemColor(siem);
  return (
    <span className={styles.tag} style={{ color, borderColor: color + '50', background: color + '15' }}>
      {siem?.toUpperCase() || '—'}
    </span>
  );
}
