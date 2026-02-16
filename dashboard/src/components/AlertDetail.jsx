import React from 'react';
import SeverityBadge from './SeverityBadge';
import SiemTag from './SiemTag';
import StatusBadge from './StatusBadge';
import { formatTime, formatDate, timeAgo } from '../config';
import styles from './AlertDetail.module.css';

export default function AlertDetail({ alert, onClose, onStatusChange }) {
  if (!alert) return null;

  const sections = [
    { key: 'IDENTITY', rows: [
      ['Alert UID',   alert.uid],
      ['Source UID',  alert.source_uid],
      ['Source SIEM', <SiemTag siem={alert.source_siem} />],
      ['Status',      <StatusBadge status={alert.status} />],
    ]},
    { key: 'TIMING', rows: [
      ['Event Time',    formatDate(alert.timestamp) + ' ' + formatTime(alert.timestamp)],
      ['Ingested At',   formatDate(alert.ingested_at) + ' ' + formatTime(alert.ingested_at)],
      ['Age',           timeAgo(alert.ingested_at)],
    ]},
    { key: 'CLASSIFICATION', rows: [
      ['Type',      alert.type_name || '—'],
      ['Category',  alert.category  || '—'],
      ['Severity',  <SeverityBadge level={alert.severity} label={alert.severity_label} size="md" />],
      ['Risk Score', alert.risk_score != null ? `${alert.risk_score} / 100` : '—'],
    ]},
  ];

  if (alert.src_endpoint?.ip || alert.dst_endpoint?.ip) {
    sections.push({ key: 'NETWORK', rows: [
      ['Source IP',   alert.src_endpoint?.ip       || '—'],
      ['Source Host', alert.src_endpoint?.hostname  || '—'],
      ['Source Port', alert.src_endpoint?.port      || '—'],
      ['Dest IP',     alert.dst_endpoint?.ip        || '—'],
      ['Dest Port',   alert.dst_endpoint?.port      || '—'],
    ]});
  }

  const actor = alert.actor;
  if (actor?.user || actor?.process) {
    sections.push({ key: 'ACTOR', rows: [
      ['User',    actor.user    || '—'],
      ['Process', actor.process || '—'],
    ]});
  }

  const techniques = alert.attack_techniques || [];
  const enrichments = alert.enrichments || {};

  return (
    <div className={styles.panel}>
      {/* Header */}
      <div className={styles.header}>
        <div className={styles.headerLeft}>
          <span className={styles.headerLabel}>ALERT DETAIL</span>
          <SeverityBadge level={alert.severity} label={alert.severity_label} size="md" />
        </div>
        <button className={styles.close} onClick={onClose}>✕</button>
      </div>

      {/* Title */}
      <div className={styles.titleBlock}>
        <div className={styles.title}>{alert.title}</div>
        {alert.description && (
          <div className={styles.description}>{alert.description}</div>
        )}
      </div>

      {/* Status change */}
      <div className={styles.statusRow}>
        <span className={styles.statusLabel}>STATUS:</span>
        {['new','in_progress','resolved','suppressed'].map(s => (
          <button
            key={s}
            className={`${styles.statusBtn} ${alert.status === s ? styles.statusActive : ''}`}
            onClick={() => onStatusChange(alert.uid, s)}
          >
            {s.replace('_', ' ').toUpperCase()}
          </button>
        ))}
      </div>

      <div className={styles.scrollBody}>

        {/* Data sections */}
        {sections.map(sec => (
          <div key={sec.key} className={styles.section}>
            <div className={styles.sectionHead}>{sec.key}</div>
            <table className={styles.table}>
              <tbody>
                {sec.rows.filter(([,v]) => v !== undefined).map(([k, v]) => (
                  <tr key={k}>
                    <td className={styles.tdKey}>{k}</td>
                    <td className={styles.tdVal}>{v ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ))}

        {/* ATT&CK Techniques */}
        {techniques.length > 0 && (
          <div className={styles.section}>
            <div className={styles.sectionHead}>MITRE ATT&CK</div>
            <div className={styles.techniques}>
              {techniques.map((t, i) => (
                <div key={i} className={styles.technique}>
                  {t.technique_id && (
                    <span className={styles.techId}>{t.technique_id}</span>
                  )}
                  <div>
                    <div className={styles.techName}>{t.technique_name || '—'}</div>
                    {t.tactic_name && (
                      <div className={styles.techTactic}>{t.tactic_name}</div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Tags */}
        {alert.tags?.length > 0 && (
          <div className={styles.section}>
            <div className={styles.sectionHead}>TAGS</div>
            <div className={styles.tags}>
              {alert.tags.map(tag => (
                <span key={tag} className={styles.tag}>{tag}</span>
              ))}
            </div>
          </div>
        )}

        {/* Enrichments */}
        {Object.keys(enrichments).length > 0 && (
          <div className={styles.section}>
            <div className={styles.sectionHead}>ENRICHMENTS</div>
            <table className={styles.table}>
              <tbody>
                {Object.entries(enrichments)
                  .filter(([,v]) => v != null)
                  .map(([k, v]) => (
                    <tr key={k}>
                      <td className={styles.tdKey}>{k.replace(/_/g,' ')}</td>
                      <td className={styles.tdVal}>{String(v)}</td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Raw event toggle */}
        <details className={styles.rawSection}>
          <summary className={styles.rawSummary}>RAW EVENT PAYLOAD</summary>
          <pre className={styles.rawPre}>
            {JSON.stringify(alert.raw_event || {}, null, 2)}
          </pre>
        </details>

      </div>
    </div>
  );
}
