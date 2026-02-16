import React, { useState, useMemo } from 'react';
import SeverityBadge from './SeverityBadge';
import SiemTag from './SiemTag';
import StatusBadge from './StatusBadge';
import { timeAgo, formatTime } from '../config';
import styles from './AlertTable.module.css';

const COLS = [
  { key: 'severity',    label: 'SEV',       width: '72px'  },
  { key: 'time',        label: 'TIME',       width: '76px'  },
  { key: 'siem',        label: 'SIEM',       width: '76px'  },
  { key: 'title',       label: 'TITLE',      width: 'auto'  },
  { key: 'src',         label: 'SOURCE IP',  width: '120px' },
  { key: 'techniques',  label: 'ATT&CK',     width: '100px' },
  { key: 'status',      label: 'STATUS',     width: '100px' },
];

export default function AlertTable({ alerts, selectedUid, onSelect, newUids }) {
  const [sortCol, setSortCol]   = useState('time');
  const [sortDir, setSortDir]   = useState('desc');
  const [search,  setSearch]    = useState('');
  const [sevFilter, setSevFilter] = useState(0);
  const [siemFilter, setSiemFilter] = useState('all');

  const siems = useMemo(() => {
    const s = new Set(alerts.map(a => a.source_siem).filter(Boolean));
    return ['all', ...s];
  }, [alerts]);

  const filtered = useMemo(() => {
    let list = alerts;
    if (sevFilter > 0)        list = list.filter(a => a.severity >= sevFilter);
    if (siemFilter !== 'all') list = list.filter(a => a.source_siem === siemFilter);
    if (search.trim()) {
      const q = search.trim().toLowerCase();
      list = list.filter(a =>
        a.title?.toLowerCase().includes(q) ||
        a.source_uid?.toLowerCase().includes(q) ||
        a.src_endpoint?.ip?.includes(q) ||
        a.source_siem?.includes(q)
      );
    }
    const sorted = [...list].sort((a, b) => {
      let av, bv;
      if (sortCol === 'severity') { av = a.severity; bv = b.severity; }
      else if (sortCol === 'time') { av = new Date(a.ingested_at); bv = new Date(b.ingested_at); }
      else { av = a.title; bv = b.title; }
      if (av < bv) return sortDir === 'asc' ? -1 : 1;
      if (av > bv) return sortDir === 'asc' ? 1 : -1;
      return 0;
    });
    return sorted;
  }, [alerts, sevFilter, siemFilter, search, sortCol, sortDir]);

  function toggleSort(col) {
    if (sortCol === col) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortCol(col); setSortDir('desc'); }
  }

  return (
    <div className={styles.container}>
      {/* Toolbar */}
      <div className={styles.toolbar}>
        <div className={styles.searchWrap}>
          <span className={styles.searchIcon}>⌕</span>
          <input
            className={styles.search}
            placeholder="Search title, IP, source..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
          {search && (
            <button className={styles.clearSearch} onClick={() => setSearch('')}>✕</button>
          )}
        </div>

        <div className={styles.filters}>
          <span className={styles.filterLabel}>SEV ≥</span>
          <select className={styles.select} value={sevFilter} onChange={e => setSevFilter(+e.target.value)}>
            <option value={0}>ALL</option>
            <option value={2}>LOW+</option>
            <option value={3}>MEDIUM+</option>
            <option value={4}>HIGH+</option>
            <option value={5}>CRITICAL</option>
          </select>

          <span className={styles.filterLabel}>SIEM</span>
          <select className={styles.select} value={siemFilter} onChange={e => setSiemFilter(e.target.value)}>
            {siems.map(s => (
              <option key={s} value={s}>{s.toUpperCase()}</option>
            ))}
          </select>
        </div>

        <div className={styles.count}>
          <span className={styles.countNum}>{filtered.length}</span>
          <span className={styles.countOf}>/ {alerts.length}</span>
        </div>
      </div>

      {/* Table */}
      <div className={styles.tableWrap}>
        <table className={styles.table}>
          <thead>
            <tr>
              {COLS.map(col => (
                <th
                  key={col.key}
                  className={`${styles.th} ${sortCol === col.key ? styles.thActive : ''}`}
                  style={{ width: col.width, minWidth: col.width }}
                  onClick={() => ['severity','time','title'].includes(col.key) && toggleSort(col.key)}
                >
                  {col.label}
                  {sortCol === col.key && (
                    <span className={styles.sortArrow}>{sortDir === 'asc' ? ' ↑' : ' ↓'}</span>
                  )}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 && (
              <tr>
                <td colSpan={COLS.length} className={styles.empty}>
                  NO ALERTS MATCH CURRENT FILTERS
                </td>
              </tr>
            )}
            {filtered.map(alert => {
              const isNew      = newUids?.has(alert.uid);
              const isSelected = selectedUid === alert.uid;
              const tech       = alert.attack_techniques?.[0];
              return (
                <tr
                  key={alert.uid}
                  className={`
                    ${styles.row}
                    ${isSelected ? styles.rowSelected : ''}
                    ${isNew      ? styles.rowNew      : ''}
                    ${alert.severity >= 5 ? styles.rowCritical : ''}
                  `}
                  onClick={() => onSelect(alert)}
                >
                  <td className={styles.td}>
                    <SeverityBadge level={alert.severity} label={alert.severity_label} />
                  </td>
                  <td className={styles.td}>
                    <div className={styles.timeMain}>{formatTime(alert.ingested_at)}</div>
                    <div className={styles.timeAgo}>{timeAgo(alert.ingested_at)}</div>
                  </td>
                  <td className={styles.td}>
                    <SiemTag siem={alert.source_siem} />
                  </td>
                  <td className={`${styles.td} ${styles.tdTitle}`}>
                    <div className={styles.titleText}>{alert.title}</div>
                    {alert.src_endpoint?.hostname && (
                      <div className={styles.titleSub}>{alert.src_endpoint.hostname}</div>
                    )}
                  </td>
                  <td className={styles.td}>
                    <span className={styles.ip}>{alert.src_endpoint?.ip || '—'}</span>
                  </td>
                  <td className={styles.td}>
                    {tech ? (
                      <div>
                        <div className={styles.techId}>{tech.technique_id}</div>
                        <div className={styles.techName}>{tech.technique_name}</div>
                      </div>
                    ) : <span className={styles.noTech}>—</span>}
                  </td>
                  <td className={styles.td}>
                    <StatusBadge status={alert.status} />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
