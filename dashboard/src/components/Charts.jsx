import React, { useMemo } from 'react';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, LineChart, Line, CartesianGrid
} from 'recharts';
import { getSeverity, getSiemColor, SEVERITY } from '../config';
import styles from './Charts.module.css';

// ─── Mini Bar: Severity Breakdown ────────────────────────────────────────────
export function SeverityChart({ alerts }) {
  const data = useMemo(() => {
    const counts = {};
    alerts.forEach(a => {
      const lbl = a.severity_label || 'Unknown';
      counts[lbl] = (counts[lbl] || 0) + 1;
    });
    return Object.entries(SEVERITY)
      .map(([lvl, meta]) => ({
        label: meta.label,
        count: counts[meta.label] || 0,
        color: meta.color,
      }))
      .filter(d => d.count > 0)
      .sort((a, b) => b.count - a.count);
  }, [alerts]);

  return (
    <div className={styles.chartBox}>
      <div className={styles.chartTitle}>SEVERITY BREAKDOWN</div>
      <ResponsiveContainer width="100%" height={120}>
        <BarChart data={data} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
          <XAxis dataKey="label" tick={{ fill: '#4d6282', fontSize: 9, fontFamily: 'IBM Plex Mono' }} axisLine={false} tickLine={false} />
          <YAxis tick={{ fill: '#4d6282', fontSize: 9, fontFamily: 'IBM Plex Mono' }} axisLine={false} tickLine={false} />
          <Tooltip
            contentStyle={{ background: '#0c1220', border: '1px solid #1e2d45', borderRadius: '3px', fontFamily: 'IBM Plex Mono', fontSize: 11 }}
            labelStyle={{ color: '#cdd6e8' }}
            cursor={{ fill: 'rgba(255,255,255,0.04)' }}
          />
          <Bar dataKey="count" radius={[2,2,0,0]}>
            {data.map((entry, i) => (
              <Cell key={i} fill={entry.color} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

// ─── Donut: SIEM Distribution ─────────────────────────────────────────────────
export function SiemChart({ alerts }) {
  const data = useMemo(() => {
    const counts = {};
    alerts.forEach(a => {
      const s = a.source_siem || 'unknown';
      counts[s] = (counts[s] || 0) + 1;
    });
    return Object.entries(counts).map(([siem, count]) => ({
      name: siem.toUpperCase(), count, color: getSiemColor(siem)
    }));
  }, [alerts]);

  const total = data.reduce((s, d) => s + d.count, 0);

  return (
    <div className={styles.chartBox}>
      <div className={styles.chartTitle}>SIEM DISTRIBUTION</div>
      <div className={styles.donutWrap}>
        <ResponsiveContainer width={110} height={110}>
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius={32}
              outerRadius={50}
              paddingAngle={2}
              dataKey="count"
            >
              {data.map((entry, i) => (
                <Cell key={i} fill={entry.color} stroke="none" />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{ background: '#0c1220', border: '1px solid #1e2d45', borderRadius: '3px', fontFamily: 'IBM Plex Mono', fontSize: 11 }}
              cursor={false}
            />
          </PieChart>
        </ResponsiveContainer>
        <div className={styles.donutCenter}>
          <span className={styles.donutNum}>{total}</span>
          <span className={styles.donutLbl}>total</span>
        </div>
        <div className={styles.legend}>
          {data.map((d, i) => (
            <div key={i} className={styles.legendItem}>
              <span className={styles.legendDot} style={{ background: d.color }} />
              <span className={styles.legendName}>{d.name}</span>
              <span className={styles.legendCount} style={{ color: d.color }}>{d.count}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Line: Alert Rate Timeline ───────────────────────────────────────────────
export function TimelineChart({ alerts }) {
  const data = useMemo(() => {
    // Bucket into 5-minute windows over last 2 hours
    const now    = Date.now();
    const window = 5 * 60 * 1000;
    const numBuckets = 24;
    const buckets = Array.from({ length: numBuckets }, (_, i) => ({
      t: new Date(now - (numBuckets - 1 - i) * window),
      high: 0, medium: 0, low: 0,
    }));

    alerts.forEach(a => {
      const ts  = new Date(a.ingested_at).getTime();
      const idx = buckets.findIndex((b, i) => {
        const next = buckets[i + 1]?.t.getTime() ?? Infinity;
        return ts >= b.t.getTime() && ts < next;
      });
      if (idx === -1) return;
      const sev = a.severity;
      if (sev >= 4)      buckets[idx].high++;
      else if (sev >= 3) buckets[idx].medium++;
      else               buckets[idx].low++;
    });

    return buckets.map(b => ({
      label: b.t.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false }),
      ...b,
    }));
  }, [alerts]);

  return (
    <div className={`${styles.chartBox} ${styles.timelineBox}`}>
      <div className={styles.chartTitle}>ALERT RATE — LAST 2H (5-MIN BUCKETS)</div>
      <ResponsiveContainer width="100%" height={100}>
        <LineChart data={data} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
          <CartesianGrid stroke="#1e2d45" strokeDasharray="2 4" vertical={false} />
          <XAxis dataKey="label" tick={{ fill: '#4d6282', fontSize: 8, fontFamily: 'IBM Plex Mono' }} axisLine={false} tickLine={false} interval={5} />
          <YAxis tick={{ fill: '#4d6282', fontSize: 9, fontFamily: 'IBM Plex Mono' }} axisLine={false} tickLine={false} allowDecimals={false} />
          <Tooltip
            contentStyle={{ background: '#0c1220', border: '1px solid #1e2d45', borderRadius: '3px', fontFamily: 'IBM Plex Mono', fontSize: 11 }}
            cursor={{ stroke: '#253550' }}
          />
          <Line type="monotone" dataKey="high"   stroke="#ff4060" strokeWidth={1.5} dot={false} />
          <Line type="monotone" dataKey="medium" stroke="#ffaa00" strokeWidth={1.5} dot={false} />
          <Line type="monotone" dataKey="low"    stroke="#00e896" strokeWidth={1}   dot={false} strokeOpacity={0.6} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
