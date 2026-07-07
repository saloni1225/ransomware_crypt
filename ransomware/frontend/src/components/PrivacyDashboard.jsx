import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { Lock, AlertTriangle, CheckCircle, XCircle, Shield, Eye } from 'lucide-react';

const SEVERITY_CONFIG = {
  critical: { color: '#ff1744', bg: 'rgba(255,23,68,0.12)', label: 'Critical' },
  high: { color: '#f64f59', bg: 'rgba(246,79,89,0.1)', label: 'High' },
  medium: { color: '#f7971e', bg: 'rgba(247,151,30,0.1)', label: 'Medium' },
  low: { color: '#43e97b', bg: 'rgba(67,233,123,0.1)', label: 'Low' },
};

const CATEGORY_COLORS = {
  credentials: '#f64f59',
  PII: '#f7971e',
  financial: '#a78bfa',
  health: '#43e97b',
  intellectual_property: '#00f2fe',
};

const EVENT_TYPE_LABELS = {
  exfiltration: '⬆️ Exfiltration',
  data_access: '👁️ Data Access',
  policy_violation: '⚠️ Policy Violation',
  leak_attempt: '💧 Leak Attempt',
};

// Privacy Health Score Gauge (SVG arc)
function ScoreGauge({ score, label, color }) {
  const radius = 70;
  const circumference = Math.PI * radius; // half circle
  const progress = (score / 100) * circumference;
  const remaining = circumference - progress;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '24px 0' }}>
      <svg width="180" height="100" viewBox="0 0 180 100">
        {/* Track */}
        <path
          d={`M 10 90 A 80 80 0 0 1 170 90`}
          fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="12" strokeLinecap="round"
        />
        {/* Progress */}
        <path
          d={`M 10 90 A 80 80 0 0 1 170 90`}
          fill="none"
          stroke={color}
          strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={`${(score / 100) * 250} 250`}
          style={{ filter: `drop-shadow(0 0 8px ${color}80)`, transition: 'stroke-dasharray 1s ease' }}
        />
        {/* Score Text */}
        <text x="90" y="80" textAnchor="middle" fill="white" fontSize="32" fontWeight="800" fontFamily="Inter, sans-serif">{score}</text>
        <text x="90" y="97" textAnchor="middle" fill={color} fontSize="11" fontWeight="700" fontFamily="Inter, sans-serif">{label.toUpperCase()}</text>
      </svg>
      <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>Privacy Health Score</div>
    </div>
  );
}

// Category Pie Chart (simple SVG)
function CategoryPie({ categories }) {
  const COLORS = Object.values(CATEGORY_COLORS);
  const keys = Object.keys(categories);
  const total = Object.values(categories).reduce((a, b) => a + b, 0);
  if (total === 0) return <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>No data</div>;

  let offset = 0;
  const cx = 70, cy = 70, r = 55;
  const arcs = keys.map((k, i) => {
    const pct = categories[k] / total;
    const startAngle = offset * 360;
    const endAngle = (offset + pct) * 360;
    offset += pct;
    const toRad = (a) => (a - 90) * Math.PI / 180;
    const x1 = cx + r * Math.cos(toRad(startAngle));
    const y1 = cy + r * Math.sin(toRad(startAngle));
    const x2 = cx + r * Math.cos(toRad(endAngle));
    const y2 = cy + r * Math.sin(toRad(endAngle));
    const large = pct > 0.5 ? 1 : 0;
    return { key: k, d: `M ${cx} ${cy} L ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2} Z`, color: CATEGORY_COLORS[k] || COLORS[i % COLORS.length], count: categories[k], pct: Math.round(pct * 100) };
  });

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
      <svg width="140" height="140">
        {arcs.map(arc => (
          <path key={arc.key} d={arc.d} fill={arc.color} opacity={0.85} stroke="var(--bg-card)" strokeWidth="2" />
        ))}
      </svg>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
        {arcs.map(arc => (
          <div key={arc.key} style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <div style={{ width: '10px', height: '10px', borderRadius: '3px', background: arc.color, flexShrink: 0 }} />
            <span style={{ fontSize: '12px', color: 'var(--text-secondary)', textTransform: 'capitalize' }}>{arc.key}</span>
            <span style={{ fontSize: '12px', color: 'var(--text-muted)', marginLeft: 'auto', fontFamily: 'monospace' }}>{arc.count} ({arc.pct}%)</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function PrivacyDashboard() {
  const [privacyScore, setPrivacyScore] = useState(null);
  const [events, setEvents] = useState([]);
  const [stats, setStats] = useState(null);
  const [categories, setCategories] = useState({});
  const [loading, setLoading] = useState(true);
  const [evFilter, setEvFilter] = useState('all');

  const load = async () => {
    try {
      const [score, evs, st, cats] = await Promise.all([
        api.getPrivacyScore(),
        api.listPrivacyEvents(),
        api.getPrivacyStats(),
        fetch('http://localhost:8000/api/privacy/data-categories', { headers: { Authorization: `Bearer ${localStorage.getItem('token')}` } }).then(r => r.json()),
      ]);
      setPrivacyScore(score);
      setEvents(evs);
      setStats(st);
      // Convert array to object
      const catObj = {};
      cats.forEach(c => { catObj[c.category] = c.count; });
      setCategories(catObj);
    } catch (err) { console.error(err); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  const filteredEvents = events.filter(e => {
    if (evFilter === 'blocked') return e.is_blocked;
    if (evFilter === 'unblocked') return !e.is_blocked;
    if (evFilter === 'critical') return e.severity === 'critical';
    return true;
  });

  return (
    <div style={{ padding: '32px', maxWidth: '1300px' }}>
      {/* Header */}
      <div style={{ marginBottom: '32px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '6px' }}>
          <Lock size={28} color="#a78bfa" />
          <h1 style={{ fontSize: '26px', fontWeight: 800, color: 'var(--text-main)', margin: 0 }}>Privacy Dashboard</h1>
        </div>
        <p style={{ color: 'var(--text-secondary)', fontSize: '14px', margin: 0 }}>
          Data exfiltration monitoring · GDPR compliance · Privacy health score
        </p>
      </div>

      {/* Top Panel: Score + Categories + Compliance */}
      <div style={{ display: 'grid', gridTemplateColumns: '240px 1fr 280px', gap: '20px', marginBottom: '28px' }}>

        {/* Score Gauge */}
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '14px', padding: '12px' }}>
          {privacyScore ? (
            <ScoreGauge score={privacyScore.score} label={privacyScore.label} color={privacyScore.color} />
          ) : (
            <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>Loading...</div>
          )}
          {/* Stats below gauge */}
          {stats && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', padding: '0 8px 8px' }}>
              {[
                { label: 'Total Events', value: stats.total_events, color: 'var(--cyan)' },
                { label: 'Blocked', value: stats.blocked, color: '#43e97b' },
                { label: 'Violations', value: stats.unblocked, color: '#f64f59' },
                { label: 'Exfil Attempts', value: stats.exfiltration_attempts, color: '#f7971e' },
              ].map(c => (
                <div key={c.label} style={{ background: 'rgba(0,0,0,0.2)', borderRadius: '8px', padding: '10px', textAlign: 'center' }}>
                  <div style={{ fontSize: '18px', fontWeight: 800, color: c.color }}>{c.value}</div>
                  <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '2px' }}>{c.label}</div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Category Breakdown */}
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '14px', padding: '24px' }}>
          <h3 style={{ color: 'var(--text-main)', fontSize: '14px', fontWeight: 700, marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Eye size={15} /> Data Category Breakdown
          </h3>
          <CategoryPie categories={categories} />
        </div>

        {/* Compliance Checks */}
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '14px', padding: '24px' }}>
          <h3 style={{ color: 'var(--text-main)', fontSize: '14px', fontWeight: 700, marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Shield size={15} /> GDPR Compliance
          </h3>
          {privacyScore?.compliance_checks ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {privacyScore.compliance_checks.map(check => (
                <div key={check.check} style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  {check.status === 'pass'
                    ? <CheckCircle size={15} color="#43e97b" />
                    : check.status === 'warn'
                      ? <AlertTriangle size={15} color="#f7971e" />
                      : <XCircle size={15} color="#f64f59" />
                  }
                  <span style={{ fontSize: '12px', color: 'var(--text-secondary)', flex: 1 }}>{check.check}</span>
                  <span style={{
                    fontSize: '10px', fontWeight: 700,
                    color: check.status === 'pass' ? '#43e97b' : check.status === 'warn' ? '#f7971e' : '#f64f59',
                    textTransform: 'uppercase',
                  }}>{check.status}</span>
                </div>
              ))}
            </div>
          ) : (
            <div style={{ color: 'var(--text-muted)', fontSize: '13px' }}>Loading compliance status...</div>
          )}
        </div>
      </div>

      {/* Events Table */}
      <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '14px', overflow: 'hidden' }}>
        <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-main)' }}>Privacy Event Log ({filteredEvents.length})</span>
          <div style={{ display: 'flex', background: 'var(--bg-sidebar)', borderRadius: '8px', padding: '3px', gap: '3px' }}>
            {['all', 'critical', 'blocked', 'unblocked'].map(f => (
              <button key={f} onClick={() => setEvFilter(f)} style={{
                padding: '5px 12px', borderRadius: '5px', border: 'none',
                background: evFilter === f ? 'var(--bg-card)' : 'transparent',
                color: evFilter === f ? 'var(--text-main)' : 'var(--text-secondary)',
                fontSize: '11px', fontWeight: 600, cursor: 'pointer', fontFamily: 'var(--font-primary)',
                textTransform: 'capitalize',
              }}>{f}</button>
            ))}
          </div>
        </div>
        <div style={{ maxHeight: '420px', overflowY: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ background: 'rgba(0,0,0,0.3)', position: 'sticky', top: 0 }}>
                {['Severity', 'Event Type', 'Data Category', 'Device', 'Status', 'Details', 'Time'].map(h => (
                  <th key={h} style={{ padding: '10px 16px', textAlign: 'left', fontSize: '10px', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={7} style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>Loading events...</td></tr>
              ) : filteredEvents.length === 0 ? (
                <tr><td colSpan={7} style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>No privacy events.</td></tr>
              ) : (
                filteredEvents.map(ev => {
                  const sev = SEVERITY_CONFIG[ev.severity] || SEVERITY_CONFIG.low;
                  const catColor = CATEGORY_COLORS[ev.data_category] || 'var(--cyan)';
                  return (
                    <tr key={ev.id} style={{
                      borderBottom: '1px solid rgba(255,255,255,0.04)',
                      background: !ev.is_blocked && (ev.severity === 'critical' || ev.severity === 'high') ? 'rgba(246,79,89,0.03)' : 'transparent',
                    }}>
                      <td style={{ padding: '11px 16px' }}>
                        <span style={{ background: sev.bg, color: sev.color, borderRadius: '20px', padding: '3px 10px', fontSize: '11px', fontWeight: 700, textTransform: 'uppercase' }}>{sev.label}</span>
                      </td>
                      <td style={{ padding: '11px 16px', fontSize: '12px', color: 'var(--text-secondary)' }}>{EVENT_TYPE_LABELS[ev.event_type] || ev.event_type}</td>
                      <td style={{ padding: '11px 16px' }}>
                        <span style={{ background: `${catColor}15`, color: catColor, borderRadius: '20px', padding: '3px 10px', fontSize: '11px', fontWeight: 600 }}>{ev.data_category}</span>
                      </td>
                      <td style={{ padding: '11px 16px', fontSize: '12px', color: 'var(--text-muted)', fontFamily: 'monospace' }}>{ev.device_id || '—'}</td>
                      <td style={{ padding: '11px 16px' }}>
                        {ev.is_blocked
                          ? <span style={{ display: 'flex', alignItems: 'center', gap: '5px', color: '#43e97b', fontSize: '12px' }}><CheckCircle size={13} /> Blocked</span>
                          : <span style={{ display: 'flex', alignItems: 'center', gap: '5px', color: '#f64f59', fontSize: '12px' }}><XCircle size={13} /> Unblocked</span>
                        }
                      </td>
                      <td style={{ padding: '11px 16px', fontSize: '11px', color: 'var(--text-muted)', maxWidth: '200px' }}>
                        {ev.details ? Object.entries(ev.details).slice(0, 2).map(([k, v]) => `${k}: ${v}`).join(' · ') : '—'}
                      </td>
                      <td style={{ padding: '11px 16px', fontSize: '11px', color: 'var(--text-muted)' }}>
                        {ev.timestamp ? new Date(ev.timestamp).toLocaleString() : '—'}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
