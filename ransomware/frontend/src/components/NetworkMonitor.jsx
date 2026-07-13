import React, { useState, useEffect, useRef } from 'react';
import { api } from '../services/api';
import { Activity, Globe, AlertTriangle, RefreshCw, Wifi, Zap } from 'lucide-react';

const STATUS_CONFIG = {
  normal: { color: '#43e97b', bg: 'rgba(67,233,123,0.1)', label: 'Normal' },
  suspicious: { color: '#f7971e', bg: 'rgba(247,151,30,0.1)', label: 'Suspicious' },
  c2: { color: '#f64f59', bg: 'rgba(246,79,89,0.12)', label: 'C2 Server' },
  blocked: { color: '#a78bfa', bg: 'rgba(167,139,250,0.1)', label: 'Blocked' },
};

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1073741824) return `${(bytes / 1048576).toFixed(1)} MB`;
  return `${(bytes / 1073741824).toFixed(2)} GB`;
}

const PulsingDot = ({ color }) => (
  <span style={{
    display: 'inline-block', width: '8px', height: '8px',
    borderRadius: '50%', background: color,
    boxShadow: `0 0 6px ${color}`,
    animation: 'pulse 1.5s ease-in-out infinite',
    flexShrink: 0,
  }} />
);

export default function NetworkMonitor() {
  const [connections, setConnections] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');
  const [simulating, setSimulating] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const intervalRef = useRef(null);

  const load = async () => {
    try {
      const [conns, st] = await Promise.all([
        api.listConnections(100),
        api.getNetworkStats(),
      ]);
      setConnections(conns);
      setStats(st);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, []);

  useEffect(() => {
    if (autoRefresh) {
      intervalRef.current = setInterval(load, 3000);
    } else {
      if (intervalRef.current) clearInterval(intervalRef.current);
    }
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [autoRefresh]);

  const handleSimulate = async () => {
    setSimulating(true);
    try {
      await api.simulateConnections();
      await load();
    } catch (err) { console.error(err); }
    finally { setSimulating(false); }
  };

  const filtered = connections.filter(c => filter === 'all' || c.status === filter);
  const threats = connections.filter(c => c.status === 'c2' || c.status === 'suspicious');

  return (
    <div style={{ padding: '32px', maxWidth: '1400px' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '32px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '6px' }}>
            <Activity size={28} color="var(--cyan)" />
            <h1 style={{ fontSize: '26px', fontWeight: 800, color: 'var(--text-main)', margin: 0 }}>Network Monitor</h1>
            {autoRefresh && (
              <span style={{
                background: 'rgba(67,233,123,0.12)', color: '#43e97b',
                borderRadius: '20px', padding: '3px 10px', fontSize: '11px', fontWeight: 700,
                display: 'flex', alignItems: 'center', gap: '5px'
              }}>
                <PulsingDot color="#43e97b" /> LIVE
              </span>
            )}
          </div>
          <p style={{ color: 'var(--text-secondary)', fontSize: '14px', margin: 0 }}>
            Real-time connection analysis · C2 IP blocklist · Port-risk scoring
          </p>
        </div>
        <div style={{ display: 'flex', gap: '10px' }}>
          <button
            onClick={() => setAutoRefresh(r => !r)}
            style={{
              background: autoRefresh ? 'rgba(67,233,123,0.1)' : 'var(--bg-card)',
              color: autoRefresh ? '#43e97b' : 'var(--text-secondary)',
              border: `1px solid ${autoRefresh ? '#43e97b' : 'var(--border-color)'}`,
              borderRadius: '8px', padding: '10px 16px', fontSize: '13px',
              fontWeight: 600, cursor: 'pointer', fontFamily: 'var(--font-primary)',
              display: 'flex', alignItems: 'center', gap: '6px',
            }}
          >
            <RefreshCw size={14} /> {autoRefresh ? 'Auto-refresh ON' : 'Auto-refresh OFF'}
          </button>
          <button
            onClick={handleSimulate}
            disabled={simulating}
            style={{
              background: 'linear-gradient(135deg, var(--primary), var(--cyan))',
              color: '#040810', border: 'none', borderRadius: '8px', padding: '10px 18px',
              fontSize: '13px', fontWeight: 700, cursor: 'pointer', fontFamily: 'var(--font-primary)',
              display: 'flex', alignItems: 'center', gap: '6px', opacity: simulating ? 0.7 : 1,
            }}
          >
            <Zap size={14} /> Load Demo Data
          </button>
        </div>
      </div>

      {/* Alert Banner for C2 */}
      {threats.length > 0 && (
        <div style={{
          background: 'rgba(246,79,89,0.08)', border: '1px solid rgba(246,79,89,0.4)',
          borderRadius: '10px', padding: '14px 20px', marginBottom: '24px',
          display: 'flex', alignItems: 'center', gap: '12px',
        }}>
          <AlertTriangle size={20} color="#f64f59" />
          <span style={{ color: '#f64f59', fontWeight: 700, fontSize: '14px' }}>
            {threats.filter(t => t.status === 'c2').length} C2 connection(s) and {threats.filter(t => t.status === 'suspicious').length} suspicious connection(s) detected!
          </span>
        </div>
      )}

      {/* Stats Cards */}
      {stats && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px', marginBottom: '28px' }}>
          {[
            { label: 'Total Connections', value: stats.total_connections, color: 'var(--cyan)' },
            { label: 'Normal', value: stats.normal, color: '#43e97b' },
            { label: 'Suspicious / C2', value: stats.threat_connections, color: '#f64f59' },
            { label: 'Total Throughput', value: formatBytes((stats.total_bytes_sent || 0) + (stats.total_bytes_recv || 0)), color: '#a78bfa' },
          ].map(card => (
            <div key={card.label} style={{
              background: 'var(--bg-card)', border: '1px solid var(--border-color)',
              borderRadius: '12px', padding: '20px', borderTop: `2px solid ${card.color}`,
            }}>
              <div style={{ fontSize: '24px', fontWeight: 800, color: 'var(--text-main)' }}>{card.value}</div>
              <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '4px' }}>{card.label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Filter Tabs */}
      <div style={{ display: 'flex', background: 'var(--bg-sidebar)', borderRadius: '8px', padding: '4px', gap: '4px', marginBottom: '16px', width: 'fit-content' }}>
        {['all', 'normal', 'suspicious', 'c2', 'blocked'].map(f => (
          <button key={f} onClick={() => setFilter(f)} style={{
            padding: '7px 16px', borderRadius: '6px', border: 'none',
            background: filter === f ? 'var(--bg-card)' : 'transparent',
            color: filter === f ? 'var(--text-main)' : 'var(--text-secondary)',
            fontSize: '12px', fontWeight: 600, cursor: 'pointer', fontFamily: 'var(--font-primary)',
            textTransform: 'capitalize',
          }}>{f === 'c2' ? 'C2 Server' : f}</button>
        ))}
      </div>

      {/* Connections Table */}
      <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '12px', overflow: 'hidden' }}>
        <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between' }}>
          <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-main)' }}>Live Connections ({filtered.length})</span>
          <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Auto-updates every 3s</span>
        </div>
        <div style={{ maxHeight: '500px', overflowY: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead style={{ position: 'sticky', top: 0, zIndex: 1 }}>
              <tr style={{ background: 'rgba(0,0,0,0.4)' }}>
                {['Status', 'Process', 'Remote IP', 'Port', 'Protocol', 'Country', 'Sent', 'Recv', 'Time'].map(h => (
                  <th key={h} style={{
                    padding: '10px 14px', textAlign: 'left',
                    fontSize: '10px', fontWeight: 700, color: 'var(--text-muted)',
                    textTransform: 'uppercase', letterSpacing: '0.06em',
                  }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={9} style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>Loading...</td></tr>
              ) : filtered.length === 0 ? (
                <tr><td colSpan={9} style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>No connections yet. Real agent connections appear here automatically — or load demo data.</td></tr>
              ) : (
                filtered.map(conn => {
                  const conf = STATUS_CONFIG[conn.status] || STATUS_CONFIG.normal;
                  return (
                    <tr key={conn.id} style={{
                      borderBottom: '1px solid rgba(255,255,255,0.04)',
                      background: conn.status === 'c2' ? 'rgba(246,79,89,0.03)' : 'transparent',
                    }}>
                      <td style={{ padding: '10px 14px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '7px' }}>
                          <PulsingDot color={conf.color} />
                          <span style={{ color: conf.color, fontSize: '11px', fontWeight: 700 }}>{conf.label}</span>
                        </div>
                      </td>
                      <td style={{ padding: '10px 14px', fontSize: '12px', color: 'var(--text-main)', fontFamily: 'monospace', fontWeight: 600 }}>{conn.process_name}</td>
                      <td style={{ padding: '10px 14px', fontSize: '12px', color: conn.status === 'c2' ? '#f64f59' : 'var(--text-secondary)', fontFamily: 'monospace' }}>{conn.remote_ip}</td>
                      <td style={{ padding: '10px 14px', fontSize: '12px', color: 'var(--text-secondary)', fontFamily: 'monospace' }}>{conn.remote_port}</td>
                      <td style={{ padding: '10px 14px', fontSize: '11px', color: 'var(--text-muted)' }}>{conn.protocol}</td>
                      <td style={{ padding: '10px 14px', fontSize: '12px', color: 'var(--text-secondary)' }}>{conn.country || '—'}</td>
                      <td style={{ padding: '10px 14px', fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'monospace' }}>{formatBytes(conn.bytes_sent)}</td>
                      <td style={{ padding: '10px 14px', fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'monospace' }}>{formatBytes(conn.bytes_recv)}</td>
                      <td style={{ padding: '10px 14px', fontSize: '11px', color: 'var(--text-muted)' }}>
                        {conn.timestamp ? new Date(conn.timestamp).toLocaleTimeString() : '—'}
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
