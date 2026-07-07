import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { Wifi, WifiOff, AlertTriangle, ShieldAlert, RefreshCw, Zap } from 'lucide-react';

const RISK_CONFIG = {
  low: { color: '#43e97b', bg: 'rgba(67,233,123,0.1)', label: 'Low' },
  medium: { color: '#f7971e', bg: 'rgba(247,151,30,0.1)', label: 'Medium' },
  high: { color: '#f64f59', bg: 'rgba(246,79,89,0.12)', label: 'High' },
  critical: { color: '#ff1744', bg: 'rgba(255,23,68,0.15)', label: 'Critical' },
};

const SECURITY_COLORS = {
  WPA3: '#43e97b', 'WPA2-Enterprise': '#43e97b', WPA2: '#00f2fe',
  WPA: '#f7971e', WEP: '#f64f59', Open: '#ff1744',
};

function SignalBars({ strength }) {
  // strength is negative dBm: -30 = excellent, -90 = weak
  const quality = strength > -50 ? 4 : strength > -65 ? 3 : strength > -80 ? 2 : 1;
  return (
    <div style={{ display: 'flex', alignItems: 'flex-end', gap: '2px', height: '18px' }}>
      {[1, 2, 3, 4].map(i => (
        <div key={i} style={{
          width: '5px',
          height: `${i * 4 + 4}px`,
          borderRadius: '2px',
          background: i <= quality ? 'var(--cyan)' : 'rgba(255,255,255,0.12)',
        }} />
      ))}
    </div>
  );
}

function WifiCard({ net }) {
  const risk = RISK_CONFIG[net.risk_level] || RISK_CONFIG.low;
  const secColor = SECURITY_COLORS[net.security_type] || '#a78bfa';

  return (
    <div style={{
      background: 'var(--bg-card)',
      border: `1px solid ${net.is_evil_twin ? '#ff1744' : net.risk_level === 'high' ? 'rgba(246,79,89,0.3)' : 'var(--border-color)'}`,
      borderRadius: '12px', padding: '18px 20px',
      position: 'relative', overflow: 'hidden',
      boxShadow: net.is_evil_twin ? '0 0 20px rgba(255,23,68,0.15)' : 'none',
      transition: 'transform 0.2s, box-shadow 0.2s',
    }}
      onMouseEnter={e => { e.currentTarget.style.transform = 'translateY(-2px)'; e.currentTarget.style.boxShadow = `0 8px 24px rgba(0,0,0,0.3)`; }}
      onMouseLeave={e => { e.currentTarget.style.transform = 'none'; e.currentTarget.style.boxShadow = net.is_evil_twin ? '0 0 20px rgba(255,23,68,0.15)' : 'none'; }}
    >
      {/* Evil Twin Badge */}
      {net.is_evil_twin && (
        <div style={{
          position: 'absolute', top: '10px', right: '10px',
          background: 'rgba(255,23,68,0.15)', color: '#ff1744',
          borderRadius: '20px', padding: '3px 10px', fontSize: '10px',
          fontWeight: 800, letterSpacing: '0.08em', textTransform: 'uppercase',
          border: '1px solid rgba(255,23,68,0.3)',
          display: 'flex', alignItems: 'center', gap: '4px',
        }}>
          <AlertTriangle size={10} /> EVIL TWIN
        </div>
      )}

      {/* Connected Badge */}
      {net.is_connected && (
        <div style={{
          position: 'absolute', top: net.is_evil_twin ? '38px' : '10px', right: '10px',
          background: 'rgba(0,242,254,0.1)', color: 'var(--cyan)',
          borderRadius: '20px', padding: '3px 10px', fontSize: '10px',
          fontWeight: 700, border: '1px solid rgba(0,242,254,0.2)',
        }}>● CONNECTED</div>
      )}

      {/* Icon */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '14px' }}>
        <div style={{
          background: `${risk.color}15`, borderRadius: '10px', padding: '10px',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          {net.risk_level === 'critical' || net.is_evil_twin
            ? <ShieldAlert size={20} color={risk.color} />
            : net.security_type === 'Open'
              ? <WifiOff size={20} color={risk.color} />
              : <Wifi size={20} color={risk.color} />
          }
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{
            fontSize: '15px', fontWeight: 700, color: 'var(--text-main)',
            whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
          }}>{net.ssid}</div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'monospace' }}>{net.bssid}</div>
        </div>
      </div>

      {/* Signal Bars */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
        <SignalBars strength={net.signal_strength} />
        <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{net.signal_strength} dBm · CH {net.channel} · {net.frequency}GHz</span>
      </div>

      {/* Footer */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span style={{
          background: `${secColor}15`, color: secColor,
          borderRadius: '20px', padding: '3px 10px',
          fontSize: '11px', fontWeight: 700,
          border: `1px solid ${secColor}30`,
        }}>{net.security_type}</span>
        <span style={{
          background: risk.bg, color: risk.color,
          borderRadius: '20px', padding: '3px 10px',
          fontSize: '11px', fontWeight: 700,
        }}>{risk.label} Risk</span>
      </div>
    </div>
  );
}

export default function WiFiScanner() {
  const [networks, setNetworks] = useState([]);
  const [stats, setStats] = useState(null);
  const [devices, setDevices] = useState([]);
  const [selectedDevice, setSelectedDevice] = useState('');
  const [scanning, setScanning] = useState(false);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');

  const load = async () => {
    try {
      const [nets, st, devs] = await Promise.all([
        api.listWifiNetworks(),
        api.getWifiStats(),
        api.listDevices(),
      ]);
      setNetworks(nets);
      setStats(st);
      setDevices(devs);
      if (!selectedDevice && devs.length > 0) setSelectedDevice(devs[0].id);
    } catch (err) { console.error(err); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  const handleScan = async () => {
    if (!selectedDevice) return;
    setScanning(true);
    try {
      await api.triggerWifiScan(selectedDevice);
      await load();
    } catch (err) { console.error(err); }
    finally { setScanning(false); }
  };

  const filtered = networks.filter(n => {
    if (filter === 'evil_twin') return n.is_evil_twin;
    if (filter === 'open') return n.security_type === 'Open';
    if (filter === 'high') return n.risk_level === 'high' || n.risk_level === 'critical';
    if (filter === 'connected') return n.is_connected;
    return true;
  });

  const evilTwinCount = networks.filter(n => n.is_evil_twin).length;

  return (
    <div style={{ padding: '32px', maxWidth: '1300px' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '32px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '6px' }}>
            <Wifi size={28} color="var(--primary)" />
            <h1 style={{ fontSize: '26px', fontWeight: 800, color: 'var(--text-main)', margin: 0 }}>Wi-Fi Scanner</h1>
          </div>
          <p style={{ color: 'var(--text-secondary)', fontSize: '14px', margin: 0 }}>
            Nearby network discovery · Evil-twin detection · Security rating
          </p>
        </div>
        <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
          <select value={selectedDevice} onChange={e => setSelectedDevice(e.target.value)} style={{
            background: 'var(--bg-card)', border: '1px solid var(--border-color)',
            borderRadius: '8px', color: 'var(--text-main)', padding: '10px 14px',
            fontSize: '13px', fontFamily: 'var(--font-primary)',
          }}>
            {devices.map(d => <option key={d.id} value={d.id}>{d.hostname}</option>)}
          </select>
          <button onClick={handleScan} disabled={scanning} style={{
            background: 'linear-gradient(135deg, var(--primary), var(--cyan))',
            color: '#040810', border: 'none', borderRadius: '8px', padding: '10px 20px',
            fontSize: '14px', fontWeight: 700, cursor: 'pointer', fontFamily: 'var(--font-primary)',
            display: 'flex', alignItems: 'center', gap: '8px', opacity: scanning ? 0.7 : 1,
          }}>
            {scanning ? <RefreshCw size={16} /> : <Zap size={16} />}
            {scanning ? 'Scanning...' : 'Scan Networks'}
          </button>
        </div>
      </div>

      {/* Evil Twin Alert */}
      {evilTwinCount > 0 && (
        <div style={{
          background: 'rgba(255,23,68,0.08)', border: '1px solid rgba(255,23,68,0.4)',
          borderRadius: '10px', padding: '14px 20px', marginBottom: '24px',
          display: 'flex', alignItems: 'center', gap: '12px',
        }}>
          <ShieldAlert size={20} color="#ff1744" />
          <span style={{ color: '#ff1744', fontWeight: 700, fontSize: '14px' }}>
            ⚠️ {evilTwinCount} Evil Twin network(s) detected nearby! Do not connect.
          </span>
        </div>
      )}

      {/* Stats Row */}
      {stats && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '14px', marginBottom: '28px' }}>
          {[
            { label: 'Total Networks', value: stats.total, color: 'var(--cyan)' },
            { label: 'Safe (WPA2/3)', value: stats.safe, color: '#43e97b' },
            { label: 'High Risk', value: stats.high_risk, color: '#f64f59' },
            { label: 'Evil Twins', value: stats.evil_twin, color: '#ff1744' },
            { label: 'Open Networks', value: stats.open, color: '#f7971e' },
          ].map(card => (
            <div key={card.label} style={{
              background: 'var(--bg-card)', border: '1px solid var(--border-color)',
              borderRadius: '12px', padding: '18px', borderTop: `2px solid ${card.color}`, textAlign: 'center',
            }}>
              <div style={{ fontSize: '26px', fontWeight: 800, color: 'var(--text-main)' }}>{card.value ?? '—'}</div>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '4px' }}>{card.label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Filter */}
      <div style={{ display: 'flex', background: 'var(--bg-sidebar)', borderRadius: '8px', padding: '4px', gap: '4px', marginBottom: '20px', width: 'fit-content' }}>
        {[
          { id: 'all', label: 'All' },
          { id: 'high', label: '🔴 High Risk' },
          { id: 'evil_twin', label: '⚠️ Evil Twin' },
          { id: 'open', label: '🔓 Open' },
          { id: 'connected', label: '✅ Connected' },
        ].map(f => (
          <button key={f.id} onClick={() => setFilter(f.id)} style={{
            padding: '7px 16px', borderRadius: '6px', border: 'none',
            background: filter === f.id ? 'var(--bg-card)' : 'transparent',
            color: filter === f.id ? 'var(--text-main)' : 'var(--text-secondary)',
            fontSize: '12px', fontWeight: 600, cursor: 'pointer', fontFamily: 'var(--font-primary)',
          }}>{f.label}</button>
        ))}
      </div>

      {/* Network Grid */}
      {loading ? (
        <div style={{ textAlign: 'center', padding: '60px', color: 'var(--text-muted)' }}>Scanning networks...</div>
      ) : filtered.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '60px', color: 'var(--text-muted)' }}>No networks found. Run a scan.</div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '16px' }}>
          {filtered.map(net => <WifiCard key={net.id} net={net} />)}
        </div>
      )}
    </div>
  );
}
