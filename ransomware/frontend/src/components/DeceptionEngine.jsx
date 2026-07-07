import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { Crosshair, Plus, AlertTriangle, CheckCircle, Clock, ToggleLeft, ToggleRight, Trash2, Zap } from 'lucide-react';

const ASSET_TYPE_ICONS = {
  file: '📄', credential: '🔑', registry: '🗝️', network_share: '🗂️',
};

const ASSET_TYPE_COLORS = {
  file: '#00f2fe', credential: '#f7971e', registry: '#a78bfa', network_share: '#43e97b',
};

function AssetCard({ asset, devices, onToggle, onDelete, onTrigger }) {
  const [triggering, setTriggering] = useState(false);
  const [selectedDevice, setSelectedDevice] = useState(devices[0]?.id || '');
  const [justTriggered, setJustTriggered] = useState(false);
  const typeColor = ASSET_TYPE_COLORS[asset.asset_type] || 'var(--cyan)';
  const typeIcon = ASSET_TYPE_ICONS[asset.asset_type] || '📁';

  const handleTrigger = async () => {
    if (!selectedDevice) return;
    setTriggering(true);
    try {
      await onTrigger(asset.id, selectedDevice, `simulated_attack_${asset.asset_type}`);
      setJustTriggered(true);
      setTimeout(() => setJustTriggered(false), 4000);
    } finally {
      setTriggering(false);
    }
  };

  return (
    <div style={{
      background: 'var(--bg-card)',
      border: `1px solid ${asset.is_triggered ? 'rgba(246,79,89,0.4)' : 'var(--border-color)'}`,
      borderRadius: '14px', padding: '22px',
      position: 'relative', overflow: 'hidden',
      boxShadow: asset.is_triggered ? '0 0 24px rgba(246,79,89,0.12)' : 'none',
      transition: 'all 0.2s',
      animation: justTriggered ? 'pulseRed 0.5s ease-out' : 'none',
    }}>
      {/* Status Ribbon */}
      <div style={{
        position: 'absolute', top: 0, left: 0, right: 0, height: '3px',
        background: asset.is_triggered
          ? 'linear-gradient(90deg, #f64f59, #ff1744)'
          : asset.is_active
            ? `linear-gradient(90deg, ${typeColor}, ${typeColor}80)`
            : 'rgba(255,255,255,0.1)',
      }} />

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>
        <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
          <div style={{
            background: `${typeColor}18`, borderRadius: '10px',
            padding: '10px', fontSize: '18px', lineHeight: 1,
          }}>{typeIcon}</div>
          <div>
            <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-main)' }}>{asset.asset_name}</div>
            <div style={{ fontSize: '11px', color: typeColor, fontWeight: 600, textTransform: 'capitalize', marginTop: '2px' }}>{asset.asset_type}</div>
          </div>
        </div>

        {/* Toggle */}
        <button onClick={() => onToggle(asset.id)} style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '4px' }}>
          {asset.is_active
            ? <ToggleRight size={24} color="var(--cyan)" />
            : <ToggleLeft size={24} color="var(--text-muted)" />
          }
        </button>
      </div>

      {/* Path */}
      {asset.path && (
        <div style={{
          background: 'rgba(0,0,0,0.25)', borderRadius: '6px', padding: '8px 10px',
          fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'monospace',
          marginBottom: '14px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        }}>{asset.path}</div>
      )}

      {/* Trigger Count */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
        <div style={{ display: 'flex', align: 'center', gap: '8px' }}>
          {asset.is_triggered ? (
            <span style={{ display: 'flex', alignItems: 'center', gap: '5px', color: '#f64f59', fontSize: '12px', fontWeight: 700 }}>
              <AlertTriangle size={14} /> TRIGGERED ({asset.trigger_count}x)
            </span>
          ) : (
            <span style={{ display: 'flex', alignItems: 'center', gap: '5px', color: '#43e97b', fontSize: '12px' }}>
              <CheckCircle size={14} /> Never triggered
            </span>
          )}
        </div>
        {asset.last_triggered && (
          <span style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '11px', color: 'var(--text-muted)' }}>
            <Clock size={11} /> {new Date(asset.last_triggered).toLocaleString()}
          </span>
        )}
      </div>

      {/* Simulate Trigger */}
      {asset.is_active && (
        <div style={{ display: 'flex', gap: '8px' }}>
          <select value={selectedDevice} onChange={e => setSelectedDevice(e.target.value)} style={{
            flex: 1, background: 'var(--bg-sidebar)', border: '1px solid var(--border-color)',
            borderRadius: '7px', color: 'var(--text-main)', padding: '7px 10px',
            fontSize: '12px', fontFamily: 'var(--font-primary)',
          }}>
            {devices.map(d => <option key={d.id} value={d.id}>{d.hostname}</option>)}
          </select>
          <button onClick={handleTrigger} disabled={triggering} style={{
            background: triggering ? 'rgba(246,79,89,0.15)' : 'rgba(246,79,89,0.1)',
            border: '1px solid rgba(246,79,89,0.3)', color: '#f64f59',
            borderRadius: '7px', padding: '7px 14px', fontSize: '12px',
            fontWeight: 700, cursor: 'pointer', fontFamily: 'var(--font-primary)',
            display: 'flex', alignItems: 'center', gap: '5px',
          }}>
            <Zap size={13} /> {triggering ? '...' : 'Trigger'}
          </button>
          <button onClick={() => onDelete(asset.id)} style={{
            background: 'rgba(0,0,0,0.2)', border: '1px solid rgba(255,255,255,0.08)',
            color: 'var(--text-muted)', borderRadius: '7px', padding: '7px 10px',
            cursor: 'pointer', display: 'flex', alignItems: 'center',
          }}>
            <Trash2 size={13} />
          </button>
        </div>
      )}

      {justTriggered && (
        <div style={{
          position: 'absolute', inset: 0, background: 'rgba(246,79,89,0.08)',
          borderRadius: '14px', display: 'flex', alignItems: 'center', justifyContent: 'center',
          pointerEvents: 'none',
        }}>
          <span style={{ fontSize: '28px' }}>🚨</span>
        </div>
      )}
    </div>
  );
}

const DeployModal = ({ devices, onClose, onCreated }) => {
  const [form, setForm] = useState({ asset_name: '', asset_type: 'file', path: '', description: '' });
  const [saving, setSaving] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSaving(true);
    try {
      await api.createDeceptionAsset(form);
      onCreated();
      onClose();
    } finally { setSaving(false); }
  };

  const inputStyle = {
    background: 'var(--bg-sidebar)', border: '1px solid var(--border-color)',
    borderRadius: '8px', color: 'var(--text-main)', padding: '10px 12px',
    fontSize: '13px', fontFamily: 'var(--font-primary)', outline: 'none', width: '100%',
  };

  return (
    <div style={{
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', display: 'flex',
      alignItems: 'center', justifyContent: 'center', zIndex: 100, backdropFilter: 'blur(4px)',
    }}>
      <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '16px', padding: '32px', width: '480px' }}>
        <h2 style={{ color: 'var(--text-main)', fontSize: '18px', fontWeight: 800, marginBottom: '24px' }}>🕵️ Deploy Deception Asset</h2>
        <form onSubmit={handleSubmit}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', marginBottom: '24px' }}>
            <div>
              <label style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600, display: 'block', marginBottom: '6px' }}>ASSET NAME</label>
              <input required style={inputStyle} value={form.asset_name} onChange={e => setForm({...form, asset_name: e.target.value})} placeholder="salary_backup.xlsx" />
            </div>
            <div>
              <label style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600, display: 'block', marginBottom: '6px' }}>TYPE</label>
              <select style={inputStyle} value={form.asset_type} onChange={e => setForm({...form, asset_type: e.target.value})}>
                <option value="file">File</option>
                <option value="credential">Credential (AD Account)</option>
                <option value="registry">Registry Key</option>
                <option value="network_share">Network Share</option>
              </select>
            </div>
            <div>
              <label style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600, display: 'block', marginBottom: '6px' }}>PATH / LOCATION</label>
              <input style={inputStyle} value={form.path} onChange={e => setForm({...form, path: e.target.value})} placeholder="C:\Users\Admin\Documents\decoy.xlsx" />
            </div>
            <div>
              <label style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600, display: 'block', marginBottom: '6px' }}>DESCRIPTION</label>
              <input style={inputStyle} value={form.description} onChange={e => setForm({...form, description: e.target.value})} placeholder="Describe this decoy asset..." />
            </div>
          </div>
          <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end' }}>
            <button type="button" onClick={onClose} style={{ background: 'transparent', border: '1px solid var(--border-color)', borderRadius: '8px', color: 'var(--text-secondary)', padding: '10px 20px', fontSize: '13px', cursor: 'pointer', fontFamily: 'var(--font-primary)' }}>Cancel</button>
            <button type="submit" disabled={saving} style={{ background: 'linear-gradient(135deg, var(--primary), var(--cyan))', color: '#040810', border: 'none', borderRadius: '8px', padding: '10px 20px', fontSize: '13px', fontWeight: 700, cursor: 'pointer', fontFamily: 'var(--font-primary)' }}>
              {saving ? 'Deploying...' : '🚀 Deploy'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default function DeceptionEngine() {
  const [assets, setAssets] = useState([]);
  const [stats, setStats] = useState(null);
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showDeploy, setShowDeploy] = useState(false);

  const load = async () => {
    try {
      const [a, s, devs] = await Promise.all([
        api.listDeceptionAssets(),
        api.getDeceptionStats(),
        api.listDevices(),
      ]);
      setAssets(a);
      setStats(s);
      setDevices(devs);
    } catch (err) { console.error(err); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  const handleToggle = async (id) => { await api.toggleDeceptionAsset(id); load(); };
  const handleDelete = async (id) => { await api.deleteDeceptionAsset ? api.deleteDeceptionAsset(id) : null; load(); };
  const handleTrigger = async (id, deviceId, by) => { await api.triggerDeceptionAsset(id, deviceId, by); load(); };

  return (
    <div style={{ padding: '32px', maxWidth: '1300px' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '32px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '6px' }}>
            <Crosshair size={28} color="#f7971e" />
            <h1 style={{ fontSize: '26px', fontWeight: 800, color: 'var(--text-main)', margin: 0 }}>Deception Engine</h1>
          </div>
          <p style={{ color: 'var(--text-secondary)', fontSize: '14px', margin: 0 }}>
            Honeypot assets · Decoy credentials · Trigger-based threat detection
          </p>
        </div>
        <button onClick={() => setShowDeploy(true)} style={{
          background: 'linear-gradient(135deg, #f7971e, #f64f59)',
          color: '#fff', border: 'none', borderRadius: '8px', padding: '10px 20px',
          fontSize: '14px', fontWeight: 700, cursor: 'pointer', fontFamily: 'var(--font-primary)',
          display: 'flex', alignItems: 'center', gap: '8px',
        }}>
          <Plus size={16} /> Deploy Decoy
        </button>
      </div>

      {/* Stats Row */}
      {stats && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '14px', marginBottom: '28px' }}>
          {[
            { label: 'Total Assets', value: stats.total_assets, color: 'var(--cyan)' },
            { label: 'Active Decoys', value: stats.active_assets, color: '#43e97b' },
            { label: 'Triggered', value: stats.triggered_assets, color: '#f64f59' },
            { label: 'Total Trigger Events', value: stats.total_trigger_events, color: '#f7971e' },
          ].map(c => (
            <div key={c.label} style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '12px', padding: '18px 22px', borderTop: `2px solid ${c.color}` }}>
              <div style={{ fontSize: '26px', fontWeight: 800, color: 'var(--text-main)' }}>{c.value ?? '—'}</div>
              <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '4px' }}>{c.label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Assets Grid */}
      {loading ? (
        <div style={{ textAlign: 'center', padding: '60px', color: 'var(--text-muted)' }}>Loading deception assets...</div>
      ) : assets.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '60px', color: 'var(--text-muted)' }}>No assets deployed. Click "Deploy Decoy" to add honeypots.</div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: '16px' }}>
          {assets.map(asset => (
            <AssetCard key={asset.id} asset={asset} devices={devices} onToggle={handleToggle} onDelete={handleDelete} onTrigger={handleTrigger} />
          ))}
        </div>
      )}

      {showDeploy && <DeployModal devices={devices} onClose={() => setShowDeploy(false)} onCreated={load} />}
    </div>
  );
}
