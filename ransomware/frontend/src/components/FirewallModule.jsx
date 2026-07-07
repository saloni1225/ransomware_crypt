import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { Shield, Plus, Trash2, ToggleLeft, ToggleRight, ChevronDown, ChevronUp, Activity } from 'lucide-react';

const ACTION_COLOR = { allow: '#43e97b', block: '#f64f59' };
const DIR_COLOR = { inbound: '#00f2fe', outbound: '#a78bfa', both: '#f7971e' };

const RuleRow = ({ rule, onToggle, onDelete }) => {
  const [deleting, setDeleting] = useState(false);
  const isAllow = rule.action === 'allow';

  return (
    <tr style={{
      borderBottom: '1px solid rgba(255,255,255,0.04)',
      background: rule.is_active ? 'transparent' : 'rgba(0,0,0,0.2)',
      opacity: rule.is_active ? 1 : 0.55,
      transition: 'all 0.15s',
    }}>
      {/* Priority */}
      <td style={{ padding: '12px 16px', fontSize: '12px', color: 'var(--text-muted)', fontFamily: 'monospace' }}>#{rule.priority}</td>

      {/* Rule Name */}
      <td style={{ padding: '12px 16px' }}>
        <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-main)' }}>{rule.rule_name}</div>
        {rule.device_id && <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Device: {rule.device_id}</div>}
      </td>

      {/* Direction */}
      <td style={{ padding: '12px 16px' }}>
        <span style={{
          background: `${DIR_COLOR[rule.direction] || 'var(--cyan)'}15`,
          color: DIR_COLOR[rule.direction] || 'var(--cyan)',
          borderRadius: '20px', padding: '3px 10px', fontSize: '11px', fontWeight: 700,
          textTransform: 'capitalize',
        }}>{rule.direction}</span>
      </td>

      {/* Action */}
      <td style={{ padding: '12px 16px' }}>
        <span style={{
          background: `${ACTION_COLOR[rule.action]}15`,
          color: ACTION_COLOR[rule.action],
          borderRadius: '20px', padding: '3px 10px', fontSize: '11px', fontWeight: 700,
          textTransform: 'uppercase',
        }}>{rule.action}</span>
      </td>

      {/* Protocol */}
      <td style={{ padding: '12px 16px', fontSize: '12px', color: 'var(--text-secondary)', fontFamily: 'monospace' }}>{rule.protocol}</td>

      {/* Port */}
      <td style={{ padding: '12px 16px', fontSize: '12px', color: 'var(--text-secondary)', fontFamily: 'monospace' }}>{rule.port || 'any'}</td>

      {/* Remote IP */}
      <td style={{ padding: '12px 16px', fontSize: '12px', color: 'var(--text-muted)', fontFamily: 'monospace' }}>{rule.remote_ip || 'any'}</td>

      {/* Hits */}
      <td style={{ padding: '12px 16px', fontSize: '12px', color: rule.hit_count > 0 ? 'var(--cyan)' : 'var(--text-muted)', fontFamily: 'monospace' }}>
        {rule.hit_count.toLocaleString()}
      </td>

      {/* Toggle */}
      <td style={{ padding: '12px 16px' }}>
        <button onClick={() => onToggle(rule.id)} style={{
          background: 'none', border: 'none', cursor: 'pointer', padding: '4px',
          display: 'flex', alignItems: 'center',
        }}>
          {rule.is_active
            ? <ToggleRight size={26} color="var(--cyan)" />
            : <ToggleLeft size={26} color="var(--text-muted)" />
          }
        </button>
      </td>

      {/* Delete */}
      <td style={{ padding: '12px 16px' }}>
        <button onClick={() => { setDeleting(true); onDelete(rule.id).finally(() => setDeleting(false)); }} style={{
          background: 'rgba(246,79,89,0.08)', border: '1px solid rgba(246,79,89,0.2)',
          borderRadius: '6px', color: '#f64f59', padding: '5px 9px', cursor: 'pointer',
          display: 'flex', alignItems: 'center', opacity: deleting ? 0.5 : 1,
        }}>
          <Trash2 size={13} />
        </button>
      </td>
    </tr>
  );
};

const NewRuleForm = ({ onClose, onCreated }) => {
  const [form, setForm] = useState({ rule_name: '', direction: 'inbound', action: 'block', protocol: 'TCP', port: '', remote_ip: 'any', priority: 100 });
  const [saving, setSaving] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSaving(true);
    try {
      await api.createFirewallRule(form);
      onCreated();
      onClose();
    } catch (err) { console.error(err); }
    finally { setSaving(false); }
  };

  const inputStyle = {
    background: 'var(--bg-sidebar)', border: '1px solid var(--border-color)',
    borderRadius: '8px', color: 'var(--text-main)', padding: '9px 12px',
    fontSize: '13px', fontFamily: 'var(--font-primary)', outline: 'none', width: '100%',
  };

  return (
    <div style={{
      background: 'var(--bg-card)', border: '1px solid var(--border-color)',
      borderRadius: '12px', padding: '24px', marginBottom: '24px',
    }}>
      <h3 style={{ color: 'var(--text-main)', fontSize: '15px', fontWeight: 700, marginBottom: '18px' }}>New Firewall Rule</h3>
      <form onSubmit={handleSubmit}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '14px', marginBottom: '14px' }}>
          <div>
            <label style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600, display: 'block', marginBottom: '6px' }}>RULE NAME</label>
            <input required style={inputStyle} value={form.rule_name} onChange={e => setForm({...form, rule_name: e.target.value})} placeholder="Block RDP" />
          </div>
          <div>
            <label style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600, display: 'block', marginBottom: '6px' }}>DIRECTION</label>
            <select style={inputStyle} value={form.direction} onChange={e => setForm({...form, direction: e.target.value})}>
              <option value="inbound">Inbound</option>
              <option value="outbound">Outbound</option>
              <option value="both">Both</option>
            </select>
          </div>
          <div>
            <label style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600, display: 'block', marginBottom: '6px' }}>ACTION</label>
            <select style={inputStyle} value={form.action} onChange={e => setForm({...form, action: e.target.value})}>
              <option value="block">Block</option>
              <option value="allow">Allow</option>
            </select>
          </div>
          <div>
            <label style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600, display: 'block', marginBottom: '6px' }}>PROTOCOL</label>
            <select style={inputStyle} value={form.protocol} onChange={e => setForm({...form, protocol: e.target.value})}>
              <option>TCP</option><option>UDP</option><option>ICMP</option><option>Any</option>
            </select>
          </div>
          <div>
            <label style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600, display: 'block', marginBottom: '6px' }}>PORT</label>
            <input style={inputStyle} value={form.port} onChange={e => setForm({...form, port: e.target.value})} placeholder="443, 1-1024, any" />
          </div>
          <div>
            <label style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600, display: 'block', marginBottom: '6px' }}>REMOTE IP</label>
            <input style={inputStyle} value={form.remote_ip} onChange={e => setForm({...form, remote_ip: e.target.value})} placeholder="any, 192.168.1.0/24" />
          </div>
        </div>
        <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end' }}>
          <button type="button" onClick={onClose} style={{
            background: 'transparent', border: '1px solid var(--border-color)', borderRadius: '8px',
            color: 'var(--text-secondary)', padding: '9px 20px', fontSize: '13px', cursor: 'pointer', fontFamily: 'var(--font-primary)',
          }}>Cancel</button>
          <button type="submit" disabled={saving} style={{
            background: 'linear-gradient(135deg, var(--primary), var(--cyan))',
            color: '#040810', border: 'none', borderRadius: '8px', padding: '9px 20px',
            fontSize: '13px', fontWeight: 700, cursor: 'pointer', fontFamily: 'var(--font-primary)',
          }}>{saving ? 'Creating...' : 'Create Rule'}</button>
        </div>
      </form>
    </div>
  );
};

export default function FirewallModule() {
  const [rules, setRules] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);

  const load = async () => {
    try {
      const [r, s] = await Promise.all([api.listFirewallRules(), api.getFirewallStats()]);
      setRules(r);
      setStats(s);
    } catch (err) { console.error(err); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  const handleToggle = async (ruleId) => {
    await api.toggleFirewallRule(ruleId);
    load();
  };

  const handleDelete = async (ruleId) => {
    await api.deleteFirewallRule(ruleId);
    load();
  };

  return (
    <div style={{ padding: '32px', maxWidth: '1400px' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '32px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '6px' }}>
            <Shield size={28} color="#f7971e" />
            <h1 style={{ fontSize: '26px', fontWeight: 800, color: 'var(--text-main)', margin: 0 }}>Firewall Module</h1>
          </div>
          <p style={{ color: 'var(--text-secondary)', fontSize: '14px', margin: 0 }}>
            Network access control rules · Block / allow by port, IP, and protocol
          </p>
        </div>
        <button onClick={() => setShowForm(!showForm)} style={{
          background: showForm ? 'rgba(246,79,89,0.1)' : 'linear-gradient(135deg, var(--primary), var(--cyan))',
          color: showForm ? '#f64f59' : '#040810', border: showForm ? '1px solid rgba(246,79,89,0.3)' : 'none',
          borderRadius: '8px', padding: '10px 20px', fontSize: '14px', fontWeight: 700,
          cursor: 'pointer', fontFamily: 'var(--font-primary)',
          display: 'flex', alignItems: 'center', gap: '8px',
        }}>
          {showForm ? <ChevronUp size={16} /> : <Plus size={16} />}
          {showForm ? 'Cancel' : 'Add Rule'}
        </button>
      </div>

      {/* Stats Bar */}
      {stats && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '14px', marginBottom: '24px' }}>
          {[
            { label: 'Total Rules', value: stats.total, color: 'var(--cyan)' },
            { label: 'Active', value: stats.active, color: '#43e97b' },
            { label: 'Block Rules', value: stats.block_rules, color: '#f64f59' },
            { label: 'Allow Rules', value: stats.allow_rules, color: '#43e97b' },
            { label: 'Total Hits', value: stats.total_hits?.toLocaleString(), color: '#a78bfa' },
          ].map(card => (
            <div key={card.label} style={{
              background: 'var(--bg-card)', border: '1px solid var(--border-color)',
              borderRadius: '12px', padding: '16px 20px', borderTop: `2px solid ${card.color}`,
            }}>
              <div style={{ fontSize: '22px', fontWeight: 800, color: 'var(--text-main)' }}>{card.value}</div>
              <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '4px' }}>{card.label}</div>
            </div>
          ))}
        </div>
      )}

      {/* New Rule Form */}
      {showForm && <NewRuleForm onClose={() => setShowForm(false)} onCreated={load} />}

      {/* Rules Table */}
      <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '12px', overflow: 'hidden' }}>
        <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border-color)', display: 'flex', gap: '8px', alignItems: 'center' }}>
          <Activity size={16} color="var(--text-secondary)" />
          <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-main)' }}>Firewall Rules ({rules.length})</span>
        </div>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ background: 'rgba(0,0,0,0.3)' }}>
                {['Pri', 'Rule Name', 'Direction', 'Action', 'Protocol', 'Port', 'Remote IP', 'Hits', 'Active', 'Del'].map(h => (
                  <th key={h} style={{ padding: '10px 16px', textAlign: 'left', fontSize: '10px', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={10} style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>Loading rules...</td></tr>
              ) : rules.length === 0 ? (
                <tr><td colSpan={10} style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>No rules defined. Add one above.</td></tr>
              ) : (
                rules.map(rule => (
                  <RuleRow key={rule.id} rule={rule} onToggle={handleToggle} onDelete={handleDelete} />
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
