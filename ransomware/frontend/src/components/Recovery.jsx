import React, { useState, useEffect, useCallback } from 'react';
import { api } from '../services/api';
import {
  RotateCcw,
  Trash2,
  Shield,
  Clock,
  CheckCircle,
  AlertTriangle,
  FileX,
  RefreshCw,
  ChevronRight,
  Activity,
  Layers,
  Undo2,
  FileLock,
} from 'lucide-react';

// ─── Stat Card ─────────────────────────────────────────────────────────────
function StatCard({ label, value, icon: Icon, color, pulse }) {
  return (
    <div style={{
      background: 'var(--bg-card)',
      border: `1px solid ${color}33`,
      borderRadius: '12px',
      padding: '20px 24px',
      display: 'flex',
      alignItems: 'center',
      gap: '16px',
      position: 'relative',
      overflow: 'hidden',
    }}>
      <div style={{
        width: '44px', height: '44px',
        borderRadius: '10px',
        background: `${color}18`,
        border: `1px solid ${color}44`,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        flexShrink: 0,
      }}>
        <Icon size={20} color={color} />
      </div>
      <div>
        <p style={{ fontSize: '26px', fontWeight: 800, color, margin: 0, lineHeight: 1.1 }}>{value}</p>
        <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: '2px 0 0', fontWeight: 500 }}>{label}</p>
      </div>
      {pulse && (
        <div style={{
          position: 'absolute', top: 12, right: 12,
          width: 8, height: 8, borderRadius: '50%',
          background: color,
          boxShadow: `0 0 6px ${color}`,
          animation: 'pulse 2s infinite',
        }} />
      )}
    </div>
  );
}

// ─── Status badge ──────────────────────────────────────────────────────────
function StatusBadge({ status }) {
  const map = {
    quarantined: { color: '#f59e0b', bg: 'rgba(245,158,11,0.1)', label: 'Quarantined' },
    restored:    { color: '#10b981', bg: 'rgba(16,185,129,0.1)', label: 'Restored' },
    deleted:     { color: '#ef4444', bg: 'rgba(239,68,68,0.1)',  label: 'Deleted' },
    success:     { color: '#10b981', bg: 'rgba(16,185,129,0.1)', label: 'Success' },
    failed:      { color: '#ef4444', bg: 'rgba(239,68,68,0.1)',  label: 'Failed' },
    pending:     { color: '#6366f1', bg: 'rgba(99,102,241,0.1)', label: 'Pending' },
    rollback:    { color: '#8b5cf6', bg: 'rgba(139,92,246,0.1)', label: 'Rollback' },
    delete_permanent: { color: '#ef4444', bg: 'rgba(239,68,68,0.1)', label: 'Deleted' },
    queued:      { color: '#3b82f6', bg: 'rgba(59,130,246,0.1)', label: 'Queued' },
    sent:        { color: '#06b6d4', bg: 'rgba(6,182,212,0.1)', label: 'Sent to Agent' },
    received:    { color: '#a78bfa', bg: 'rgba(167,139,250,0.1)', label: 'Received' },
    started:     { color: '#6366f1', bg: 'rgba(99,102,241,0.1)', label: 'Running...' },
    running:     { color: '#6366f1', bg: 'rgba(99,102,241,0.1)', label: 'Running...' },
  };
  const s = map[status] || map.pending;
  const isProgress = ['queued', 'sent', 'received', 'started', 'running'].includes(status);
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: '6px',
      padding: '3px 10px', borderRadius: '20px',
      background: s.bg, color: s.color,
      fontSize: '11px', fontWeight: 700, letterSpacing: '0.04em',
      textTransform: 'uppercase',
    }}>
      {isProgress && (
        <span style={{
          width: '6px', height: '6px', borderRadius: '50%',
          background: s.color,
          boxShadow: `0 0 6px ${s.color}`,
          animation: 'pulse 1.5s infinite',
        }} />
      )}
      {s.label}
    </span>
  );
}

// ─── Main Component ─────────────────────────────────────────────────────────
export default function Recovery() {
  const [stats, setStats] = useState(null);
  const [quarantined, setQuarantined] = useState([]);
  const [history, setHistory] = useState([]);
  const [activeView, setActiveView] = useState('quarantine'); // 'quarantine' | 'history'
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(null);
  const [toast, setToast] = useState(null);
  const [confirmModal, setConfirmModal] = useState(null); // { type, scanId, fileName }

  const showToast = (msg, type = 'success') => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3500);
  };

  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const [statsData, quarantinedData, historyData] = await Promise.all([
        api.getRecoveryStats(),
        api.listQuarantinedFiles(),
        api.getRecoveryHistory(0, 50),
      ]);
      setStats(statsData);
      setQuarantined(quarantinedData);
      setHistory(historyData);
    } catch (err) {
      if (!silent) showToast('Failed to load recovery data', 'error');
    } finally {
      if (!silent) setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    const activeStatuses = ['queued', 'sent', 'received', 'started', 'running', 'pending', 'restore_pending', 'quarantine_pending'];
    const hasActive =
      quarantined.some(item => activeStatuses.includes(item.status)) ||
      history.some(item => activeStatuses.includes(item.status));

    if (!hasActive) return;

    const interval = setInterval(() => {
      load(true);
    }, 3000);

    return () => clearInterval(interval);
  }, [quarantined, history, load]);

  const handleRestore = async (scanId, filePath) => {
    setConfirmModal({
      type: 'restore',
      scanId,
      fileName: filePath?.split('\\').pop() || filePath,
      action: async () => {
        setActionLoading(scanId);
        try {
          await api.restoreFile(scanId, 'Manually restored via Recovery Center');
          showToast('File successfully restored ✓');
          load();
        } catch (err) {
          showToast('Restore failed: ' + err.message, 'error');
        } finally {
          setActionLoading(null);
        }
      }
    });
  };

  const handleDelete = async (scanId, filePath) => {
    setConfirmModal({
      type: 'delete',
      scanId,
      fileName: filePath?.split('\\').pop() || filePath,
      action: async () => {
        setActionLoading(scanId);
        try {
          await api.deleteFile(scanId, 'Permanently deleted via Recovery Center');
          showToast('File permanently deleted');
          load();
        } catch (err) {
          showToast('Delete failed: ' + err.message, 'error');
        } finally {
          setActionLoading(null);
        }
      }
    });
  };

  const formatDate = (iso) => {
    if (!iso) return '—';
    const d = new Date(iso);
    return d.toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  };

  const formatBytes = (bytes) => {
    if (!bytes) return '—';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const actionTypeIcon = (type) => {
    if (type === 'restore') return <RotateCcw size={13} color="#10b981" />;
    if (type === 'rollback') return <Undo2 size={13} color="#8b5cf6" />;
    if (type === 'delete_permanent') return <Trash2 size={13} color="#ef4444" />;
    return <Activity size={13} color="#6366f1" />;
  };

  return (
    <div style={{ padding: '32px', maxWidth: '1400px', margin: '0 auto' }}>

      {/* ── Toast ── */}
      {toast && (
        <div style={{
          position: 'fixed', top: 20, right: 24, zIndex: 9999,
          background: toast.type === 'error' ? 'rgba(239,68,68,0.12)' : 'rgba(16,185,129,0.12)',
          border: `1px solid ${toast.type === 'error' ? '#ef4444' : '#10b981'}44`,
          color: toast.type === 'error' ? '#ef4444' : '#10b981',
          padding: '12px 20px', borderRadius: '10px',
          fontSize: '13px', fontWeight: 600,
          backdropFilter: 'blur(12px)',
          display: 'flex', alignItems: 'center', gap: '8px',
          animation: 'fadeIn 0.2s ease',
        }}>
          {toast.type === 'error' ? <AlertTriangle size={14} /> : <CheckCircle size={14} />}
          {toast.msg}
        </div>
      )}

      {/* ── Confirm Modal ── */}
      {confirmModal && (
        <div style={{
          position: 'fixed', inset: 0, zIndex: 1000,
          background: 'rgba(4,8,16,0.7)',
          backdropFilter: 'blur(6px)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          <div style={{
            background: 'var(--bg-card)',
            border: `1px solid ${confirmModal.type === 'delete' ? '#ef444444' : '#10b98144'}`,
            borderRadius: '16px', padding: '32px', maxWidth: '420px', width: '90%',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
              {confirmModal.type === 'delete'
                ? <Trash2 size={22} color="#ef4444" />
                : <RotateCcw size={22} color="#10b981" />
              }
              <h3 style={{ color: 'var(--text-main)', margin: 0, fontSize: '18px', fontWeight: 700 }}>
                {confirmModal.type === 'delete' ? 'Permanently Delete File?' : 'Restore File?'}
              </h3>
            </div>
            <p style={{ color: 'var(--text-secondary)', fontSize: '13px', lineHeight: 1.6, marginBottom: '8px' }}>
              {confirmModal.type === 'delete'
                ? 'This action cannot be undone. The file will be marked as permanently removed.'
                : 'The file will be restored from quarantine and marked as clean.'
              }
            </p>
            <p style={{
              background: 'rgba(255,255,255,0.04)', borderRadius: '8px',
              padding: '10px 14px', fontSize: '12px', color: 'var(--text-muted)',
              fontFamily: 'monospace', wordBreak: 'break-all', margin: '0 0 24px',
            }}>
              {confirmModal.fileName}
            </p>
            <div style={{ display: 'flex', gap: '12px' }}>
              <button
                onClick={() => setConfirmModal(null)}
                style={{
                  flex: 1, padding: '10px', borderRadius: '8px',
                  border: '1px solid var(--border-color)',
                  background: 'transparent', color: 'var(--text-secondary)',
                  cursor: 'pointer', fontFamily: 'var(--font-primary)',
                  fontSize: '13px', fontWeight: 600,
                }}
              >Cancel</button>
              <button
                onClick={async () => { setConfirmModal(null); await confirmModal.action(); }}
                style={{
                  flex: 1, padding: '10px', borderRadius: '8px',
                  border: 'none',
                  background: confirmModal.type === 'delete'
                    ? 'linear-gradient(135deg, #ef4444, #dc2626)'
                    : 'linear-gradient(135deg, #10b981, #059669)',
                  color: '#fff', cursor: 'pointer',
                  fontFamily: 'var(--font-primary)',
                  fontSize: '13px', fontWeight: 700,
                }}
              >
                {confirmModal.type === 'delete' ? 'Delete Permanently' : 'Confirm Restore'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Page Header ── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '32px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '6px' }}>
            <div style={{
              background: 'linear-gradient(135deg, rgba(16,185,129,0.2), rgba(6,182,212,0.2))',
              border: '1px solid rgba(16,185,129,0.3)',
              borderRadius: '10px', padding: '8px',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <Shield size={20} color="#10b981" />
            </div>
            <h1 style={{ fontSize: '24px', fontWeight: 800, color: 'var(--text-main)', margin: 0 }}>
              Recovery & Rollback Center
            </h1>
          </div>
          <p style={{ color: 'var(--text-muted)', margin: 0, fontSize: '13px' }}>
            Manage quarantined files, restore clean items, and audit remediation actions
          </p>
        </div>
        <button
          id="recovery-refresh-btn"
          onClick={load}
          disabled={loading}
          style={{
            display: 'flex', alignItems: 'center', gap: '8px',
            padding: '10px 18px', borderRadius: '8px',
            background: 'transparent',
            border: '1px solid var(--border-color)',
            color: 'var(--text-secondary)', cursor: 'pointer',
            fontFamily: 'var(--font-primary)', fontSize: '13px', fontWeight: 600,
            transition: 'var(--transition)',
          }}
          onMouseEnter={e => { e.currentTarget.style.borderColor = '#10b981'; e.currentTarget.style.color = '#10b981'; }}
          onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border-color)'; e.currentTarget.style.color = 'var(--text-secondary)'; }}
        >
          <RefreshCw size={14} style={{ animation: loading ? 'spin 1s linear infinite' : 'none' }} />
          {loading ? 'Refreshing…' : 'Refresh'}
        </button>
      </div>

      {/* ── Stat Cards ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px', marginBottom: '32px' }}>
        <StatCard
          label="Files in Quarantine"
          value={stats?.quarantined_files ?? '—'}
          icon={FileLock}
          color="#f59e0b"
          pulse={stats?.quarantined_files > 0}
        />
        <StatCard
          label="Files Restored"
          value={stats?.restored_files ?? '—'}
          icon={RotateCcw}
          color="#10b981"
        />
        <StatCard
          label="Permanently Deleted"
          value={stats?.deleted_files ?? '—'}
          icon={Trash2}
          color="#ef4444"
        />
        <StatCard
          label="Total Actions Taken"
          value={stats?.total_actions ?? '—'}
          icon={Layers}
          color="#6366f1"
        />
      </div>

      {/* ── Tab Navigation ── */}
      <div style={{
        display: 'flex', gap: '4px', background: 'var(--bg-card)',
        border: '1px solid var(--border-color)', borderRadius: '10px',
        padding: '4px', marginBottom: '24px', width: 'fit-content',
      }}>
        {[
          { id: 'quarantine', label: 'Quarantine Queue', icon: FileX },
          { id: 'history', label: 'Recovery History', icon: Clock },
        ].map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            id={`recovery-tab-${id}`}
            onClick={() => setActiveView(id)}
            style={{
              display: 'flex', alignItems: 'center', gap: '8px',
              padding: '8px 18px', borderRadius: '7px', border: 'none',
              background: activeView === id ? 'rgba(16,185,129,0.12)' : 'transparent',
              color: activeView === id ? '#10b981' : 'var(--text-muted)',
              cursor: 'pointer', fontFamily: 'var(--font-primary)',
              fontSize: '13px', fontWeight: activeView === id ? 700 : 500,
              transition: 'var(--transition)',
              boxShadow: activeView === id ? 'inset 0 0 0 1px rgba(16,185,129,0.2)' : 'none',
            }}
          >
            <Icon size={14} />
            {label}
            {id === 'quarantine' && quarantined.length > 0 && (
              <span style={{
                background: '#f59e0b', color: '#040810',
                borderRadius: '20px', padding: '1px 7px',
                fontSize: '10px', fontWeight: 800,
              }}>{quarantined.length}</span>
            )}
          </button>
        ))}
      </div>

      {/* ── Quarantine Queue ── */}
      {activeView === 'quarantine' && (
        <div style={{
          background: 'var(--bg-card)',
          border: '1px solid var(--border-color)',
          borderRadius: '12px', overflow: 'hidden',
        }}>
          {quarantined.length === 0 ? (
            <div style={{
              padding: '64px 32px', textAlign: 'center',
              display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '12px',
            }}>
              <div style={{
                width: '56px', height: '56px', borderRadius: '14px',
                background: 'rgba(16,185,129,0.08)',
                border: '1px solid rgba(16,185,129,0.2)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}>
                <CheckCircle size={24} color="#10b981" />
              </div>
              <h3 style={{ color: 'var(--text-main)', margin: 0, fontSize: '16px', fontWeight: 700 }}>
                No Files in Quarantine
              </h3>
              <p style={{ color: 'var(--text-muted)', margin: 0, fontSize: '13px' }}>
                All detected threats have been resolved. Run a malware scan to populate this queue.
              </p>
            </div>
          ) : (
            <>
              {/* Table Header */}
              <div style={{
                display: 'grid',
                gridTemplateColumns: '3fr 1fr 1fr 1fr 1fr auto',
                padding: '14px 20px',
                borderBottom: '1px solid var(--border-color)',
                background: 'rgba(255,255,255,0.02)',
              }}>
                {['File Path', 'Threat', 'Size', 'Scan Time', 'Status', 'Actions'].map(h => (
                  <span key={h} style={{
                    fontSize: '11px', fontWeight: 700, color: 'var(--text-muted)',
                    textTransform: 'uppercase', letterSpacing: '0.06em',
                  }}>{h}</span>
                ))}
              </div>

              {/* Table Rows */}
              {quarantined.map((file, i) => (
                <div
                  key={file.id}
                  style={{
                    display: 'grid',
                    gridTemplateColumns: '3fr 1fr 1fr 1fr 1fr auto',
                    padding: '16px 20px',
                    borderBottom: i < quarantined.length - 1 ? '1px solid var(--border-color)' : 'none',
                    alignItems: 'center',
                    transition: 'var(--transition)',
                  }}
                  onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.02)'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  {/* File Path */}
                  <div>
                    <p style={{
                      color: 'var(--text-main)', margin: 0, fontSize: '13px',
                      fontWeight: 600, fontFamily: 'monospace',
                      overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                      maxWidth: '320px',
                    }} title={file.file_path}>
                      {file.file_path}
                    </p>
                    <p style={{ color: 'var(--text-muted)', margin: '2px 0 0', fontSize: '11px' }}>
                      Device: {file.device_id}
                    </p>
                  </div>

                  {/* Threat Name */}
                  <span style={{
                    color: '#ef4444', fontSize: '12px', fontWeight: 600,
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                    maxWidth: '140px',
                  }} title={file.threat_name || '—'}>
                    {file.threat_name || '—'}
                  </span>

                  {/* Size */}
                  <span style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>
                    {formatBytes(file.file_size)}
                  </span>

                  {/* Scan Time */}
                  <span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>
                    {formatDate(file.scan_time)}
                  </span>

                  {/* Status */}
                  <StatusBadge status={file.status} />

                  {/* Actions */}
                  <div style={{ display: 'flex', gap: '8px' }}>
                    <button
                      id={`restore-btn-${file.id}`}
                      onClick={() => handleRestore(file.id, file.file_path)}
                      disabled={actionLoading === file.id}
                      title="Restore file from quarantine"
                      style={{
                        display: 'flex', alignItems: 'center', gap: '5px',
                        padding: '6px 12px', borderRadius: '6px', border: 'none',
                        background: 'rgba(16,185,129,0.1)',
                        color: '#10b981', cursor: 'pointer',
                        fontFamily: 'var(--font-primary)',
                        fontSize: '12px', fontWeight: 600,
                        transition: 'var(--transition)',
                      }}
                      onMouseEnter={e => e.currentTarget.style.background = 'rgba(16,185,129,0.2)'}
                      onMouseLeave={e => e.currentTarget.style.background = 'rgba(16,185,129,0.1)'}
                    >
                      <RotateCcw size={12} />
                      Restore
                    </button>
                    <button
                      id={`delete-btn-${file.id}`}
                      onClick={() => handleDelete(file.id, file.file_path)}
                      disabled={actionLoading === file.id}
                      title="Permanently delete file"
                      style={{
                        display: 'flex', alignItems: 'center', gap: '5px',
                        padding: '6px 10px', borderRadius: '6px', border: 'none',
                        background: 'rgba(239,68,68,0.08)',
                        color: '#ef4444', cursor: 'pointer',
                        fontFamily: 'var(--font-primary)',
                        fontSize: '12px', fontWeight: 600,
                        transition: 'var(--transition)',
                      }}
                      onMouseEnter={e => e.currentTarget.style.background = 'rgba(239,68,68,0.2)'}
                      onMouseLeave={e => e.currentTarget.style.background = 'rgba(239,68,68,0.08)'}
                    >
                      <Trash2 size={12} />
                    </button>
                  </div>
                </div>
              ))}
            </>
          )}
        </div>
      )}

      {/* ── Recovery History ── */}
      {activeView === 'history' && (
        <div style={{
          background: 'var(--bg-card)',
          border: '1px solid var(--border-color)',
          borderRadius: '12px', overflow: 'hidden',
        }}>
          {history.length === 0 ? (
            <div style={{ padding: '64px 32px', textAlign: 'center' }}>
              <Clock size={40} color="var(--text-muted)" style={{ marginBottom: '12px' }} />
              <h3 style={{ color: 'var(--text-main)', margin: '0 0 6px' }}>No Recovery Actions Yet</h3>
              <p style={{ color: 'var(--text-muted)', margin: 0, fontSize: '13px' }}>
                Actions will appear here once you restore or delete quarantined files.
              </p>
            </div>
          ) : (
            <>
              {/* Table header */}
              <div style={{
                display: 'grid',
                gridTemplateColumns: '2fr 1fr 2fr 1fr 1fr',
                padding: '14px 20px',
                borderBottom: '1px solid var(--border-color)',
                background: 'rgba(255,255,255,0.02)',
              }}>
                {['File / Target', 'Action', 'Performed By', 'Status', 'Timestamp'].map(h => (
                  <span key={h} style={{
                    fontSize: '11px', fontWeight: 700, color: 'var(--text-muted)',
                    textTransform: 'uppercase', letterSpacing: '0.06em',
                  }}>{h}</span>
                ))}
              </div>

              {history.map((action, i) => (
                <div
                  key={action.id}
                  style={{
                    display: 'grid',
                    gridTemplateColumns: '2fr 1fr 2fr 1fr 1fr',
                    padding: '14px 20px',
                    borderBottom: i < history.length - 1 ? '1px solid var(--border-color)' : 'none',
                    alignItems: 'center',
                    transition: 'var(--transition)',
                  }}
                  onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.02)'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  {/* File Path */}
                  <span style={{
                    fontSize: '12px', color: 'var(--text-main)',
                    fontFamily: 'monospace', overflow: 'hidden',
                    textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '260px',
                  }} title={action.file_path || 'Threat Event Rollback'}>
                    {action.file_path || 'Threat Event Rollback'}
                  </span>

                  {/* Action Type */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    {actionTypeIcon(action.action_type)}
                    <span style={{ fontSize: '12px', color: 'var(--text-secondary)', textTransform: 'capitalize' }}>
                      {action.action_type?.replace('_', ' ')}
                    </span>
                  </div>

                  {/* Performed by */}
                  <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                    {action.performed_by || '—'}
                  </span>

                  {/* Status */}
                  <StatusBadge status={action.status} />

                  {/* Timestamp */}
                  <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                    {formatDate(action.timestamp)}
                  </span>
                </div>
              ))}
            </>
          )}
        </div>
      )}

      <style>{`
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(-6px); } to { opacity: 1; transform: translateY(0); } }
      `}</style>
    </div>
  );
}
