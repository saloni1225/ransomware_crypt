import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { FileText, Download, ExternalLink, Calendar, RefreshCw, BarChart2 } from 'lucide-react';

export default function Reports() {
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    loadSummary();
  }, []);

  const loadSummary = async () => {
    setLoading(true);
    try {
      const data = await api.getDashboardSummary();
      setSummary(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleExport = () => {
    const url = api.getExportReportUrl();
    window.open(url, '_blank');
  };

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '32px' }}>
        <div>
          <h1 style={{ fontSize: '28px', fontWeight: 800 }}>Security Analytics & Reports</h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '15px', marginTop: '4px' }}>
            Compile system statuses and export print-ready executive PDF summaries.
          </p>
        </div>
        <button 
          onClick={loadSummary} 
          className="btn-secondary" 
          disabled={loading}
          style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '10px 16px' }}
        >
          <RefreshCw size={16} className={loading ? 'spin-slow' : ''} />
          Reload Analytics
        </button>
      </div>

      {loading || !summary ? (
        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '40vh' }}>
          <div style={{
            border: '3px solid rgba(255,255,255,0.05)',
            borderTop: '3px solid var(--cyan)',
            borderRadius: '50%',
            width: '40px',
            height: '40px',
            animation: 'spin-slow 1s linear infinite'
          }}></div>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          {/* Executive Generator Card */}
          <div className="glass-card" style={{
            background: 'linear-gradient(135deg, rgba(17, 24, 39, 0.9), rgba(11, 16, 27, 0.9))',
            border: '1px solid rgba(0, 242, 254, 0.15)',
            padding: '32px',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            gap: '24px',
            flexWrap: 'wrap'
          }}>
            <div style={{ flex: 1, minWidth: '300px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '12px' }}>
                <FileText size={22} color="var(--cyan)" />
                <h3 style={{ fontSize: '20px', fontWeight: 800 }}>Executive Incident Summary</h3>
              </div>
              <p style={{ color: 'var(--text-secondary)', fontSize: '14.5px', lineHeight: '1.6', maxWidth: '600px' }}>
                Generates a formal, printable report compiling all connected client scores, recent file logs, process anomalies, and deception engine alerts. Ideal for system administrators and compliance reporting.
              </p>
            </div>
            
            <div style={{ display: 'flex', gap: '12px' }}>
              <button 
                onClick={() => window.open(api.getExportReportPdfUrl(), '_blank')}
                className="btn-primary"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  padding: '14px 28px',
                  fontSize: '15px'
                }}
              >
                <Download size={18} />
                Download PDF
              </button>

              <button 
                onClick={handleExport}
                className="btn-secondary"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  padding: '14px 28px',
                  fontSize: '15px'
                }}
              >
                <ExternalLink size={18} />
                Print HTML
              </button>
              
              <button 
                onClick={() => window.open(api.getExportReportCsvUrl(), '_blank')}
                className="btn-secondary"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  padding: '14px 28px',
                  fontSize: '15px'
                }}
              >
                <Download size={18} />
                Export CSV
              </button>
            </div>
          </div>

          {/* Quick Stats Grid */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
            gap: '24px'
          }}>
            <div className="glass-card" style={{ textAlign: 'center' }}>
              <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Average Node Health</span>
              <h4 style={{ fontSize: '32px', fontWeight: 800, marginTop: '10px', color: 'var(--cyan)' }}>{summary.overall_trust_score}%</h4>
              <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '6px' }}>Weighted aggregate trust</p>
            </div>
            
            <div className="glass-card" style={{ textAlign: 'center' }}>
              <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Active Alerts</span>
              <h4 style={{ fontSize: '32px', fontWeight: 800, marginTop: '10px', color: 'var(--severity-high)' }}>{summary.total_threats}</h4>
              <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '6px' }}>Unresolved incidents</p>
            </div>

            <div className="glass-card" style={{ textAlign: 'center' }}>
              <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Critical Triggers</span>
              <h4 style={{ fontSize: '32px', fontWeight: 800, marginTop: '10px', color: 'var(--severity-critical)' }}>{summary.critical_threats}</h4>
              <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '6px' }}>Ransomware detections</p>
            </div>

            <div className="glass-card" style={{ textAlign: 'center' }}>
              <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Total Logged nodes</span>
              <h4 style={{ fontSize: '32px', fontWeight: 800, marginTop: '10px' }}>{summary.total_devices}</h4>
              <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '6px' }}>Registered client hosts</p>
            </div>
          </div>

          {/* Historical Incidents Table */}
          <div className="glass-card">
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '20px' }}>
              <BarChart2 size={18} color="var(--primary)" />
              <h3 style={{ fontSize: '16px', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-secondary)' }}>Security Threat Audit History</h3>
            </div>
            
            <div style={{ overflowX: 'auto' }}>
              {summary.recent_events && summary.recent_events.length > 0 ? (
                <table className="custom-table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Host Node</th>
                      <th>Category</th>
                      <th>Severity</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {summary.recent_events.map((e) => (
                      <tr key={e.id}>
                        <td style={{ color: 'var(--text-secondary)' }}>{new Date(e.timestamp).toLocaleString()}</td>
                        <td style={{ fontWeight: 600 }}>{e.device_id}</td>
                        <td style={{ textTransform: 'uppercase', fontSize: '12px', fontWeight: 700 }}>{e.category}</td>
                        <td>
                          <span className={`badge ${e.severity.toLowerCase()}`}>
                            {e.severity}
                          </span>
                        </td>
                        <td style={{
                          color: e.status === 'active' ? 'var(--severity-critical)' : 'var(--severity-low)',
                          fontWeight: 700,
                          textTransform: 'capitalize'
                        }}>{e.status}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--text-muted)' }}>
                  <p>No historical security logs found.</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
