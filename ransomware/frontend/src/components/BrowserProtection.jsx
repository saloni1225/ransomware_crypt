import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { 
  Globe, 
  Shield, 
  ShieldAlert, 
  ShieldCheck,
  AlertTriangle, 
  CheckCircle2, 
  XCircle, 
  Search, 
  Terminal,
  Activity,
  Compass,
  ArrowRight,
  ExternalLink
} from 'lucide-react';

const SEVERITY_CONFIG = {
  critical: { color: '#ff1744', bg: 'rgba(255,23,68,0.12)', label: 'Critical' },
  high: { color: '#f64f59', bg: 'rgba(246,79,89,0.1)', label: 'High' },
  medium: { color: '#f7971e', bg: 'rgba(247,151,30,0.1)', label: 'Medium' },
  low: { color: '#43e97b', bg: 'rgba(67,233,123,0.1)', label: 'Low' },
};

const EVENT_TYPE_LABELS = {
  phishing: '🔗 Phishing Attempt',
  fake_login: '👤 Fake Login Portal',
  malicious_download: '💾 Malicious Download',
  suspicious_domain: '🌐 Suspicious Domain',
};

function RiskGauge({ score }) {
  const radius = 65;
  const circumference = Math.PI * radius; // Half-circle gauge
  const pct = score / 100;
  const progress = pct * circumference;
  
  // Decide color based on score
  let color = '#43e97b'; // Green
  let statusLabel = 'SECURE';
  if (score >= 40 && score < 75) {
    color = '#f7971e'; // Orange
    statusLabel = 'WARNING';
  } else if (score >= 75) {
    color = '#f64f59'; // Red
    statusLabel = 'DANGER';
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '16px 0' }}>
      <svg width="160" height="90" viewBox="0 0 160 90">
        {/* Outer path track */}
        <path
          d="M 15 80 A 65 65 0 0 1 145 80"
          fill="none"
          stroke="rgba(255,255,255,0.06)"
          strokeWidth="12"
          strokeLinecap="round"
        />
        {/* Animated outer path progress */}
        <path
          d="M 15 80 A 65 65 0 0 1 145 80"
          fill="none"
          stroke={color}
          strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={`${progress} ${circumference}`}
          style={{ 
            filter: `drop-shadow(0 0 6px ${color}90)`, 
            transition: 'stroke-dasharray 0.8s cubic-bezier(0.4, 0, 0.2, 1)' 
          }}
        />
        {/* Score/Label Text */}
        <text x="80" y="70" textAnchor="middle" fill="var(--text-main)" fontSize="28" fontWeight="800" fontFamily="Inter, sans-serif">
          {score}
        </text>
        <text x="80" y="85" textAnchor="middle" fill={color} fontSize="10" fontWeight="700" letterSpacing="0.08em" fontFamily="Inter, sans-serif">
          {statusLabel}
        </text>
      </svg>
      <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '6px', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
        Average Threat Level
      </div>
    </div>
  );
}

export default function BrowserProtection() {
  const [events, setEvents] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [evFilter, setEvFilter] = useState('all');
  
  // URL Risk Analyzer State
  const [urlToCheck, setUrlToCheck] = useState('');
  const [analysisResult, setAnalysisResult] = useState(null);
  const [checkingUrl, setCheckingUrl] = useState(false);
  const [checkError, setCheckError] = useState('');

  const loadData = async () => {
    try {
      const [evs, st] = await Promise.all([
        api.listBrowserEvents(100),
        api.getBrowserStats()
      ]);
      setEvents(evs);
      setStats(st);
    } catch (err) {
      console.error('Failed to load browser protection data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleCheckUrl = async (e) => {
    e.preventDefault();
    if (!urlToCheck.trim()) return;

    setCheckingUrl(true);
    setCheckError('');
    setAnalysisResult(null);

    try {
      const res = await api.checkUrlSafety(urlToCheck);
      setAnalysisResult(res);
    } catch (err) {
      setCheckError('Failed to analyze URL. Please check back end connection.');
    } finally {
      setCheckingUrl(false);
    }
  };

  const getRiskLabel = (score) => {
    if (score >= 80) return 'critical';
    if (score >= 50) return 'high';
    if (score >= 25) return 'medium';
    return 'low';
  };

  const filteredEvents = events.filter(e => {
    if (evFilter === 'blocked') return e.is_blocked;
    if (evFilter === 'allowed') return !e.is_blocked;
    if (evFilter === 'malicious') return e.risk_score >= 50;
    return true;
  });

  return (
    <div style={{ padding: '32px', maxWidth: '1300px', margin: '0 auto', color: 'var(--text-main)' }}>
      {/* Header */}
      <div style={{ marginBottom: '32px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '6px' }}>
          <Globe size={28} color="var(--cyan)" style={{ filter: 'drop-shadow(0 0 8px var(--cyan))' }} />
          <h1 style={{ fontSize: '26px', fontWeight: 800, margin: 0, letterSpacing: '-0.02em' }}>Browser Protection Center</h1>
        </div>
        <p style={{ color: 'var(--text-secondary)', fontSize: '14px', margin: 0 }}>
          Real-time protection against phishing, fake login pages, malicious downloads, and suspicious command injections.
        </p>
      </div>

      {/* Grid containing Stats Gauge, Quick Facts, and URL Scanner */}
      <div style={{ display: 'grid', gridTemplateColumns: '300px 1fr', gap: '24px', marginBottom: '28px' }}>
        
        {/* Left Side: Score Widget & General Stats */}
        <div style={{ 
          background: 'var(--bg-card)', 
          border: '1px solid var(--border-color)', 
          borderRadius: '16px', 
          padding: '24px',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
          gap: '16px'
        }}>
          <div>
            <h3 style={{ fontSize: '14px', fontWeight: 700, margin: '0 0 16px 0', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Activity size={16} color="var(--cyan)" /> Web Posture
            </h3>
            {stats ? (
              <RiskGauge score={stats.average_risk_score} />
            ) : (
              <div style={{ height: '90px', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)' }}>Loading...</div>
            )}
          </div>

          {stats && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
              {[
                { label: 'Total Events', value: stats.total_events, color: 'var(--cyan)' },
                { label: 'Blocked Attacks', value: stats.blocked_count, color: '#43e97b' },
                { label: 'Phishing Pages', value: stats.phishing_count, color: '#f7971e' },
                { label: 'Malicious Files', value: stats.malicious_download_count, color: '#f64f59' }
              ].map((s, idx) => (
                <div key={idx} style={{ 
                  background: 'rgba(0,0,0,0.18)', 
                  borderRadius: '10px', 
                  padding: '12px', 
                  textAlign: 'center',
                  border: '1px solid rgba(255,255,255,0.03)'
                }}>
                  <div style={{ fontSize: '20px', fontWeight: 800, color: s.color }}>{s.value}</div>
                  <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '4px', textTransform: 'uppercase', fontWeight: 600 }}>{s.label}</div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right Side: URL Checker Input & Analysis Result */}
        <div style={{ 
          background: 'var(--bg-card)', 
          border: '1px solid var(--border-color)', 
          borderRadius: '16px', 
          padding: '24px',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between'
        }}>
          <div>
            <h3 style={{ fontSize: '14px', fontWeight: 700, margin: '0 0 8px 0', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Compass size={16} color="var(--cyan)" /> Web URL Scanner & Threat Heuristics
            </h3>
            <p style={{ color: 'var(--text-muted)', fontSize: '12px', margin: '0 0 20px 0' }}>
              Manually inspect any web address to test RDS defense rules. Check domains for typosquatting, unauthorized ports, and known phishing patterns.
            </p>

            <form onSubmit={handleCheckUrl} style={{ display: 'flex', gap: '10px', marginBottom: '20px' }}>
              <div style={{ position: 'relative', flex: 1 }}>
                <Search size={16} color="var(--text-muted)" style={{ position: 'absolute', left: '14px', top: '50%', transform: 'translateY(-50%)' }} />
                <input
                  type="text"
                  placeholder="Enter website URL to scan (e.g., http://login-secure-paypal.com/verify)"
                  value={urlToCheck}
                  onChange={(e) => setUrlToCheck(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '12px 16px 12px 40px',
                    borderRadius: '10px',
                    border: '1px solid var(--border-color)',
                    background: 'var(--bg-sidebar)',
                    color: 'white',
                    fontSize: '13px',
                    outline: 'none',
                    transition: 'border-color 0.2s',
                    fontFamily: 'var(--font-primary)'
                  }}
                  onFocus={(e) => e.target.style.borderColor = 'var(--cyan)'}
                  onBlur={(e) => e.target.style.borderColor = 'var(--border-color)'}
                />
              </div>
              <button
                type="submit"
                disabled={checkingUrl}
                style={{
                  padding: '0 24px',
                  borderRadius: '10px',
                  border: 'none',
                  background: 'var(--cyan)',
                  color: 'black',
                  fontWeight: 700,
                  fontSize: '13px',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  opacity: checkingUrl ? 0.7 : 1,
                  transition: 'opacity 0.2s'
                }}
              >
                {checkingUrl ? 'Analyzing...' : 'Scan URL'}
                <ArrowRight size={14} />
              </button>
            </form>
          </div>

          {/* Results display */}
          <div style={{ flex: 1, display: 'flex', alignItems: 'center' }}>
            {checkError && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#f64f59', fontSize: '13px' }}>
                <AlertTriangle size={16} /> {checkError}
              </div>
            )}

            {analysisResult && (
              <div style={{ 
                width: '100%', 
                background: 'rgba(0,0,0,0.2)', 
                borderRadius: '12px', 
                border: `1px solid ${analysisResult.is_blocked ? '#f64f5924' : '#43e97b24'}`,
                padding: '16px',
                display: 'grid',
                gridTemplateColumns: '1fr 200px',
                gap: '20px',
                alignItems: 'center'
              }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                    {analysisResult.is_blocked ? (
                      <span style={{ 
                        background: 'rgba(246,79,89,0.12)', 
                        color: '#f64f59', 
                        padding: '4px 10px', 
                        borderRadius: '20px', 
                        fontSize: '11px', 
                        fontWeight: 800,
                        display: 'flex',
                        alignItems: 'center',
                        gap: '4px'
                      }}>
                        <ShieldAlert size={12} /> MALICIOUS / BLOCKED
                      </span>
                    ) : (
                      <span style={{ 
                        background: 'rgba(67,233,123,0.12)', 
                        color: '#43e97b', 
                        padding: '4px 10px', 
                        borderRadius: '20px', 
                        fontSize: '11px', 
                        fontWeight: 800,
                        display: 'flex',
                        alignItems: 'center',
                        gap: '4px'
                      }}>
                        <ShieldCheck size={12} /> CLEAN / VERIFIED
                      </span>
                    )}
                    <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                      Domain: {analysisResult.domain}
                    </span>
                  </div>

                  <div style={{ fontSize: '13px', color: 'white', fontWeight: 600, wordBreak: 'break-all', marginBottom: '8px' }}>
                    {analysisResult.url}
                  </div>

                  {analysisResult.reasons.length > 0 && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', marginTop: '10px' }}>
                      {analysisResult.reasons.map((r, i) => (
                        <div key={i} style={{ fontSize: '11px', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <span style={{ color: '#f7971e' }}>•</span> {r}
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                <div style={{ textAlign: 'center', borderLeft: '1px solid rgba(255,255,255,0.06)', paddingLeft: '20px' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Computed Risk Score</div>
                  <div style={{ 
                    fontSize: '36px', 
                    fontWeight: 900, 
                    color: analysisResult.risk_score >= 75 ? '#f64f59' : analysisResult.risk_score >= 40 ? '#f7971e' : '#43e97b',
                    margin: '4px 0'
                  }}>
                    {analysisResult.risk_score}
                  </div>
                  <div style={{ 
                    fontSize: '10px', 
                    fontWeight: 700, 
                    color: analysisResult.risk_score >= 50 ? '#f64f59' : 'var(--text-muted)' 
                  }}>
                    {analysisResult.risk_score >= 50 ? 'BLOCK ADVISORY' : 'ALLOW ACCESSIBLE'}
                  </div>
                </div>
              </div>
            )}

            {!analysisResult && !checkingUrl && !checkError && (
              <div style={{ color: 'var(--text-muted)', fontSize: '12px', textAlign: 'center', width: '100%', padding: '20px 0' }}>
                Enter a URL above to inspect heuristics analysis and rule configurations.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Events Table Container */}
      <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '16px', overflow: 'hidden' }}>
        
        {/* Table Header Controls */}
        <div style={{ padding: '16px 24px', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Terminal size={16} color="var(--cyan)" />
            <span style={{ fontSize: '13px', fontWeight: 700 }}>Intrusion Prevention Logs ({filteredEvents.length})</span>
          </div>
          <div style={{ display: 'flex', background: 'var(--bg-sidebar)', borderRadius: '8px', padding: '3px', gap: '3px' }}>
            {[
              { id: 'all', name: 'All' },
              { id: 'blocked', name: 'Blocked' },
              { id: 'allowed', name: 'Allowed' },
              { id: 'malicious', name: 'High Risk' }
            ].map(f => (
              <button 
                key={f.id} 
                onClick={() => setEvFilter(f.id)} 
                style={{
                  padding: '5px 12px', 
                  borderRadius: '5px', 
                  border: 'none',
                  background: evFilter === f.id ? 'var(--bg-card)' : 'transparent',
                  color: evFilter === f.id ? 'var(--text-main)' : 'var(--text-secondary)',
                  fontSize: '11px', 
                  fontWeight: 600, 
                  cursor: 'pointer', 
                  fontFamily: 'var(--font-primary)'
                }}
              >
                {f.name}
              </button>
            ))}
          </div>
        </div>

        {/* Table Body */}
        <div style={{ maxHeight: '420px', overflowY: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ background: 'rgba(0,0,0,0.3)', position: 'sticky', top: 0, zIndex: 1 }}>
                {['Risk Level', 'Type', 'Domain / Host', 'Action Taken', 'Device ID', 'Incident Details', 'Time Detected'].map(h => (
                  <th key={h} style={{ 
                    padding: '12px 20px', 
                    textAlign: 'left', 
                    fontSize: '10px', 
                    fontWeight: 700, 
                    color: 'var(--text-muted)', 
                    textTransform: 'uppercase', 
                    letterSpacing: '0.06em' 
                  }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={7} style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>Loading events...</td></tr>
              ) : filteredEvents.length === 0 ? (
                <tr><td colSpan={7} style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>No browser events match the filter.</td></tr>
              ) : (
                filteredEvents.map(ev => {
                  const riskLevel = getRiskLabel(ev.risk_score);
                  const sev = SEVERITY_CONFIG[riskLevel];
                  return (
                    <tr key={ev.id} style={{
                      borderBottom: '1px solid rgba(255,255,255,0.04)',
                      background: !ev.is_blocked && ev.risk_score >= 50 ? 'rgba(246,79,89,0.03)' : 'transparent',
                      transition: 'background-color 0.2s',
                    }}
                    onMouseEnter={(e) => e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.015)'}
                    onMouseLeave={(e) => e.currentTarget.style.backgroundColor = !ev.is_blocked && ev.risk_score >= 50 ? 'rgba(246,79,89,0.03)' : 'transparent'}
                    >
                      {/* Risk Level Badge */}
                      <td style={{ padding: '12px 20px' }}>
                        <span style={{ 
                          background: sev.bg, 
                          color: sev.color, 
                          borderRadius: '20px', 
                          padding: '3px 10px', 
                          fontSize: '10px', 
                          fontWeight: 800, 
                          textTransform: 'uppercase' 
                        }}>
                          {sev.label} ({ev.risk_score})
                        </span>
                      </td>

                      {/* Type */}
                      <td style={{ padding: '12px 20px', fontSize: '12px', color: 'var(--text-secondary)', fontWeight: 500 }}>
                        {EVENT_TYPE_LABELS[ev.event_type] || ev.event_type}
                      </td>

                      {/* Domain / Link */}
                      <td style={{ padding: '12px 20px', fontSize: '12px', color: 'white' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <span style={{ fontFamily: 'monospace', color: 'var(--cyan)' }}>{ev.domain}</span>
                          <a href={ev.url} target="_blank" rel="noreferrer" style={{ color: 'var(--text-muted)', display: 'inline-flex' }}>
                            <ExternalLink size={12} />
                          </a>
                        </div>
                      </td>

                      {/* Action Taken */}
                      <td style={{ padding: '12px 20px' }}>
                        {ev.is_blocked ? (
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: '#43e97b', fontSize: '11px', fontWeight: 700 }}>
                            <CheckCircle2 size={13} /> BLOCKED
                          </span>
                        ) : (
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: '#f64f59', fontSize: '11px', fontWeight: 700 }}>
                            <XCircle size={13} /> ACCESSED
                          </span>
                        )}
                      </td>

                      {/* Device ID */}
                      <td style={{ padding: '12px 20px', fontSize: '12px', color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                        {ev.device_id}
                      </td>

                      {/* Incident Details */}
                      <td style={{ padding: '12px 20px', fontSize: '11px', color: 'var(--text-muted)', maxWidth: '280px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {ev.details && Object.keys(ev.details).length > 0 
                          ? Object.entries(ev.details).map(([k, v]) => `${k}: ${v}`).join(' · ')
                          : ev.url
                        }
                      </td>

                      {/* Time Detected */}
                      <td style={{ padding: '12px 20px', fontSize: '11px', color: 'var(--text-muted)' }}>
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
