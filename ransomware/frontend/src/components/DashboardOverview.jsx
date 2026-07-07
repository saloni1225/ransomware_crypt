import React from 'react';
import { 
  ShieldAlert, 
  MonitorPlay, 
  ShieldCheck, 
  AlertTriangle,
  ArrowRight,
  TrendingDown,
  Info,
  Activity
} from 'lucide-react';
import { 
  LineChart, Line, BarChart, Bar, 
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer 
} from 'recharts';

export default function DashboardOverview({ summary, loading, setActiveTab, setSelectedEventId }) {
  if (loading || !summary) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '60vh' }}>
        <div style={{
          border: '3px solid rgba(255,255,255,0.05)',
          borderTop: '3px solid var(--cyan)',
          borderRadius: '50%',
          width: '40px',
          height: '40px',
          animation: 'spin-slow 1s linear infinite'
        }}></div>
      </div>
    );
  }

  const handleViewThreat = (id) => {
    setSelectedEventId(id);
    setActiveTab('threats');
  };

  const getRiskLevel = (score) => {
    if (score >= 90) return { label: 'HEALTHY', color: '#10b981' };
    if (score >= 70) return { label: 'LOW RISK', color: '#f59e0b' };
    if (score >= 50) return { label: 'MEDIUM RISK', color: '#f97316' };
    return { label: 'HIGH RISK', color: '#ef4444' };
  };

  const risk = getRiskLevel(summary.overall_trust_score);

  // Generate mock chart data since historical analytics isn't fully implemented
  const generateMockChartData = () => {
    const data = [];
    const now = new Date();
    for (let i = 6; i >= 0; i--) {
      const d = new Date(now);
      d.setDate(d.getDate() - i);
      data.push({
        name: d.toLocaleDateString('en-US', { weekday: 'short' }),
        threats: Math.floor(Math.random() * 5) + (i === 0 ? summary.total_threats : 0),
        trustScore: Math.max(50, Math.min(100, summary.overall_trust_score + (Math.random() * 10 - 5)))
      });
    }
    return data;
  };
  const chartData = generateMockChartData();

  return (
    <div>
      {/* Top Welcome Title */}
      <div style={{ marginBottom: '32px' }}>
        <h1 style={{ fontSize: '28px', fontWeight: 800 }}>Security Command Center</h1>
        <p style={{ color: 'var(--text-secondary)', fontSize: '15px', marginTop: '4px' }}>
          Real-time ransomware defense, behavior baselines, and decoy validation.
        </p>
      </div>

      {/* Grid Metrics */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
        gap: '24px',
        marginBottom: '32px'
      }}>
        {/* Card 1: Trust Score */}
        <div className="glass-card" style={{ position: 'relative', overflow: 'hidden' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
            <div>
              <p style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Overall Trust Score</p>
              <h3 style={{ fontSize: '36px', fontWeight: 800, marginTop: '8px', color: risk.color }}>
                {summary.overall_trust_score}<span style={{ fontSize: '16px', color: 'var(--text-muted)' }}>/100</span>
              </h3>
            </div>
            <div style={{
              background: `rgba(${risk.color === '#10b981' ? '16, 185, 129' : risk.color === '#f59e0b' ? '245, 158, 11' : '239, 68, 68'}, 0.1)`,
              padding: '10px',
              borderRadius: '10px',
              border: `1px solid ${risk.color}`
            }}>
              <ShieldCheck size={24} color={risk.color} />
            </div>
          </div>
          <div style={{
            marginTop: '20px',
            fontSize: '12px',
            fontWeight: 700,
            color: risk.color,
            letterSpacing: '0.05em',
            textTransform: 'uppercase',
            display: 'inline-block',
            padding: '2px 8px',
            borderRadius: '4px',
            background: `rgba(${risk.color === '#10b981' ? '16, 185, 129' : risk.color === '#f59e0b' ? '245, 158, 11' : '239, 68, 68'}, 0.05)`
          }}>
            Status: {risk.label}
          </div>
        </div>

        {/* Card 2: Devices */}
        <div className="glass-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
            <div>
              <p style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Connected Devices</p>
              <h3 style={{ fontSize: '36px', fontWeight: 800, marginTop: '8px' }}>
                {summary.active_devices}<span style={{ fontSize: '16px', color: 'var(--text-muted)' }}> / {summary.total_devices} Online</span>
              </h3>
            </div>
            <div style={{
              background: 'rgba(0, 242, 254, 0.08)',
              padding: '10px',
              borderRadius: '10px',
              border: '1px solid rgba(0, 242, 254, 0.2)'
            }}>
              <MonitorPlay size={24} color="var(--cyan)" />
            </div>
          </div>
          <p style={{ marginTop: '20px', fontSize: '13px', color: 'var(--text-secondary)' }}>
            Active endpoint monitoring agents.
          </p>
        </div>

        {/* Card 3: Total Threats */}
        <div className="glass-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
            <div>
              <p style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Active Threats</p>
              <h3 style={{ fontSize: '36px', fontWeight: 800, marginTop: '8px', color: summary.total_threats > 0 ? 'var(--severity-high)' : 'var(--text-main)' }}>
                {summary.total_threats}
              </h3>
            </div>
            <div style={{
              background: 'rgba(249, 115, 22, 0.08)',
              padding: '10px',
              borderRadius: '10px',
              border: '1px solid rgba(249, 115, 22, 0.2)'
            }}>
              <AlertTriangle size={24} color="var(--severity-high)" />
            </div>
          </div>
          <p style={{ marginTop: '20px', fontSize: '13px', color: 'var(--text-secondary)' }}>
            Total unresolved alerts flagged.
          </p>
        </div>

        {/* Card 4: Critical Alerts */}
        <div className="glass-card" style={{
          border: summary.critical_threats > 0 ? '1px solid rgba(239, 68, 68, 0.25)' : '1px solid var(--border-color)',
          boxShadow: summary.critical_threats > 0 ? '0 0 15px rgba(239, 68, 68, 0.08)' : 'none'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
            <div>
              <p style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Critical Incidents</p>
              <h3 style={{ fontSize: '36px', fontWeight: 800, marginTop: '8px', color: summary.critical_threats > 0 ? 'var(--severity-critical)' : 'var(--text-main)' }}>
                {summary.critical_threats}
              </h3>
            </div>
            <div style={{
              background: 'rgba(239, 68, 68, 0.08)',
              padding: '10px',
              borderRadius: '10px',
              border: '1px solid rgba(239, 68, 68, 0.2)'
            }}>
              <ShieldAlert size={24} color="var(--severity-critical)" />
            </div>
          </div>
          <p style={{ marginTop: '20px', fontSize: '13px', color: 'var(--text-secondary)' }}>
            Immediate quarantine response needed.
          </p>
        </div>
      </div>

      {/* Critical Banner Alert */}
      {summary.critical_threats > 0 && (
        <div className="alert-banner">
          <ShieldAlert size={24} color="var(--severity-critical)" />
          <div style={{ flex: 1 }}>
            <h4 style={{ fontSize: '15px', fontWeight: 700 }}>Critical Active Malware/Ransomware Alerts Detected</h4>
            <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '2px' }}>
              One or more devices exhibit high entropy encryption signatures. Automated local host quarantine has been executed.
            </p>
          </div>
          <button 
            onClick={() => setActiveTab('threats')}
            className="btn-primary" 
            style={{
              padding: '8px 16px',
              fontSize: '13px',
              display: 'flex',
              alignItems: 'center',
              gap: '6px'
            }}
          >
            Investigate
            <ArrowRight size={14} />
          </button>
        </div>
      )}

      {/* Analytics Charts */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: '1fr 1fr',
        gap: '24px',
        marginBottom: '32px'
      }}>
        {/* Trend Chart */}
        <div className="glass-card" style={{ padding: '24px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '20px' }}>
            <Activity size={18} color="var(--cyan)" />
            <h3 style={{ fontSize: '16px', fontWeight: 700, textTransform: 'uppercase', color: 'var(--cyan)' }}>Threat Activity Trend (7 Days)</h3>
          </div>
          <div style={{ height: '250px', width: '100%' }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
                <XAxis dataKey="name" stroke="var(--text-muted)" fontSize={12} tickLine={false} />
                <YAxis stroke="var(--text-muted)" fontSize={12} tickLine={false} allowDecimals={false} />
                <Tooltip 
                  contentStyle={{ backgroundColor: 'rgba(11, 16, 27, 0.9)', border: '1px solid var(--border-color)', borderRadius: '8px' }}
                  itemStyle={{ color: 'var(--text-main)' }}
                />
                <Bar dataKey="threats" fill="var(--severity-high)" radius={[4, 4, 0, 0]} name="Alerts" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Health Chart */}
        <div className="glass-card" style={{ padding: '24px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '20px' }}>
            <TrendingDown size={18} color="#10b981" />
            <h3 style={{ fontSize: '16px', fontWeight: 700, textTransform: 'uppercase', color: '#10b981' }}>Trust Score Evolution</h3>
          </div>
          <div style={{ height: '250px', width: '100%' }}>
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
                <XAxis dataKey="name" stroke="var(--text-muted)" fontSize={12} tickLine={false} />
                <YAxis domain={[0, 100]} stroke="var(--text-muted)" fontSize={12} tickLine={false} />
                <Tooltip 
                  contentStyle={{ backgroundColor: 'rgba(11, 16, 27, 0.9)', border: '1px solid var(--border-color)', borderRadius: '8px' }}
                  itemStyle={{ color: 'var(--text-main)' }}
                />
                <Line type="monotone" dataKey="trustScore" stroke="#10b981" strokeWidth={3} dot={{ r: 4, fill: '#10b981' }} name="Avg Score" />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Layout Split: Recent Threats & Security Diagram */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: '2fr 1fr',
        gap: '24px'
      }}>
        {/* Recent Events Panel */}
        <div className="glass-card" style={{ padding: '24px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
            <h3 style={{ fontSize: '18px', fontWeight: 700 }}>Recent Incidents Log</h3>
            <button 
              onClick={() => setActiveTab('threats')}
              style={{
                background: 'none',
                border: 'none',
                color: 'var(--cyan)',
                fontSize: '13px',
                fontWeight: 600,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '4px'
              }}
            >
              View All Threat Center
              <ArrowRight size={14} />
            </button>
          </div>

          <div style={{ overflowX: 'auto' }}>
            {summary.recent_events && summary.recent_events.length > 0 ? (
              <table className="custom-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Device</th>
                    <th>Alert Title</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {summary.recent_events.map((event) => (
                    <tr key={event.id}>
                      <td style={{ color: 'var(--text-secondary)', fontSize: '13px' }}>
                        {new Date(event.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                      </td>
                      <td style={{ fontWeight: 600 }}>{event.device_id}</td>
                      <td>{event.title}</td>
                      <td>
                        <span className={`badge ${event.severity.toLowerCase()}`}>
                          {event.severity}
                        </span>
                      </td>
                      <td>
                        <span style={{
                          color: event.status === 'active' ? 'var(--severity-critical)' : 'var(--severity-low)',
                          fontWeight: 600,
                          fontSize: '13px',
                          textTransform: 'capitalize'
                        }}>
                          {event.status}
                        </span>
                      </td>
                      <td>
                        <button 
                          onClick={() => handleViewThreat(event.id)}
                          className="btn-secondary"
                          style={{
                            padding: '6px 12px',
                            fontSize: '12px',
                            borderRadius: '6px'
                          }}
                        >
                          Details
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--text-muted)' }}>
                <ShieldCheck size={40} style={{ marginBottom: '12px', opacity: 0.5 }} />
                <p>No security incidents recorded. System secure.</p>
              </div>
            )}
          </div>
        </div>

        {/* Security Summary Graph (Visual CSS Widget) */}
        <div className="glass-card" style={{ display: 'flex', flexDirection: 'column' }}>
          <h3 style={{ fontSize: '18px', fontWeight: 700, marginBottom: '20px' }}>Active Protections</h3>
          
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', flex: 1 }}>
            {/* Monitor 1 */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <div style={{
                background: 'rgba(16, 185, 129, 0.1)',
                padding: '8px',
                borderRadius: '8px',
                border: '1px solid rgba(16, 185, 129, 0.2)'
              }}>
                <ShieldCheck size={18} color="#10b981" />
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '13px', fontWeight: 600 }}>
                  <span>Anti-Ransomware</span>
                  <span style={{ color: '#10b981' }}>Active</span>
                </div>
                <div style={{ background: 'rgba(255,255,255,0.05)', height: '4px', borderRadius: '2px', marginTop: '6px' }}>
                  <div style={{ width: '100%', background: '#10b981', height: '100%', borderRadius: '2px' }}></div>
                </div>
              </div>
            </div>

            {/* Monitor 2 */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <div style={{
                background: 'rgba(16, 185, 129, 0.1)',
                padding: '8px',
                borderRadius: '8px',
                border: '1px solid rgba(16, 185, 129, 0.2)'
              }}>
                <ShieldCheck size={18} color="#10b981" />
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '13px', fontWeight: 600 }}>
                  <span>Deception Engine</span>
                  <span style={{ color: '#10b981' }}>Active</span>
                </div>
                <div style={{ background: 'rgba(255,255,255,0.05)', height: '4px', borderRadius: '2px', marginTop: '6px' }}>
                  <div style={{ width: '100%', background: '#10b981', height: '100%', borderRadius: '2px' }}></div>
                </div>
              </div>
            </div>

            {/* Monitor 3 */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <div style={{
                background: 'rgba(16, 185, 129, 0.1)',
                padding: '8px',
                borderRadius: '8px',
                border: '1px solid rgba(16, 185, 129, 0.2)'
              }}>
                <ShieldCheck size={18} color="#10b981" />
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '13px', fontWeight: 600 }}>
                  <span>USB Control Agent</span>
                  <span style={{ color: '#10b981' }}>Active</span>
                </div>
                <div style={{ background: 'rgba(255,255,255,0.05)', height: '4px', borderRadius: '2px', marginTop: '6px' }}>
                  <div style={{ width: '100%', background: '#10b981', height: '100%', borderRadius: '2px' }}></div>
                </div>
              </div>
            </div>

            {/* Monitor 4 */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <div style={{
                background: 'rgba(16, 185, 129, 0.1)',
                padding: '8px',
                borderRadius: '8px',
                border: '1px solid rgba(16, 185, 129, 0.2)'
              }}>
                <ShieldCheck size={18} color="#10b981" />
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '13px', fontWeight: 600 }}>
                  <span>Identity Monitor</span>
                  <span style={{ color: '#10b981' }}>Active</span>
                </div>
                <div style={{ background: 'rgba(255,255,255,0.05)', height: '4px', borderRadius: '2px', marginTop: '6px' }}>
                  <div style={{ width: '100%', background: '#10b981', height: '100%', borderRadius: '2px' }}></div>
                </div>
              </div>
            </div>
            
            <div style={{
              background: 'rgba(255,255,255,0.02)',
              border: '1px dashed var(--border-color)',
              borderRadius: '8px',
              padding: '12px',
              fontSize: '12px',
              color: 'var(--text-secondary)',
              marginTop: 'auto',
              display: 'flex',
              gap: '8px'
            }}>
              <Info size={16} color="var(--cyan)" style={{ flexShrink: 0 }} />
              <span>Endpoints are running localized behavior monitoring rules linked via WebSocket relays.</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
