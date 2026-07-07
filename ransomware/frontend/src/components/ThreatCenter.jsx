import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { 
  ShieldAlert, 
  ShieldCheck, 
  RefreshCw, 
  Brain, 
  GitFork, 
  Terminal, 
  Lock, 
  Server, 
  EyeOff, 
  Play, 
  Clock, 
  CheckCircle2, 
  Slash 
} from 'lucide-react';

export default function ThreatCenter({ selectedEventId, setSelectedEventId }) {
  const [events, setEvents] = useState([]);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [explanation, setExplanation] = useState(null);
  const [storyline, setStoryline] = useState(null);
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [loadingList, setLoadingList] = useState(false);
  const [loadingDetails, setLoadingDetails] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);

  useEffect(() => {
    loadEvents();
  }, []);

  useEffect(() => {
    if (selectedEventId) {
      loadEventDetails(selectedEventId);
    } else {
      setSelectedEvent(null);
      setExplanation(null);
      setStoryline(null);
    }
  }, [selectedEventId]);

  const loadEvents = async () => {
    setLoadingList(true);
    try {
      const data = await api.listThreatEvents();
      setEvents(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoadingList(false);
    }
  };

  const loadEventDetails = async (id) => {
    setLoadingDetails(true);
    try {
      const eventDetails = await api.getThreatDetails(id);
      setSelectedEvent(eventDetails);
      
      const expDetails = await api.getThreatExplanation(id);
      setExplanation(expDetails);
      
      const storyDetails = await api.getThreatStoryline(id);
      setStoryline(storyDetails);
    } catch (err) {
      console.error(err);
    } finally {
      setLoadingDetails(false);
    }
  };

  const handleUpdateStatus = async (statusValue) => {
    if (!selectedEvent) return;
    setActionLoading(true);
    try {
      await api.updateThreatStatus(selectedEvent.id, statusValue);
      // Reload list and details
      await loadEvents();
      await loadEventDetails(selectedEvent.id);
    } catch (err) {
      console.error(err);
    } finally {
      setActionLoading(false);
    }
  };

  const filteredEvents = events.filter(e => {
    const matchCat = categoryFilter === 'all' || e.category === categoryFilter;
    const matchStat = statusFilter === 'all' || e.status === statusFilter;
    return matchCat && matchStat;
  });

  const getStorylineNodeIcon = (type, status) => {
    if (status === 'success') return <ShieldCheck size={16} color="#10b981" />;
    if (status === 'blocked') return <Lock size={16} color="#ef4444" />;
    if (type === 'process') return <Terminal size={16} color="var(--primary)" />;
    return <Server size={16} color="var(--cyan)" />;
  };

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '32px' }}>
        <div>
          <h1 style={{ fontSize: '28px', fontWeight: 800 }}>Threat Response Center</h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '15px', marginTop: '4px' }}>
            Inspect security events, view threat analysis recommendations, and trace process execution chains.
          </p>
        </div>
        <button 
          onClick={loadEvents} 
          className="btn-secondary" 
          disabled={loadingList}
          style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '10px 16px' }}
        >
          <RefreshCw size={16} className={loadingList ? 'spin-slow' : ''} />
          Reload
        </button>
      </div>

      <div style={{
        display: 'grid',
        gridTemplateColumns: '1.2fr 1.8fr',
        gap: '24px',
        alignItems: 'start'
      }}>
        
        {/* Left Side: Incident List */}
        <div className="glass-card" style={{ padding: '20px', minHeight: '600px' }}>
          {/* Filters */}
          <div style={{ display: 'flex', gap: '10px', marginBottom: '20px' }}>
            <select 
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              className="text-input"
              style={{ flex: 1, padding: '8px 12px', fontSize: '13px' }}
            >
              <option value="all">All Categories</option>
              <option value="ransomware">Ransomware</option>
              <option value="deception">Deception</option>
              <option value="usb">USB Security</option>
              <option value="identity">Identity</option>
            </select>

            <select 
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="text-input"
              style={{ flex: 1, padding: '8px 12px', fontSize: '13px' }}
            >
              <option value="all">All Statuses</option>
              <option value="active">Active</option>
              <option value="quarantined">Quarantined</option>
              <option value="resolved">Resolved</option>
              <option value="ignored">Ignored</option>
            </select>
          </div>

          {/* Table list */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {loadingList ? (
              <div style={{ textAlign: 'center', padding: '100px 0' }}>
                <div style={{
                  border: '3px solid rgba(255,255,255,0.05)',
                  borderTop: '3px solid var(--cyan)',
                  borderRadius: '50%',
                  width: '30px',
                  height: '30px',
                  margin: '0 auto 12px auto',
                  animation: 'spin-slow 1s linear infinite'
                }}></div>
                <p style={{ color: 'var(--text-secondary)', fontSize: '14px' }}>Loading alerts...</p>
              </div>
            ) : filteredEvents.length > 0 ? (
              filteredEvents.map((e) => {
                const isSelected = selectedEventId === e.id;
                return (
                  <button
                    key={e.id}
                    onClick={() => setSelectedEventId(e.id)}
                    style={{
                      width: '100%',
                      background: isSelected ? 'rgba(0, 242, 254, 0.06)' : 'rgba(255,255,255,0.02)',
                      border: isSelected ? '1px solid rgba(0, 242, 254, 0.3)' : '1px solid var(--border-color)',
                      borderRadius: '10px',
                      padding: '16px',
                      textAlign: 'left',
                      cursor: 'pointer',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'start',
                      fontFamily: 'var(--font-primary)',
                      transition: 'var(--transition)'
                    }}
                    onMouseEnter={(elm) => {
                      if (!isSelected) elm.currentTarget.style.borderColor = 'rgba(255,255,255,0.15)';
                    }}
                    onMouseLeave={(elm) => {
                      if (!isSelected) elm.currentTarget.style.borderColor = 'var(--border-color)';
                    }}
                  >
                    <div style={{ flex: 1, minWidth: 0, paddingRight: '12px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                        <span className={`badge ${e.severity.toLowerCase()}`} style={{ fontSize: '10px', padding: '2px 8px' }}>
                          {e.severity}
                        </span>
                        <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                          {new Date(e.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                        </span>
                      </div>
                      <h4 style={{ 
                        fontSize: '14px', 
                        fontWeight: 700, 
                        color: 'var(--text-main)',
                        whiteSpace: 'nowrap',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis'
                      }}>{e.title}</h4>
                      <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '4px' }}>Device: {e.device_id}</p>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'end', gap: '6px' }}>
                      <span style={{
                        fontSize: '11px',
                        fontWeight: 700,
                        textTransform: 'uppercase',
                        color: e.status === 'active' ? 'var(--severity-critical)' : 'var(--severity-low)'
                      }}>{e.status}</span>
                      <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Conf: {e.confidence_score}%</span>
                    </div>
                  </button>
                );
              })
            ) : (
              <div style={{ textAlign: 'center', padding: '80px 0', color: 'var(--text-muted)' }}>
                <ShieldCheck size={36} style={{ marginBottom: '8px', opacity: 0.4 }} />
                <p style={{ fontSize: '14px' }}>No events match filters.</p>
              </div>
            )}
          </div>
        </div>

        {/* Right Side: Incident Forensics Inspector */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          {loadingDetails ? (
            <div className="glass-card" style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '600px' }}>
              <div style={{
                border: '3px solid rgba(255,255,255,0.05)',
                borderTop: '3px solid var(--cyan)',
                borderRadius: '50%',
                width: '35px',
                height: '35px',
                animation: 'spin-slow 1s linear infinite'
              }}></div>
            </div>
          ) : selectedEvent ? (
            <>
              {/* Event Header Card */}
              <div className="glass-card" style={{
                borderLeft: `4px solid ${
                  selectedEvent.severity === 'CRITICAL' ? 'var(--severity-critical)' : 
                  selectedEvent.severity === 'HIGH' ? 'var(--severity-high)' : 'var(--severity-medium)'
                }`
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: '16px' }}>
                  <div>
                    <span className={`badge ${selectedEvent.severity.toLowerCase()}`} style={{ marginBottom: '8px' }}>
                      {selectedEvent.severity}
                    </span>
                    <h2 style={{ fontSize: '22px', fontWeight: 800 }}>{selectedEvent.title}</h2>
                    <p style={{ color: 'var(--text-secondary)', fontSize: '13px', marginTop: '4px' }}>
                      Device: <strong style={{ color: 'var(--text-main)' }}>{selectedEvent.device_id}</strong> • 
                      Detected: {new Date(selectedEvent.timestamp).toLocaleString()}
                    </p>
                  </div>
                  <div style={{ textAlign: 'right' }}>
                    <p style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>Current Action Status</p>
                    <p style={{
                      fontSize: '18px',
                      fontWeight: 800,
                      color: selectedEvent.status === 'active' ? 'var(--severity-critical)' : 'var(--severity-low)',
                      textTransform: 'uppercase',
                      marginTop: '4px'
                    }}>{selectedEvent.status}</p>
                  </div>
                </div>
                <p style={{ fontSize: '14px', color: 'var(--text-secondary)', borderTop: '1px solid var(--border-color)', paddingTop: '16px' }}>
                  {selectedEvent.description}
                </p>

                {/* Status action buttons */}
                <div style={{
                  display: 'flex',
                  gap: '12px',
                  marginTop: '24px',
                  borderTop: '1px solid var(--border-color)',
                  paddingTop: '20px'
                }}>
                  {selectedEvent.status === 'active' && (
                    <button
                      onClick={() => handleUpdateStatus('quarantined')}
                      disabled={actionLoading}
                      className="btn-primary"
                      style={{
                        background: 'linear-gradient(135deg, #ef4444, #f97316)',
                        padding: '10px 20px',
                        fontSize: '13px',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '6px'
                      }}
                    >
                      <Lock size={15} />
                      Quarantine Process
                    </button>
                  )}
                  {selectedEvent.status !== 'resolved' && (
                    <button
                      onClick={() => handleUpdateStatus('resolved')}
                      disabled={actionLoading}
                      className="btn-secondary"
                      style={{
                        padding: '10px 20px',
                        fontSize: '13px',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '6px'
                      }}
                    >
                      <CheckCircle2 size={15} color="#10b981" />
                      Resolve Alert
                    </button>
                  )}
                  {selectedEvent.status !== 'ignored' && (
                    <button
                      onClick={() => handleUpdateStatus('ignored')}
                      disabled={actionLoading}
                      className="btn-secondary"
                      style={{
                        padding: '10px 20px',
                        fontSize: '13px',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '6px'
                      }}
                    >
                      <EyeOff size={15} />
                      Ignore Alert
                    </button>
                  )}
                </div>
              </div>

              {/* Threat Analysis Block */}
              {explanation && (
                <div className="glass-card" style={{
                  border: '1px solid rgba(0, 242, 254, 0.15)',
                  boxShadow: '0 0 20px rgba(0, 242, 254, 0.03)'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '20px' }}>
                    <Brain size={20} color="var(--cyan)" />
                    <h3 style={{ fontSize: '16px', fontWeight: 700, letterSpacing: '0.02em', textTransform: 'uppercase', color: 'var(--cyan)' }}>
                      Threat Analysis Insights
                    </h3>
                  </div>

                  <div style={{ display: 'flex', gap: '24px', alignItems: 'center', marginBottom: '20px' }}>
                    {/* Progress Circle Dial */}
                    <div style={{
                      position: 'relative',
                      width: '70px',
                      height: '70px',
                      borderRadius: '50%',
                      background: `conic-gradient(var(--cyan) ${explanation.confidence * 3.6}deg, rgba(255,255,255,0.05) 0deg)`,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center'
                    }}>
                      <div style={{
                        position: 'absolute',
                        width: '58px',
                        height: '58px',
                        borderRadius: '50%',
                        background: 'var(--bg-panel, #05070d)',
                        display: 'flex',
                        flexDirection: 'column',
                        alignItems: 'center',
                        justifyContent: 'center'
                      }}>
                        <span style={{ fontSize: '16px', fontWeight: 800, color: 'var(--cyan)' }}>{explanation.confidence}%</span>
                        <span style={{ fontSize: '9px', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>Conf.</span>
                      </div>
                    </div>

                    <div>
                      <h4 style={{ fontSize: '15px', fontWeight: 700 }}>Heuristic Severity Analysis</h4>
                      <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                        This assessment score is computed by correlating process hierarchy spawns and entropy spikes on write buffers.
                      </p>
                    </div>
                  </div>

                  {/* Bullet reasons list */}
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', margin: '20px 0' }}>
                    {explanation.reasons.map((reason, idx) => (
                      <div key={idx} style={{
                        display: 'flex',
                        gap: '10px',
                        fontSize: '13.5px',
                        background: 'rgba(255,255,255,0.015)',
                        border: '1px solid var(--border-color)',
                        borderRadius: '8px',
                        padding: '10px 14px',
                        lineHeight: '1.4'
                      }}>
                        <span style={{ color: 'var(--cyan)' }}>✓</span>
                        <span style={{ color: 'var(--text-main)' }}>{reason}</span>
                      </div>
                    ))}
                  </div>

                  {/* Recommended Action Card */}
                  <div style={{
                    background: 'rgba(79, 172, 254, 0.06)',
                    border: '1px solid rgba(79, 172, 254, 0.2)',
                    borderRadius: '8px',
                    padding: '14px 16px',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '4px'
                  }}>
                    <span style={{ fontSize: '11px', color: 'var(--primary)', fontWeight: 700, textTransform: 'uppercase' }}>Recommended Response Steps</span>
                    <strong style={{ fontSize: '14px', color: 'var(--text-main)' }}>{explanation.recommended_action}</strong>
                  </div>
                </div>
              )}

              {/* Attack Storyline Process Tree Block */}
              {storyline && (
                <div className="glass-card">
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '24px' }}>
                    <GitFork size={20} color="var(--primary)" />
                    <h3 style={{ fontSize: '16px', fontWeight: 700, letterSpacing: '0.02em', textTransform: 'uppercase', color: 'var(--primary)' }}>
                      Attack Execution Storyline Graph
                    </h3>
                  </div>

                  {/* Timeline Flow */}
                  <div style={{
                    position: 'relative',
                    paddingLeft: '24px',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '24px'
                  }}>
                    {/* Vertical connecting line */}
                    <div style={{
                      position: 'absolute',
                      left: '8px',
                      top: '12px',
                      bottom: '12px',
                      width: '2px',
                      background: 'linear-gradient(to bottom, var(--border-color) 20%, var(--primary) 50%, var(--cyan) 80%, rgba(239, 68, 68, 0.3) 100%)'
                    }}></div>

                    {storyline.nodes.map((node, index) => {
                      const isThreat = node.status === 'threat';
                      const isBlocked = node.status === 'blocked';
                      const isSuccess = node.status === 'success';
                      
                      let dotColor = 'var(--text-muted)';
                      let cardBorderColor = 'var(--border-color)';
                      if (isThreat) {
                        dotColor = 'var(--severity-high)';
                        cardBorderColor = 'rgba(249, 115, 22, 0.2)';
                      } else if (isBlocked) {
                        dotColor = 'var(--severity-critical)';
                        cardBorderColor = 'rgba(239, 68, 68, 0.3)';
                      } else if (isSuccess) {
                        dotColor = '#10b981';
                        cardBorderColor = 'rgba(16, 185, 129, 0.3)';
                      }

                      return (
                        <div key={node.id} style={{ position: 'relative' }}>
                          {/* Timeline dot */}
                          <div style={{
                            position: 'absolute',
                            left: '-24px',
                            top: '12px',
                            transform: 'translateX(-50%)',
                            width: '18px',
                            height: '18px',
                            borderRadius: '50%',
                            background: 'var(--bg-panel, #05070d)',
                            border: `2px solid ${dotColor}`,
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            zIndex: 2,
                            boxShadow: isBlocked ? '0 0 10px rgba(239, 68, 68, 0.3)' : 'none'
                          }}>
                            <div style={{
                              width: '6px',
                              height: '6px',
                              borderRadius: '50%',
                              background: dotColor
                            }}></div>
                          </div>

                          {/* Node detail block */}
                          <div style={{
                            background: 'rgba(255,255,255,0.01)',
                            border: `1px solid ${cardBorderColor}`,
                            borderRadius: '10px',
                            padding: '14px 16px',
                            display: 'flex',
                            gap: '12px',
                            alignItems: 'start'
                          }}>
                            <div style={{
                              background: 'rgba(255,255,255,0.03)',
                              padding: '8px',
                              borderRadius: '6px',
                              border: '1px solid var(--border-color)'
                            }}>
                              {getStorylineNodeIcon(node.type, node.status)}
                            </div>
                            <div style={{ flex: 1, minWidth: 0 }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <strong style={{ fontSize: '14px', color: 'var(--text-main)' }}>{node.label}</strong>
                                <span style={{ fontSize: '11px', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                                  <Clock size={11} />
                                  {node.time}
                                </span>
                              </div>
                              <p style={{ fontSize: '12.5px', color: 'var(--text-secondary)', marginTop: '4px', lineHeight: '1.4' }}>
                                {node.description}
                              </p>
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </>
          ) : (
            /* Empty State */
            <div className="glass-card" style={{
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'center',
              alignItems: 'center',
              minHeight: '600px',
              textAlign: 'center',
              padding: '40px',
              color: 'var(--text-secondary)'
            }}>
              <Brain size={44} style={{ marginBottom: '16px', opacity: 0.3 }} />
              <h3 style={{ fontSize: '18px', fontWeight: 700, color: 'var(--text-main)' }}>Forensic Analysis Portal</h3>
              <p style={{ fontSize: '14px', maxWidth: '320px', marginTop: '6px' }}>
                Select an active alert incident from the log feed to load threat analysis insights, recommended containment actions, and visualized process trees.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
