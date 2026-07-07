import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { 
  Smartphone, 
  RefreshCw, 
  Info,
  Server,
  Laptop,
  CheckCircle,
  AlertOctagon,
  Percent
} from 'lucide-react';

export default function DeviceTrust() {
  const [devices, setDevices] = useState([]);
  const [selectedDeviceId, setSelectedDeviceId] = useState(null);
  const [trustDetails, setTrustDetails] = useState(null);
  const [loadingList, setLoadingList] = useState(false);
  const [loadingDetails, setLoadingDetails] = useState(false);

  useEffect(() => {
    loadDevices();
  }, []);

  useEffect(() => {
    if (selectedDeviceId) {
      loadTrustBreakdown(selectedDeviceId);
    } else {
      setTrustDetails(null);
    }
  }, [selectedDeviceId]);

  const loadDevices = async () => {
    setLoadingList(true);
    try {
      const data = await api.listDevices();
      setDevices(data);
      if (data.length > 0 && !selectedDeviceId) {
        setSelectedDeviceId(data[0].id);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoadingList(false);
    }
  };

  const loadTrustBreakdown = async (id) => {
    setLoadingDetails(true);
    try {
      const breakdown = await api.getDeviceTrust(id);
      setTrustDetails(breakdown);
    } catch (err) {
      console.error(err);
    } finally {
      setLoadingDetails(false);
    }
  };

  const getOsIcon = (osType) => {
    // Return laptop/server based on type
    const normalized = osType ? osType.toLowerCase() : '';
    if (normalized === 'linux') return <Server size={18} color="var(--primary)" />;
    return <Laptop size={18} color="var(--cyan)" />;
  };

  const getTrustColor = (score) => {
    if (score >= 90) return '#10b981'; // Green
    if (score >= 70) return '#f59e0b'; // Amber
    if (score >= 50) return '#f97316'; // Orange
    return '#ef4444'; // Red
  };

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '32px' }}>
        <div>
          <h1 style={{ fontSize: '28px', fontWeight: 800 }}>Endpoint Device Trust</h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '15px', marginTop: '4px' }}>
            Verify client devices, audit firewall settings, and inspect weighted parameters computing the device Trust Score.
          </p>
        </div>
        <button 
          onClick={loadDevices} 
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
        gridTemplateColumns: '1.3fr 1.7fr',
        gap: '24px',
        alignItems: 'start'
      }}>
        {/* Left: Device List */}
        <div className="glass-card" style={{ padding: '20px', minHeight: '500px' }}>
          <h3 style={{ fontSize: '16px', fontWeight: 700, marginBottom: '20px', textTransform: 'uppercase', color: 'var(--text-secondary)' }}>
            Monitored Endpoint Nodes
          </h3>
          
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {loadingList ? (
              <div style={{ textAlign: 'center', padding: '80px 0' }}>
                <div style={{
                  border: '3px solid rgba(255,255,255,0.05)',
                  borderTop: '3px solid var(--cyan)',
                  borderRadius: '50%',
                  width: '30px',
                  height: '30px',
                  margin: '0 auto 12px auto',
                  animation: 'spin-slow 1s linear infinite'
                }}></div>
              </div>
            ) : devices.length > 0 ? (
              devices.map((device) => {
                const isSelected = selectedDeviceId === device.id;
                const scoreColor = getTrustColor(device.trust_score);
                const isOnline = device.status === 'online';
                
                return (
                  <button
                    key={device.id}
                    onClick={() => setSelectedDeviceId(device.id)}
                    style={{
                      width: '100%',
                      background: isSelected ? 'rgba(0, 242, 254, 0.05)' : 'rgba(255,255,255,0.015)',
                      border: isSelected ? '1px solid rgba(0, 242, 254, 0.3)' : '1px solid var(--border-color)',
                      borderRadius: '10px',
                      padding: '16px',
                      textAlign: 'left',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      fontFamily: 'var(--font-primary)',
                      transition: 'var(--transition)'
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                      <div style={{
                        background: 'rgba(255,255,255,0.02)',
                        padding: '10px',
                        borderRadius: '8px',
                        border: '1px solid var(--border-color)',
                        position: 'relative'
                      }}>
                        {getOsIcon(device.os_type)}
                        {/* Online/Offline Status Pin */}
                        <div style={{
                          position: 'absolute',
                          bottom: '-2px',
                          right: '-2px',
                          width: '10px',
                          height: '10px',
                          borderRadius: '50%',
                          background: isOnline ? '#10b981' : '#6b7280',
                          border: '2px solid #121824',
                          boxShadow: isOnline ? '0 0 6px #10b981' : 'none'
                        }}></div>
                      </div>
                      <div>
                        <strong style={{ fontSize: '15px', color: 'var(--text-main)', display: 'block' }}>{device.hostname}</strong>
                        <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>IP: {device.ip_address || 'Unregistered'}</span>
                      </div>
                    </div>

                    <div style={{ textAlign: 'right' }}>
                      <span style={{ fontSize: '11px', color: 'var(--text-secondary)', display: 'block', textTransform: 'uppercase', fontWeight: 600 }}>Trust</span>
                      <strong style={{ fontSize: '18px', color: scoreColor, fontWeight: 800 }}>{device.trust_score}</strong>
                    </div>
                  </button>
                );
              })
            ) : (
              <div style={{ textAlign: 'center', padding: '60px 0', color: 'var(--text-muted)' }}>
                <p>No endpoints registered. Start agent simulator.</p>
              </div>
            )}
          </div>
        </div>

        {/* Right: Trust Parameter Audit Breakdown */}
        <div className="glass-card" style={{ minHeight: '500px' }}>
          {loadingDetails ? (
            <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '400px' }}>
              <div style={{
                border: '3px solid rgba(255,255,255,0.05)',
                borderTop: '3px solid var(--cyan)',
                borderRadius: '50%',
                width: '35px',
                height: '35px',
                animation: 'spin-slow 1s linear infinite'
              }}></div>
            </div>
          ) : trustDetails ? (
            <div>
              {/* Device Header */}
              <div style={{ borderBottom: '1px solid var(--border-color)', paddingBottom: '20px', marginBottom: '24px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <h3 style={{ fontSize: '18px', fontWeight: 700 }}>Trust Assessment Summary</h3>
                  <span style={{
                    fontSize: '12px',
                    fontWeight: 700,
                    color: '#10b981',
                    background: 'rgba(16, 185, 129, 0.08)',
                    padding: '4px 10px',
                    borderRadius: '6px',
                    border: '1px solid rgba(16, 185, 129, 0.2)'
                  }}>Verified Host</span>
                </div>
                <p style={{ color: 'var(--text-secondary)', fontSize: '13px', marginTop: '4px' }}>
                  Detailed scoring breakdown of host variables evaluating compromise levels.
                </p>
              </div>

              {/* Big trust meter */}
              <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: '24px',
                background: 'rgba(255,255,255,0.01)',
                border: '1px solid var(--border-color)',
                borderRadius: '12px',
                padding: '20px',
                marginBottom: '32px'
              }}>
                <div style={{
                  width: '80px',
                  height: '80px',
                  borderRadius: '50%',
                  background: `conic-gradient(${getTrustColor(trustDetails.overall_score)} ${trustDetails.overall_score * 3.6}deg, rgba(255,255,255,0.05) 0deg)`,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  boxShadow: `0 0 15px rgba(${
                    trustDetails.overall_score >= 90 ? '16, 185, 129' : trustDetails.overall_score >= 70 ? '245, 158, 11' : '239, 68, 68'
                  }, 0.15)`
                }}>
                  <div style={{
                    width: '66px',
                    height: '66px',
                    borderRadius: '50%',
                    background: '#121824',
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    justifyContent: 'center'
                  }}>
                    <span style={{ fontSize: '20px', fontWeight: 800, color: getTrustColor(trustDetails.overall_score) }}>{trustDetails.overall_score}</span>
                    <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>SCORE</span>
                  </div>
                </div>
                <div>
                  <h4 style={{ fontSize: '16px', fontWeight: 700 }}>Weighted Compromise Ratio</h4>
                  <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '2px', lineHeight: '1.4' }}>
                    Calculated by applying specific safety weights. Score drops whenever endpoint agents reports anomalies.
                  </p>
                </div>
              </div>

              {/* Progress bars list representing parameter weights */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
                {Object.keys(trustDetails.breakdown).map((key) => {
                  const item = trustDetails.breakdown[key];
                  const itemPercentage = (item.score / item.max) * 100;
                  const itemColor = getTrustColor(itemPercentage);
                  
                  return (
                    <div key={key}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '13.5px', marginBottom: '8px' }}>
                        <span style={{ fontWeight: 600, color: 'var(--text-main)' }}>{item.label}</span>
                        <span style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>
                          <strong style={{ color: itemColor }}>{item.score}</strong> / {item.max} pts
                        </span>
                      </div>
                      
                      {/* Bar tracker */}
                      <div style={{
                        background: 'rgba(255,255,255,0.05)',
                        height: '8px',
                        borderRadius: '4px',
                        overflow: 'hidden'
                      }}>
                        <div style={{
                          width: `${itemPercentage}%`,
                          background: itemColor,
                          height: '100%',
                          borderRadius: '4px',
                          boxShadow: `0 0 8px rgba(${
                            itemPercentage >= 90 ? '16, 185, 129' : itemPercentage >= 70 ? '245, 158, 11' : '239, 68, 68'
                          }, 0.35)`,
                          transition: 'width 1s ease-in-out'
                        }}></div>
                      </div>
                    </div>
                  );
                })}
              </div>

              <div style={{
                background: 'rgba(255,255,255,0.015)',
                border: '1px solid var(--border-color)',
                borderRadius: '8px',
                padding: '12px 14px',
                marginTop: '32px',
                fontSize: '12px',
                color: 'var(--text-secondary)',
                display: 'flex',
                gap: '8px'
              }}>
                <Info size={16} color="var(--primary)" style={{ flexShrink: 0 }} />
                <span>Device Trust scoring logic is structured dynamically. Local responses (e.g. quarantining) execute when scores drop below 50.</span>
              </div>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', height: '400px', color: 'var(--text-secondary)', textAlign: 'center' }}>
              <Smartphone size={36} style={{ marginBottom: '12px', opacity: 0.3 }} />
              <p>Select a connected client node to audit its parameters.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
