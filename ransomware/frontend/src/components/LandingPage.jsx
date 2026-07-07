import React, { useState, useEffect } from 'react';
import { Shield, Terminal, ArrowRight, Activity, Lock, RefreshCw, Layers, Server, Play, CheckCircle2 } from 'lucide-react';

const Github = ({ size = 16, ...props }) => (
  <svg
    height={size}
    width={size}
    viewBox="0 0 16 16"
    fill="currentColor"
    {...props}
  >
    <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z" />
  </svg>
);

export default function LandingPage({ onNavigateToAuth }) {
  const [terminalBooting, setTerminalBooting] = useState(true);
  const [bootLines, setBootLines] = useState([]);
  const [theme, setTheme] = useState(document.documentElement.getAttribute('data-theme') || 'dark');

  const bootSequence = [
    "SENTINELCRYPT EDR INITIALIZATION SEQUENCER v2.4.0-RELEASE",
    "Initializing micro-agents behavior loops... [OK]",
    "Mapping host kernel syscall hooks... [OK]",
    "Loading anti-ransomware heuristical filters... [OK]",
    "Synchronizing SentinelCrypt local-first VSS backup engines... [OK]",
    "Deploying active deception assets & honeytokens... [OK]",
    "SentinelCrypt EDR engine stands ACTIVE. Monitoring for file encryptors."
  ];

  useEffect(() => {
    if (!terminalBooting) return;
    
    let timer;
    let lineIdx = 0;
    
    const printLine = () => {
      if (lineIdx < bootSequence.length) {
        setBootLines(prev => [...prev, bootSequence[lineIdx]]);
        lineIdx++;
        timer = setTimeout(printLine, 350);
      } else {
        timer = setTimeout(() => {
          setTerminalBooting(false);
        }, 800);
      }
    };

    printLine();
    return () => clearTimeout(timer);
  }, [terminalBooting]);

  useEffect(() => {
    const handleThemeChange = () => {
      setTheme(document.documentElement.getAttribute('data-theme') || 'dark');
    };
    window.addEventListener('storage', handleThemeChange);
    
    // Check theme initially
    const observer = new MutationObserver(() => {
      setTheme(document.documentElement.getAttribute('data-theme') || 'dark');
    });
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
    
    return () => {
      window.removeEventListener('storage', handleThemeChange);
      observer.disconnect();
    };
  }, []);

  const features = [
    {
      icon: Activity,
      title: "Real-time Threat Auditing",
      description: "Monitors file creation, entropy anomalies, and unauthorized encryption routines at the kernel level."
    },
    {
      icon: Layers,
      title: "Active Deception Engine",
      description: "Deploys customized honeypots and decoy directory assets to attract and intercept active attacks instantly."
    },
    {
      icon: RefreshCw,
      title: "VSS Snapshots & Recovery",
      description: "Coordinates automated Volume Shadow Copies and isolated rollbacks to restore data in minutes without paying ransoms."
    },
    {
      icon: Lock,
      title: "Multi-Factor Authentication",
      description: "Enforces standard TOTP 2FA compliance protocols ensuring zero administrative compromise."
    }
  ];

  if (terminalBooting) {
    return (
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        minHeight: '100vh',
        width: '100%',
        backgroundColor: '#030509',
        color: '#00f0ff',
        fontFamily: 'var(--font-mono)',
        padding: '32px',
        boxSizing: 'border-box'
      }}>
        <div style={{
          width: '100%',
          maxWidth: '650px',
          background: '#070a10',
          border: '1px solid rgba(0, 240, 255, 0.15)',
          borderRadius: '12px',
          padding: '24px',
          boxShadow: '0 0 40px rgba(0, 240, 255, 0.05)',
          position: 'relative'
        }}>
          {/* Header controls */}
          <div style={{ display: 'flex', gap: '8px', marginBottom: '18px', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '12px' }}>
            <div style={{ width: '12px', height: '12px', borderRadius: '50%', backgroundColor: '#ef4444' }}></div>
            <div style={{ width: '12px', height: '12px', borderRadius: '50%', backgroundColor: '#f59e0b' }}></div>
            <div style={{ width: '12px', height: '12px', borderRadius: '50%', backgroundColor: '#10b981' }}></div>
            <span style={{ fontSize: '11px', color: 'rgba(255,255,255,0.3)', marginLeft: '12px', fontFamily: 'var(--font-primary)' }}>terminal_boot.sh</span>
          </div>
          
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', minHeight: '200px' }}>
            {bootLines.map((line, idx) => (
              <div key={idx} style={{
                color: idx === bootLines.length - 1 && line && line.includes("ACTIVE") ? '#10b981' : '#00f0ff',
                fontSize: '13.5px',
                lineHeight: '1.5',
                display: 'flex',
                alignItems: 'center',
                gap: '8px'
              }}>
                <span style={{ color: 'rgba(255,255,255,0.2)' }}>$</span>
                {line}
              </div>
            ))}
            <div style={{ width: '6px', height: '15px', backgroundColor: '#00f0ff', display: 'inline-block', animation: 'pulse 1s infinite', marginTop: '4px' }}></div>
          </div>

          <button 
            onClick={() => setTerminalBooting(false)}
            style={{
              position: 'absolute',
              bottom: '24px',
              right: '24px',
              background: 'transparent',
              border: '1px solid rgba(255,255,255,0.1)',
              color: 'var(--text-secondary)',
              padding: '6px 12px',
              borderRadius: '6px',
              fontSize: '11px',
              fontFamily: 'var(--font-primary)',
              cursor: 'pointer',
              transition: 'all 0.2s'
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.borderColor = 'rgba(255,255,255,0.2)';
              e.currentTarget.style.color = '#ffffff';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.borderColor = 'rgba(255,255,255,0.1)';
              e.currentTarget.style.color = 'var(--text-secondary)';
            }}
          >
            Skip Intro
          </button>
        </div>
      </div>
    );
  }

  return (
    <div style={{
      width: '100%',
      minHeight: '100vh',
      backgroundColor: 'var(--bg-landing, #020408)',
      backgroundImage: theme === 'dark' 
        ? 'radial-gradient(circle at 50% 35%, rgba(5, 7, 13, 0.2) 0%, rgba(2, 4, 8, 0.97) 75%), linear-gradient(rgba(0, 240, 255, 0.012) 1px, transparent 1px) 0 0 / 50px 50px, linear-gradient(90deg, rgba(0, 240, 255, 0.012) 1px, transparent 1px) 0 0 / 50px 50px'
        : 'radial-gradient(circle at 50% 35%, rgba(255, 255, 255, 0.8) 0%, rgba(241, 245, 249, 0.98) 85%), linear-gradient(rgba(2, 132, 199, 0.01) 1px, transparent 1px) 0 0 / 50px 50px, linear-gradient(90deg, rgba(2, 132, 199, 0.01) 1px, transparent 1px) 0 0 / 50px 50px',
      color: 'var(--text-main)',
      display: 'flex',
      flexDirection: 'column',
      fontFamily: 'var(--font-primary)',
      transition: 'background-color 0.3s ease, color 0.3s ease'
    }}>
      {/* Landing Header */}
      <header style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '24px 8%',
        borderBottom: '1px solid var(--border-color, rgba(255,255,255,0.06))',
        backdropFilter: 'blur(8px)',
        position: 'sticky',
        top: 0,
        zIndex: 100,
        background: 'var(--bg-panel-opaque, rgba(5, 7, 13, 0.6))'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{
            background: 'linear-gradient(135deg, var(--primary, #4facfe), var(--cyan, #00f0ff))',
            padding: '8px',
            borderRadius: '8px',
            boxShadow: '0 0 15px var(--cyan-glow, rgba(0, 240, 255, 0.2))',
            display: 'flex',
            alignItems: 'center'
          }}>
            <Shield size={20} color="#040810" />
          </div>
          <span style={{ fontSize: '20px', fontWeight: 800, letterSpacing: '0.02em' }}>SentinelCrypt EDR</span>
        </div>

        <nav style={{ display: 'flex', alignItems: 'center', gap: '32px' }}>
          <a href="#features" style={{ color: 'var(--text-secondary)', textDecoration: 'none', fontSize: '14px', fontWeight: 500, transition: 'color 0.2s' }}
             onMouseEnter={e => e.currentTarget.style.color = 'var(--text-main)'}
             onMouseLeave={e => e.currentTarget.style.color = 'var(--text-secondary)'}>Features</a>
          <a href="#architecture" style={{ color: 'var(--text-secondary)', textDecoration: 'none', fontSize: '14px', fontWeight: 500, transition: 'color 0.2s' }}
             onMouseEnter={e => e.currentTarget.style.color = 'var(--text-main)'}
             onMouseLeave={e => e.currentTarget.style.color = 'var(--text-secondary)'}>Architecture</a>
          <a href="https://github.com" target="_blank" rel="noopener noreferrer" style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--text-secondary)', textDecoration: 'none', fontSize: '14px', fontWeight: 500, transition: 'color 0.2s' }}
             onMouseEnter={e => e.currentTarget.style.color = 'var(--text-main)'}
             onMouseLeave={e => e.currentTarget.style.color = 'var(--text-secondary)'}>
            <Github size={15} /> GitHub
          </a>
        </nav>

        <div style={{ display: 'flex', gap: '12px' }}>
          <button 
            onClick={() => onNavigateToAuth(true)}
            style={{
              background: 'transparent',
              border: '1px solid var(--border-color, rgba(255,255,255,0.08))',
              color: 'var(--text-main)',
              padding: '8px 18px',
              borderRadius: '8px',
              fontSize: '13.5px',
              fontWeight: 600,
              cursor: 'pointer',
              transition: 'var(--transition)'
            }}
            onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.04)'}
            onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
          >
            Sign In
          </button>
          <button 
            onClick={() => onNavigateToAuth(false)}
            className="btn-primary"
            style={{
              padding: '8px 18px',
              fontSize: '13.5px',
              boxShadow: '0 0 15px var(--cyan-glow)'
            }}
          >
            Register
          </button>
        </div>
      </header>

      {/* Main Hero */}
      <section style={{
        padding: '100px 8% 80px',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        textAlign: 'center',
        maxWidth: '900px',
        margin: '0 auto',
        flex: 1
      }}>
        <div style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '8px',
          background: 'rgba(0, 240, 255, 0.06)',
          border: '1px solid rgba(0, 240, 255, 0.15)',
          color: 'var(--cyan, #00f0ff)',
          padding: '6px 14px',
          borderRadius: '9999px',
          fontSize: '12.5px',
          fontWeight: 600,
          letterSpacing: '0.04em',
          textTransform: 'uppercase',
          marginBottom: '24px'
        }}>
          <Server size={14} /> Local-first Enterprise Protection
        </div>

        {/* Animated Shield Logo Mark */}
        <div style={{ marginBottom: '28px' }}>
          <svg
            width="80"
            height="80"
            viewBox="0 0 100 100"
            style={{
              filter: 'drop-shadow(0 0 15px var(--cyan-glow, rgba(0, 240, 255, 0.35)))',
              animation: 'shieldPulse 3s ease-in-out infinite'
            }}
          >
            <defs>
              <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="var(--primary, #4facfe)" />
                <stop offset="100%" stopColor="var(--cyan, #00f0ff)" />
              </linearGradient>
              <linearGradient id="shieldGradInner" x1="0%" y1="100%" x2="100%" y2="0%">
                <stop offset="0%" stopColor="var(--cyan, #00f0ff)" />
                <stop offset="100%" stopColor="var(--primary, #9B51E0)" />
              </linearGradient>
            </defs>
            {/* Outer Hexagon/Shield frame */}
            <path
              d="M50 5 L90 25 L90 60 L50 95 L10 60 L10 25 Z"
              fill="none"
              stroke="url(#shieldGrad)"
              strokeWidth="3.5"
              strokeDasharray="300"
              strokeDashoffset="300"
              style={{
                animation: 'drawShield 2.5s ease-out forwards'
              }}
            />
            {/* Inner Shield mark */}
            <path
              d="M50 18 L80 32 L80 58 L50 82 L20 58 L20 32 Z"
              fill="rgba(0, 240, 255, 0.03)"
              stroke="url(#shieldGradInner)"
              strokeWidth="2.5"
              strokeDasharray="200"
              strokeDashoffset="200"
              style={{
                animation: 'drawShield 2s ease-out 0.5s forwards'
              }}
            />
            {/* Core lock node */}
            <circle
              cx="50"
              cy="50"
              r="6"
              fill="var(--cyan)"
              style={{
                animation: 'nodePulse 2s ease-in-out infinite'
              }}
            />
          </svg>
          
          <style>{`
            @keyframes shieldPulse {
              0%, 100% { transform: translateY(0) scale(1); filter: drop-shadow(0 0 12px rgba(0, 240, 255, 0.3)); }
              50% { transform: translateY(-6px) scale(1.02); filter: drop-shadow(0 0 25px rgba(0, 240, 255, 0.6)); }
            }
            @keyframes drawShield {
              to { stroke-dashoffset: 0; }
            }
            @keyframes nodePulse {
              0%, 100% { transform: scale(1); opacity: 0.8; }
              50% { transform: scale(1.3); opacity: 1; fill: var(--primary); }
            }
          `}</style>
        </div>

        <h1 style={{
          fontSize: '52px',
          fontWeight: 800,
          lineHeight: '1.15',
          letterSpacing: '-0.02em',
          marginBottom: '20px'
        }}>
          Advanced Endpoint Defense & <br/>
          <span style={{
            background: 'linear-gradient(90deg, var(--primary, #4facfe), var(--cyan, #00f0ff))',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent'
          }}>Automated Snapshot Recovery</span>
        </h1>

        <p style={{
          fontSize: '18px',
          color: 'var(--text-secondary)',
          lineHeight: '1.6',
          maxWidth: '720px',
          marginBottom: '40px'
        }}>
          SentinelCrypt EDR operates continuously at the endpoint level to intercept malicious encryptors, orchestrate deception honeytokens, and manage automated file recovery.
        </p>

        <div style={{ display: 'flex', gap: '16px' }}>
          <button 
            onClick={() => onNavigateToAuth(true)}
            className="btn-primary"
            style={{
              padding: '14px 28px',
              fontSize: '15px',
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
              boxShadow: '0 0 20px var(--cyan-glow)'
            }}
          >
            Access SentinelCrypt EDR Console <ArrowRight size={16} />
          </button>
        </div>

        {/* Console Preview frame */}
        <div style={{
          marginTop: '60px',
          width: '100%',
          maxWidth: '850px',
          background: 'var(--bg-panel, #05070d)',
          border: '1px solid var(--border-color, rgba(255,255,255,0.08))',
          borderRadius: '16px',
          padding: '6px',
          boxShadow: '0 30px 70px rgba(0,0,0,0.5)',
          overflow: 'hidden'
        }}>
          <div style={{
            background: 'var(--bg-dark, #080b11)',
            borderRadius: '12px',
            padding: '20px',
            textAlign: 'left',
            fontFamily: 'var(--font-mono)',
            fontSize: '13px',
            color: 'var(--text-secondary)',
            border: '1px solid rgba(255,255,255,0.03)'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.06)', paddingBottom: '12px', marginBottom: '14px' }}>
              <span style={{ color: 'var(--text-main)', fontWeight: 600 }}>🛡️ sentinelcrypt_agent_status</span>
              <span style={{ color: '#10b981' }}>● SYNCHRONIZED</span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
              <div>
                <p style={{ margin: '4px 0' }}>• Hostname: <span style={{ color: 'var(--text-main)' }}>SOC-ENDPOINT-09</span></p>
                <p style={{ margin: '4px 0' }}>• Kernel Driver: <span style={{ color: '#00f0ff' }}>sentinel_filter.sys</span></p>
                <p style={{ margin: '4px 0' }}>• Heuristic Model: <span style={{ color: 'var(--text-main)' }}>SentinelCrypt Heuristics v3.1</span></p>
              </div>
              <div>
                <p style={{ margin: '4px 0' }}>• Active Honeypots: <span style={{ color: '#a855f7' }}>12 Configured</span></p>
                <p style={{ margin: '4px 0' }}>• Backup Snapshots: <span style={{ color: '#10b981' }}>Secure / VSS Enabled</span></p>
                <p style={{ margin: '4px 0' }}>• Alert Channels: <span style={{ color: 'var(--text-main)' }}>FastAPI Webhook</span></p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Features Grid */}
      <section id="features" style={{
        padding: '80px 8%',
        background: theme === 'dark' ? 'rgba(255,255,255,0.01)' : 'rgba(0,0,0,0.01)',
        borderTop: '1px solid var(--border-color, rgba(255,255,255,0.06))',
        borderBottom: '1px solid var(--border-color, rgba(255,255,255,0.06))'
      }}>
        <div style={{ textAlign: 'center', marginBottom: '52px' }}>
          <h2 style={{ fontSize: '32px', fontWeight: 800, marginBottom: '12px' }}>Engineered for Deep Defense</h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '15px' }}>Four protective abstraction pillars deployed natively on your critical systems.</p>
        </div>

        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
          gap: '24px',
          maxWidth: '1100px',
          margin: '0 auto'
        }}>
          {features.map((f, i) => {
            const Icon = f.icon;
            return (
              <div key={i} className="glass-card" style={{
                background: 'var(--bg-card)',
                padding: '28px',
                borderRadius: '12px',
                textAlign: 'left'
              }}>
                <div style={{
                  background: 'rgba(79, 172, 254, 0.08)',
                  padding: '10px',
                  borderRadius: '8px',
                  display: 'inline-block',
                  color: 'var(--cyan)',
                  marginBottom: '16px'
                }}>
                  <Icon size={22} />
                </div>
                <h3 style={{ fontSize: '17px', fontWeight: 700, marginBottom: '10px' }}>{f.title}</h3>
                <p style={{ fontSize: '14px', color: 'var(--text-secondary)', lineHeight: '1.5' }}>{f.description}</p>
              </div>
            );
          })}
        </div>
      </section>

      {/* Architecture Overview */}
      <section id="architecture" style={{
        padding: '80px 8%',
        maxWidth: '1000px',
        margin: '0 auto',
        textAlign: 'center'
      }}>
        <h2 style={{ fontSize: '32px', fontWeight: 800, marginBottom: '16px' }}>SentinelCrypt EDR Architecture</h2>
        <p style={{ color: 'var(--text-secondary)', fontSize: '15px', marginBottom: '48px', maxWidth: '600px', margin: '0 auto 48px' }}>
          A local service framework designed for minimum latency and zero cloud dependency unless orchestrated.
        </p>

        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(3, 1fr)',
          gap: '20px',
          alignItems: 'center',
          position: 'relative'
        }}>
          <div style={{ border: '1px dashed var(--border-color)', padding: '24px', borderRadius: '12px', background: 'rgba(255,255,255,0.01)' }}>
            <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--cyan)', display: 'block', marginBottom: '8px' }}>STAGE 01</span>
            <h4 style={{ fontSize: '15px', fontWeight: 700, marginBottom: '4px' }}>System Agent</h4>
            <p style={{ fontSize: '12.5px', color: 'var(--text-secondary)' }}>Lightweight monitor tracks kernel logs, files and network hooks locally.</p>
          </div>
          
          <div style={{ border: '1px dashed var(--border-color)', padding: '24px', borderRadius: '12px', background: 'rgba(255,255,255,0.01)' }}>
            <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--primary)', display: 'block', marginBottom: '8px' }}>STAGE 02</span>
            <h4 style={{ fontSize: '15px', fontWeight: 700, marginBottom: '4px' }}>FastAPI Controller</h4>
            <p style={{ fontSize: '12.5px', color: 'var(--text-secondary)' }}>Validates telemetry data, applies correlation algorithms and manages secrets.</p>
          </div>

          <div style={{ border: '1px dashed var(--border-color)', padding: '24px', borderRadius: '12px', background: 'rgba(255,255,255,0.01)' }}>
            <span style={{ fontSize: '12px', fontWeight: 700, color: '#10b981', display: 'block', marginBottom: '8px' }}>STAGE 03</span>
            <h4 style={{ fontSize: '15px', fontWeight: 700, marginBottom: '4px' }}>Incident Console</h4>
            <p style={{ fontSize: '12.5px', color: 'var(--text-secondary)' }}>SOC analysts investigate anomalies, view timelines, and initiate backups restore.</p>
          </div>
        </div>
      </section>

      {/* Trust & Stats */}
      <section style={{
        padding: '60px 8%',
        background: theme === 'dark' ? 'rgba(79, 172, 254, 0.02)' : 'rgba(2, 132, 199, 0.02)',
        borderTop: '1px solid var(--border-color)',
        textAlign: 'center'
      }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-around', gap: '32px', maxWidth: '1000px', margin: '0 auto' }}>
          <div>
            <h3 style={{ fontSize: '42px', fontWeight: 800, color: 'var(--cyan)' }}>&lt; 50ms</h3>
            <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '4px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Response Interception Time</p>
          </div>
          <div>
            <h3 style={{ fontSize: '42px', fontWeight: 800, color: '#10b981' }}>100%</h3>
            <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '4px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Offline Operational Trust</p>
          </div>
          <div>
            <h3 style={{ fontSize: '42px', fontWeight: 800, color: 'var(--primary)' }}>Zero</h3>
            <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '4px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Cloud Dependency Backups</p>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer style={{
        marginTop: 'auto',
        padding: '48px 8% 24px',
        borderTop: '1px solid var(--border-color, rgba(255,255,255,0.06))',
        background: 'var(--bg-sidebar, #03050a)',
        fontSize: '13.5px',
        color: 'var(--text-secondary)'
      }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', gap: '40px', maxWidth: '1100px', margin: '0 auto', marginBottom: '32px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
              <Shield size={18} color="var(--cyan)" />
              <span style={{ fontSize: '16px', fontWeight: 800, color: 'var(--text-main)' }}>SentinelCrypt EDR</span>
            </div>
            <p style={{ maxWidth: '320px', lineHeight: '1.5' }}>Advanced anti-ransomware auditing, honeypot deceptions and automated volume snapshots backups recovery.</p>
          </div>

          <div style={{ display: 'flex', gap: '60px' }}>
            <div>
              <h4 style={{ color: 'var(--text-main)', fontWeight: 600, marginBottom: '12px' }}>Platform</h4>
              <p style={{ margin: '6px 0' }}><a href="#features" style={{ color: 'inherit', textDecoration: 'none' }}>Capabilities</a></p>
              <p style={{ margin: '6px 0' }}><a href="#architecture" style={{ color: 'inherit', textDecoration: 'none' }}>System Design</a></p>
            </div>
            <div>
              <h4 style={{ color: 'var(--text-main)', fontWeight: 600, marginBottom: '12px' }}>Source Code</h4>
              <p style={{ margin: '6px 0' }}>
                <a href="https://github.com" target="_blank" rel="noopener noreferrer" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', color: 'inherit', textDecoration: 'none' }}>
                  <Github size={14} /> Repository
                </a>
              </p>
            </div>
          </div>
        </div>

        <div style={{ borderTop: '1px solid rgba(255,255,255,0.04)', paddingTop: '20px', display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px', maxWidth: '1100px', margin: '0 auto' }}>
          <span>© {new Date().getFullYear()} SentinelCrypt EDR. All rights reserved.</span>
        </div>
      </footer>
    </div>
  );
}
