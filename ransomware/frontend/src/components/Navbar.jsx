import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  LayoutDashboard, 
  AlertOctagon, 
  Smartphone, 
  FileSpreadsheet, 
  LogOut,
  Bug,
  Activity,
  Wifi,
  ShieldCheck,
  Crosshair,
  Lock,
  Settings,
  RotateCcw,
  Globe,
  Sun,
  Moon
} from 'lucide-react';

export default function Navbar({ activeTab, setActiveTab, handleLogout, userEmail }) {
  const [theme, setTheme] = useState(document.documentElement.getAttribute('data-theme') || 'dark');

  const toggleTheme = () => {
    const nextTheme = theme === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', nextTheme);
    localStorage.setItem('theme', nextTheme);
    setTheme(nextTheme);
  };
  const navSections = [
    {
      label: 'Core Services',
      items: [
        { id: 'dashboard', name: 'Dashboard', icon: LayoutDashboard },
        { id: 'threats', name: 'Threat Center', icon: AlertOctagon },
        { id: 'devices', name: 'Device Trust', icon: Smartphone },
        { id: 'reports', name: 'Reports', icon: FileSpreadsheet },
      ]
    },
    {
      label: 'Incident Response',
      items: [
        { id: 'recovery', name: 'Recovery & Rollback', icon: RotateCcw },
      ]
    },
    {
      label: 'Active Protection',
      items: [
        { id: 'malware', name: 'Malware Scan', icon: Bug },
        { id: 'network', name: 'Network Monitor', icon: Activity },
        { id: 'wifi', name: 'Wi-Fi Scanner', icon: Wifi },
        { id: 'firewall', name: 'Firewall', icon: ShieldCheck },
      ]
    },
    {
      label: 'Threat Intelligence',
      items: [
        { id: 'deception', name: 'Deception Engine', icon: Crosshair },
        { id: 'privacy', name: 'Privacy', icon: Lock },
        { id: 'browser', name: 'Browser Protection', icon: Globe },
      ]
    },
    {
      label: 'System Management',
      items: [
        { id: 'settings', name: 'Settings', icon: Settings },
      ]
    },
  ];

  return (
    <div style={{
      width: '260px',
      background: 'var(--bg-sidebar)',
      borderRight: '1px solid var(--border-color)',
      padding: '24px',
      display: 'flex',
      flexDirection: 'column',
      position: 'fixed',
      top: 0,
      bottom: 0,
      left: 0,
      zIndex: 10
    }}>
      {/* Brand Header */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
        marginBottom: '40px',
        padding: '0 8px'
      }}>
        <div style={{
          background: 'linear-gradient(135deg, var(--primary), var(--cyan))',
          padding: '8px',
          borderRadius: '8px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          boxShadow: '0 0 10px var(--cyan-glow)'
        }}>
          <Shield size={22} color="#040810" strokeWidth={2.5} />
        </div>
        <div>
          <h2 style={{
            fontSize: '18px',
            fontWeight: 800,
            letterSpacing: '0.02em',
            background: 'linear-gradient(90deg, #ffffff, #a0aec0)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent'
          }}>SentinelCrypt</h2>
          <span style={{
            fontSize: '11px',
            color: 'var(--cyan)',
            fontWeight: 600,
            letterSpacing: '0.1em',
            textTransform: 'uppercase'
          }}>EDR</span>
        </div>
      </div>

      {/* Nav List */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', flex: 1, overflowY: 'auto', marginRight: '-4px', paddingRight: '4px' }}>
        {navSections.map((section) => (
          <div key={section.label} style={{ marginBottom: '8px' }}>
            <div style={{
              fontSize: '9px', fontWeight: 800, color: 'var(--text-muted)',
              textTransform: 'uppercase', letterSpacing: '0.1em',
              padding: '4px 16px 6px',
            }}>{section.label}</div>
            {section.items.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '12px',
                padding: '9px 16px',
                borderRadius: '8px',
                border: 'none',
                background: isActive ? 'rgba(79, 172, 254, 0.08)' : 'transparent',
                color: isActive ? 'var(--cyan)' : 'var(--text-secondary)',
                fontFamily: 'var(--font-primary)',
                fontSize: '13px',
                fontWeight: isActive ? 600 : 500,
                textAlign: 'left',
                cursor: 'pointer',
                transition: 'var(--transition)',
                boxShadow: isActive ? 'inset 0 0 0 1px rgba(0, 242, 254, 0.15)' : 'none',
                width: '100%',
              }}
            >
              <Icon size={16} strokeWidth={isActive ? 2.2 : 1.8} />
              {item.name}
            </button>
          );
        })}
          </div>
        ))}
      </div>

      {/* User Session Footer */}
      <div style={{
        borderTop: '1px solid var(--border-color)',
        paddingTop: '20px',
        display: 'flex',
        flexDirection: 'column',
        gap: '12px'
      }}>
        {/* Theme Toggle Button */}
        <button
          onClick={toggleTheme}
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '9px 16px',
            borderRadius: '8px',
            border: '1px solid var(--border-color)',
            background: 'rgba(255, 255, 255, 0.02)',
            color: 'var(--text-secondary)',
            fontFamily: 'var(--font-primary)',
            fontSize: '13px',
            fontWeight: 500,
            cursor: 'pointer',
            transition: 'var(--transition)',
            width: '100%',
          }}
          onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(255, 255, 255, 0.05)'}
          onMouseLeave={(e) => e.currentTarget.style.background = 'rgba(255, 255, 255, 0.02)'}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            {theme === 'dark' ? <Sun size={15} color="var(--cyan)" /> : <Moon size={15} color="var(--cyan)" />}
            <span>{theme === 'dark' ? 'Light Theme' : 'Dark Theme'}</span>
          </div>
          <span style={{ fontSize: '10px', textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: 700 }}>
            {theme}
          </span>
        </button>

        <div style={{ padding: '0 8px' }}>
          <p style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 500, textTransform: 'uppercase' }}>Signed in as</p>
          <p style={{
            fontSize: '13px',
            color: 'var(--text-main)',
            fontWeight: 600,
            whiteSpace: 'nowrap',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            marginTop: '2px'
          }} title={userEmail}>
            {userEmail}
          </p>
        </div>
        <button
          onClick={handleLogout}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '12px',
            padding: '12px 16px',
            borderRadius: '8px',
            border: '1px solid rgba(239, 68, 68, 0.2)',
            background: 'rgba(239, 68, 68, 0.03)',
            color: '#ef4444',
            fontFamily: 'var(--font-primary)',
            fontSize: '14px',
            fontWeight: 600,
            cursor: 'pointer',
            transition: 'var(--transition)'
          }}
          onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(239, 68, 68, 0.08)'}
          onMouseLeave={(e) => e.currentTarget.style.background = 'rgba(239, 68, 68, 0.03)'}
        >
          <LogOut size={16} />
          Sign Out
        </button>
      </div>
    </div>
  );
}
