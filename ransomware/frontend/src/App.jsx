import React, { useState, useEffect, useRef } from 'react';
import { api, ApiError } from './services/api';
import Navbar from './components/Navbar';
import Auth from './components/Auth';
import DashboardOverview from './components/DashboardOverview';
import ThreatCenter from './components/ThreatCenter';
import DeviceTrust from './components/DeviceTrust';
import Reports from './components/Reports';
import Recovery from './components/Recovery';
// Phase 2
import MalwareScan from './components/MalwareScan';
import NetworkMonitor from './components/NetworkMonitor';
import WiFiScanner from './components/WiFiScanner';
import FirewallModule from './components/FirewallModule';
// Phase 3
import DeceptionEngine from './components/DeceptionEngine';
import PrivacyDashboard from './components/PrivacyDashboard';
import BrowserProtection from './components/BrowserProtection';
import Settings from './components/Settings';
import LandingPage from './components/LandingPage';

export default function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(api.isAuthenticated());
  const [userEmail, setUserEmail] = useState(localStorage.getItem('email') || '');
  const [activeTab, setActiveTab] = useState('dashboard');
  const [selectedEventId, setSelectedEventId] = useState(null);
  const [summary, setSummary] = useState(null);
  const [loadingSummary, setLoadingSummary] = useState(false);
  const [showAuthScreen, setShowAuthScreen] = useState(false);
  const [isRegisterFromLanding, setIsRegisterFromLanding] = useState(false);
  const pollingRef = useRef(null);

  useEffect(() => {
    if (isAuthenticated) {
      fetchUserContext();
      loadDashboardSummary();
      startPolling();
    } else {
      stopPolling();
    }
    return () => stopPolling();
  }, [isAuthenticated]);

  const fetchUserContext = async () => {
    try {
      const user = await api.getMe();
      setUserEmail(user.email);
    } catch (err) {
      if (err instanceof ApiError && (err.status === 401 || err.status === 403)) {
        console.error('Session expired or invalid:', err.message);
        handleLogout();
        return;
      }
      console.warn('Could not verify session (backend may be unavailable):', err.message);
      const cachedEmail = localStorage.getItem('email');
      if (cachedEmail) setUserEmail(cachedEmail);
    }
  };

  const loadDashboardSummary = async () => {
    try {
      const data = await api.getDashboardSummary();
      setSummary(data);
    } catch (err) {
      console.error("Failed to load summary: ", err);
    }
  };

  const startPolling = () => {
    stopPolling();
    // Poll dashboard summaries every 5 seconds for near-real-time agent logging updates
    pollingRef.current = setInterval(() => {
      loadDashboardSummary();
    }, 5000);
  };

  const stopPolling = () => {
    if (pollingRef.current) {
      clearInterval(pollingRef.current);
      pollingRef.current = null;
    }
  };

  const handleAuthSuccess = (data) => {
    setIsAuthenticated(true);
    setUserEmail(data.email);
  };

  const handleLogout = () => {
    api.logout();
    setIsAuthenticated(false);
    setUserEmail('');
    setSummary(null);
    setActiveTab('dashboard');
    setSelectedEventId(null);
    setShowAuthScreen(false);
  };

  if (!isAuthenticated) {
    if (showAuthScreen) {
      return (
        <Auth 
          onAuthSuccess={handleAuthSuccess} 
          initialIsLogin={!isRegisterFromLanding} 
          onBackToLanding={() => setShowAuthScreen(false)} 
        />
      );
    }
    return (
      <LandingPage 
        onNavigateToAuth={(isLogin) => {
          setIsRegisterFromLanding(!isLogin);
          setShowAuthScreen(true);
        }} 
      />
    );
  }

  return (
    <div className="app-container">
      {/* Sidebar Navigation */}
      <Navbar 
        activeTab={activeTab} 
        setActiveTab={setActiveTab} 
        handleLogout={handleLogout}
        userEmail={userEmail}
      />

      {/* Main Workspace Frame */}
      <div className="main-content">
        {/* Phase 1 Tabs */}
        {activeTab === 'dashboard' && (
          <DashboardOverview 
            summary={summary}
            loading={!summary}
            setActiveTab={setActiveTab}
            setSelectedEventId={setSelectedEventId}
          />
        )}

        {activeTab === 'threats' && (
          <ThreatCenter 
            selectedEventId={selectedEventId}
            setSelectedEventId={setSelectedEventId}
          />
        )}

        {activeTab === 'devices' && <DeviceTrust />}

        {activeTab === 'reports' && <Reports />}

        {/* Phase 2 Tabs */}
        {activeTab === 'malware' && <MalwareScan />}
        {activeTab === 'network' && <NetworkMonitor />}
        {activeTab === 'wifi' && <WiFiScanner />}
        {activeTab === 'firewall' && <FirewallModule />}

        {/* Phase 3 Tabs */}
        {activeTab === 'deception' && <DeceptionEngine />}
        {activeTab === 'privacy' && <PrivacyDashboard />}
        {activeTab === 'browser' && <BrowserProtection />}

        {/* Settings */}
        {activeTab === 'settings' && <Settings />}

        {/* Recovery & Rollback */}
        {activeTab === 'recovery' && <Recovery />}
      </div>
    </div>
  );
}

