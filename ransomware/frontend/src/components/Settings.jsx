import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { User, Settings as SettingsIcon, Shield, KeyRound, Copy, Check, Eye, EyeOff } from 'lucide-react';

export default function Settings() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  
  // 2FA Flow states
  const [mfaEnabled, setMfaEnabled] = useState(false);
  const [mfaSetupData, setMfaSetupData] = useState(null); // { qr_code, totp_secret }
  const [otpCode, setOtpCode] = useState('');
  const [passwordToDisable, setPasswordToDisable] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [setupStep, setSetupStep] = useState('idle'); // idle, enrolling, verifying, disabling
  
  const [feedback, setFeedback] = useState({ type: '', message: '' });
  const [copied, setCopied] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);

  useEffect(() => {
    loadUser();
  }, []);

  const [timeRemaining, setTimeRemaining] = useState(30 - (Math.floor(Date.now() / 1000) % 30));

  useEffect(() => {
    if (setupStep !== 'enrolling') return;
    const interval = setInterval(() => {
      setTimeRemaining(30 - (Math.floor(Date.now() / 1000) % 30));
    }, 1000);
    return () => clearInterval(interval);
  }, [setupStep]);

  const loadUser = async () => {
    setLoading(true);
    try {
      const data = await api.getMe();
      setUser(data);
      setMfaEnabled(data.totp_enabled);
    } catch (err) {
      console.error(err);
      showFeedback('error', 'Failed to retrieve user settings context.');
    } finally {
      setLoading(false);
    }
  };

  const showFeedback = (type, message) => {
    setFeedback({ type, message });
    setTimeout(() => setFeedback({ type: '', message: '' }), 5000);
  };

  const handleStartMfaSetup = async () => {
    setActionLoading(true);
    setFeedback({ type: '', message: '' });
    try {
      const data = await api.mfaSetup();
      setMfaSetupData(data);
      setSetupStep('enrolling');
    } catch (err) {
      showFeedback('error', err.message || 'Failed to initialize MFA configuration.');
    } finally {
      setActionLoading(false);
    }
  };

  const handleVerifySetup = async (e) => {
    e.preventDefault();
    if (otpCode.length !== 6) {
      showFeedback('error', 'Authentication code must be exactly 6 digits.');
      return;
    }
    setActionLoading(true);
    setFeedback({ type: '', message: '' });
    try {
      await api.mfaVerify(otpCode);
      showFeedback('success', 'Two-Factor Authentication registered successfully!');
      setMfaEnabled(true);
      setSetupStep('idle');
      setMfaSetupData(null);
      setOtpCode('');
      // Reload user
      const updatedUser = await api.getMe();
      setUser(updatedUser);
    } catch (err) {
      showFeedback('error', err.message || 'MFA validation failed. Check your device clock.');
    } finally {
      setActionLoading(false);
    }
  };

  const handleDisableMfa = async (e) => {
    e.preventDefault();
    if (!passwordToDisable) {
      showFeedback('error', 'Please enter your current administrator password.');
      return;
    }
    setActionLoading(true);
    setFeedback({ type: '', message: '' });
    try {
      await api.mfaDisable(passwordToDisable);
      showFeedback('success', 'Two-Factor Authentication has been disabled.');
      setMfaEnabled(false);
      setSetupStep('idle');
      setPasswordToDisable('');
      // Reload user
      const updatedUser = await api.getMe();
      setUser(updatedUser);
    } catch (err) {
      showFeedback('error', err.message || 'Incorrect password.');
    } finally {
      setActionLoading(false);
    }
  };

  const handleCopySecret = () => {
    if (mfaSetupData?.totp_secret) {
      navigator.clipboard.writeText(mfaSetupData.totp_secret);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div style={{ padding: '32px', maxWidth: '1000px', boxSizing: 'border-box' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '32px' }}>
        <SettingsIcon size={28} color="var(--cyan)" />
        <h1 style={{ fontSize: '26px', fontWeight: 800, color: 'var(--text-main)', margin: 0 }}>Account Settings</h1>
      </div>

      {feedback.message && (
        <div style={{
          background: feedback.type === 'error' ? 'rgba(239, 68, 68, 0.08)' : 'rgba(16, 185, 129, 0.08)',
          border: feedback.type === 'error' ? '1px solid rgba(239, 68, 68, 0.2)' : '1px solid rgba(16, 185, 129, 0.2)',
          color: feedback.type === 'error' ? '#ef4444' : '#10b981',
          padding: '14px 20px',
          borderRadius: '8px',
          fontSize: '14px',
          fontWeight: 500,
          marginBottom: '24px'
        }}>
          {feedback.message}
        </div>
      )}

      {loading ? (
        <div style={{ color: 'var(--text-muted)' }}>Loading settings details...</div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.2fr', gap: '24px', alignItems: 'start' }}>
          
          {/* Profile Details Card */}
          <div className="glass-card" style={{ background: 'var(--bg-card)', padding: '24px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '20px', borderBottom: '1px solid var(--border-color)', paddingBottom: '12px' }}>
              <User size={20} color="var(--text-secondary)" />
              <h2 style={{ fontSize: '18px', color: 'var(--text-main)', margin: 0 }}>Administrator Details</h2>
            </div>
            
            <div style={{ marginBottom: '18px' }}>
              <label style={{ fontSize: '12px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px', fontWeight: 600 }}>Email Address</label>
              <div style={{ color: 'var(--text-main)', fontSize: '15px', fontWeight: 500 }}>{user?.email}</div>
            </div>

            <div style={{ marginBottom: '18px' }}>
              <label style={{ fontSize: '12px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px', fontWeight: 600 }}>Authorization Privilege</label>
              <div style={{ display: 'inline-block', background: 'rgba(16, 185, 129, 0.1)', color: '#10b981', padding: '4px 10px', borderRadius: '6px', fontSize: '11px', fontWeight: 700, textTransform: 'uppercase', border: '1px solid rgba(16, 185, 129, 0.2)' }}>
                {user?.role || 'admin'}
              </div>
            </div>

            <div style={{ marginBottom: '18px' }}>
              <label style={{ fontSize: '12px', color: 'var(--text-muted)', display: 'block', marginBottom: '6px', fontWeight: 600 }}>Security Status Flags</label>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                {user?.break_glass_admin && (
                  <span style={{ display: 'inline-block', background: 'rgba(239, 68, 68, 0.1)', color: '#ef4444', padding: '4px 8px', borderRadius: '6px', fontSize: '10.5px', fontWeight: 700, textTransform: 'uppercase', border: '1px solid rgba(239, 68, 68, 0.2)' }}>
                    🛡️ Break-Glass Admin
                  </span>
                )}
                {user?.mfa_required && (
                  <span style={{ display: 'inline-block', background: 'rgba(245, 158, 11, 0.1)', color: '#f59e0b', padding: '4px 8px', borderRadius: '6px', fontSize: '10.5px', fontWeight: 700, textTransform: 'uppercase', border: '1px solid rgba(245, 158, 11, 0.2)' }}>
                    ⚠️ MFA Required
                  </span>
                )}
                {user?.mfa_enrolled && (
                  <span style={{ display: 'inline-block', background: 'rgba(16, 185, 129, 0.1)', color: '#10b981', padding: '4px 8px', borderRadius: '6px', fontSize: '10.5px', fontWeight: 700, textTransform: 'uppercase', border: '1px solid rgba(16, 185, 129, 0.2)' }}>
                    🟢 MFA Enrolled
                  </span>
                )}
                {user?.mfa_reset_required && (
                  <span style={{ display: 'inline-block', background: 'rgba(59, 130, 246, 0.1)', color: '#3b82f6', padding: '4px 8px', borderRadius: '6px', fontSize: '10.5px', fontWeight: 700, textTransform: 'uppercase', border: '1px solid rgba(59, 130, 246, 0.2)' }}>
                    🔄 MFA Reset Required
                  </span>
                )}
              </div>
            </div>
            
            <div>
              <label style={{ fontSize: '12px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px', fontWeight: 600 }}>Account Provisioned</label>
              <div style={{ color: 'var(--text-secondary)', fontSize: '14px' }}>
                {user?.created_at ? new Date(user.created_at).toLocaleString() : 'Unknown'}
              </div>
            </div>
          </div>

          {/* Security & MFA Card */}
          <div className="glass-card" style={{ background: 'var(--bg-card)', padding: '24px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '20px', borderBottom: '1px solid var(--border-color)', paddingBottom: '12px' }}>
              <Shield size={20} color="var(--text-secondary)" />
              <h2 style={{ fontSize: '18px', color: 'var(--text-main)', margin: 0 }}>Multi-Factor Authentication (2FA)</h2>
            </div>

            {setupStep === 'idle' && (
              <div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px' }}>
                  <div>
                    <div style={{ color: 'var(--text-main)', fontSize: '15px', fontWeight: 600 }}>Google Authenticator / TOTP</div>
                    <div style={{ color: 'var(--text-muted)', fontSize: '12.5px', marginTop: '4px', lineHeight: '1.4' }}>
                      Protects login sessions by requiring an OTP sync key.
                    </div>
                  </div>
                  <span style={{
                    padding: '4px 10px',
                    borderRadius: '6px',
                    fontSize: '11.5px',
                    fontWeight: 700,
                    textTransform: 'uppercase',
                    background: mfaEnabled ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)',
                    color: mfaEnabled ? '#10b981' : '#ef4444',
                    border: mfaEnabled ? '1px solid rgba(16, 185, 129, 0.2)' : '1px solid rgba(239, 68, 68, 0.2)'
                  }}>
                    {mfaEnabled ? 'Enabled' : 'Disabled'}
                  </span>
                </div>

                {!mfaEnabled ? (
                  <button
                    onClick={handleStartMfaSetup}
                    disabled={actionLoading}
                    className="btn-primary"
                    style={{ width: '100%' }}
                  >
                    {actionLoading ? 'Initializing...' : 'Configure Multi-Factor Authentication'}
                  </button>
                ) : (
                  <button
                    onClick={() => setSetupStep('disabling')}
                    className="btn-secondary"
                    style={{ width: '100%', borderColor: 'rgba(239,68,68,0.2)', color: '#ef4444' }}
                    onMouseEnter={e => e.currentTarget.style.background = 'rgba(239,68,68,0.05)'}
                    onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                  >
                    Deactivate Multi-Factor Authentication
                  </button>
                )}
              </div>
            )}

            {/* MFA Enroll Phase */}
            {setupStep === 'enrolling' && mfaSetupData && (
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '20px' }}>
                <p style={{ fontSize: '13.5px', color: 'var(--text-secondary)', textAlign: 'center', margin: 0, lineHeight: '1.5' }}>
                  🔒 Scan the QR code using Google Authenticator or Microsoft Authenticator, then enter the 6-digit verification code.
                </p>

                <div style={{
                  background: '#ffffff',
                  padding: '12px',
                  borderRadius: '12px',
                  display: 'inline-block',
                  boxShadow: '0 0 25px rgba(255, 255, 255, 0.05)'
                }}>
                  <img
                    src={mfaSetupData.qr_code}
                    alt="Authenticator Setup QR"
                    style={{ display: 'block', width: '180px', height: '180px' }}
                  />
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <div style={{ width: '60px', height: '4px', background: 'rgba(255,255,255,0.06)', borderRadius: '2px', overflow: 'hidden', position: 'relative' }}>
                    <div style={{
                      width: `${(timeRemaining / 30) * 100}%`,
                      height: '100%',
                      background: 'var(--cyan, #00f0ff)',
                      transition: 'width 1s linear',
                      boxShadow: '0 0 6px var(--cyan)'
                    }}></div>
                  </div>
                  <span style={{ fontSize: '11.5px', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>Next refresh in {timeRemaining}s</span>
                </div>

                {/* Manual Fallback Key */}
                <div style={{ width: '100%' }}>
                  <label style={{ fontSize: '11px', color: 'var(--text-muted)', display: 'block', marginBottom: '6px', fontWeight: 600 }}>Manual Entry Key</label>
                  <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    background: 'rgba(255,255,255,0.03)',
                    border: '1px solid var(--border-color)',
                    borderRadius: '8px',
                    padding: '8px 12px',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '13px',
                    color: 'var(--cyan)'
                  }}>
                    <span style={{ wordBreak: 'break-all' }}>{mfaSetupData.totp_secret}</span>
                    <button
                      onClick={handleCopySecret}
                      style={{
                        background: 'none',
                        border: 'none',
                        color: 'var(--text-secondary)',
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        marginLeft: '8px'
                      }}
                      title="Copy Secret Key"
                    >
                      {copied ? <Check size={16} color="#10b981" /> : <Copy size={16} />}
                    </button>
                  </div>
                </div>

                {/* Verification code input */}
                <form onSubmit={handleVerifySetup} style={{ width: '100%' }}>
                  <div className="input-group" style={{ marginBottom: '16px' }}>
                    <label className="input-label" htmlFor="otp-verify-input">Verification Code</label>
                    <input
                      id="otp-verify-input"
                      type="text"
                      maxLength={6}
                      required
                      placeholder="000000"
                      className="text-input"
                      value={otpCode}
                      onChange={(e) => setOtpCode(e.target.value.replace(/\D/g, ''))}
                      style={{ width: '100%', textAlign: 'center', fontSize: '18px', letterSpacing: '4px', fontWeight: 700 }}
                    />
                  </div>

                  <div style={{ display: 'flex', gap: '12px' }}>
                    <button
                      type="button"
                      onClick={() => { setSetupStep('idle'); setMfaSetupData(null); setOtpCode(''); }}
                      className="btn-secondary"
                      style={{ flex: 1 }}
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      disabled={actionLoading}
                      className="btn-primary"
                      style={{ flex: 1.5 }}
                    >
                      {actionLoading ? 'Verifying...' : 'Verify & Enable'}
                    </button>
                  </div>
                </form>
              </div>
            )}

            {/* MFA Disable Phase */}
            {setupStep === 'disabling' && (
              <form onSubmit={handleDisableMfa}>
                <p style={{ fontSize: '13.5px', color: 'var(--text-secondary)', marginBottom: '16px', lineHeight: '1.4' }}>
                  ⚠️ Disactivating MFA requires verifying your current security access password.
                </p>

                <div className="input-group" style={{ marginBottom: '20px' }}>
                  <label className="input-label" htmlFor="password-disable-input">Verify Password</label>
                  <div style={{ position: 'relative' }}>
                    <input
                      id="password-disable-input"
                      type={showPassword ? 'text' : 'password'}
                      required
                      placeholder="Enter administrator password"
                      className="text-input"
                      value={passwordToDisable}
                      onChange={(e) => setPasswordToDisable(e.target.value)}
                      style={{ width: '100%', paddingRight: '44px', boxSizing: 'border-box' }}
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      style={{
                        position: 'absolute',
                        right: '14px',
                        top: '50%',
                        transform: 'translateY(-50%)',
                        background: 'none',
                        border: 'none',
                        cursor: 'pointer',
                        color: 'var(--text-muted)',
                        display: 'flex',
                        alignItems: 'center'
                      }}
                    >
                      {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                    </button>
                  </div>
                </div>

                <div style={{ display: 'flex', gap: '12px' }}>
                  <button
                    type="button"
                    onClick={() => { setSetupStep('idle'); setPasswordToDisable(''); }}
                    className="btn-secondary"
                    style={{ flex: 1 }}
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={actionLoading}
                    className="btn-primary"
                    style={{ flex: 1.5, background: 'linear-gradient(135deg, #f87171, #ef4444)', boxShadow: 'none' }}
                  >
                    {actionLoading ? 'Deactivating...' : 'Confirm Deactivation'}
                  </button>
                </div>
              </form>
            )}

          </div>

        </div>
      )}
    </div>
  );
}
