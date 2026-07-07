import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { Shield, Eye, EyeOff, KeyRound, Mail, Info, ArrowLeft, Copy, Check } from 'lucide-react';
import ForgotPassword from './ForgotPassword';

export default function Auth({ onAuthSuccess, initialIsLogin = true, onBackToLanding }) {
  const [showForgotPassword, setShowForgotPassword] = useState(false);
  const [isLogin, setIsLogin] = useState(initialIsLogin);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [step, setStep] = useState(1); // 1 = credentials, 2 = TOTP verify, 3 = TOTP enroll setup
  const [enrollStep, setEnrollStep] = useState(1); // 1 = show QR, 2 = show OTP verification input
  const [otpCode, setOtpCode] = useState('');
  const [error, setError] = useState('');
  const [totpEnabled, setTotpEnabled] = useState(false);
  const [loading, setLoading] = useState(false);
  const [mfaSetupData, setMfaSetupData] = useState(null);
  const [copied, setCopied] = useState(false);
  const [showManualKey, setShowManualKey] = useState(false);
  const [successState, setSuccessState] = useState('');
  const [theme, setTheme] = useState(document.documentElement.getAttribute('data-theme') || 'dark');

  useEffect(() => {
    const observer = new MutationObserver(() => {
      setTheme(document.documentElement.getAttribute('data-theme') || 'dark');
    });
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
    return () => observer.disconnect();
  }, []);

  const [timeRemaining, setTimeRemaining] = useState(30 - (Math.floor(Date.now() / 1000) % 30));

  useEffect(() => {
    if (step !== 2 && (step !== 3 || enrollStep !== 2)) return;
    const interval = setInterval(() => {
      setTimeRemaining(30 - (Math.floor(Date.now() / 1000) % 30));
    }, 1000);
    return () => clearInterval(interval);
  }, [step, enrollStep]);

  const handleCopySecret = () => {
    if (mfaSetupData?.totp_secret) {
      navigator.clipboard.writeText(mfaSetupData.totp_secret);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleCredentialsSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      if (isLogin) {
        const data = await api.login(email, password);
        if (data.detail === "MFA required") {
          setStep(2);
          setTotpEnabled(true);
        } else if (data.detail === "MFA enrollment required") {
          setMfaSetupData(data);
          setStep(3);
          setEnrollStep(1); // First step: Scan QR code
        } else {
          // Logged in directly since MFA is disabled (break-glass admin case)
          setSuccessState('login_success');
          setTimeout(() => {
            onAuthSuccess(data);
          }, 1800);
        }
      } else {
        await api.register(email, password);
        setSuccessState('register_success');
        setTimeout(() => {
          setSuccessState('');
          setIsLogin(true);
          setError('Account created successfully! Please log in to configure MFA.');
        }, 1800);
      }
    } catch (err) {
      setError(err.message || 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  const handleOtpSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const data = await api.verifyOtp(email, otpCode);
      setSuccessState(step === 3 ? 'mfa_success' : 'login_success');
      setTimeout(() => {
        onAuthSuccess(data);
      }, 1800);
    } catch (err) {
      setError(err.message || 'Invalid or expired MFA code.');
    } finally {
      setLoading(false);
    }
  };

  if (showForgotPassword) {
    return <ForgotPassword onBackToLogin={() => setShowForgotPassword(false)} />;
  }

  if (successState) {
    return (
      <div style={{
        width: '100%',
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: 'var(--bg-landing, #020408)',
        padding: '24px',
        boxSizing: 'border-box'
      }}>
        <div className="glass-card" style={{
          width: '100%',
          maxWidth: '420px',
          padding: '48px 36px',
          textAlign: 'center',
          background: 'var(--bg-card, #05070d)',
          border: '1px solid rgba(16, 185, 129, 0.2)',
          boxShadow: '0 20px 50px rgba(0, 0, 0, 0.4)',
          borderRadius: '16px',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          gap: '24px'
        }}>
          {/* Animated Glowing Success Shield */}
          <div className="pulse-ring-container" style={{
            position: 'relative',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: '90px',
            height: '90px',
            borderRadius: '50%',
            background: 'rgba(16, 185, 129, 0.08)',
            border: '2px solid #10b981',
            boxShadow: '0 0 30px rgba(16, 185, 129, 0.3)',
            animation: 'shieldPulseRing 1.8s ease-out infinite'
          }}>
            <Shield size={44} color="#10b981" style={{ animation: 'shieldLockVerify 1.2s ease-out forwards' }} />
          </div>

          <div>
            <h3 style={{ fontSize: '22px', fontWeight: 800, color: 'var(--text-main)', margin: '0 0 8px 0' }}>
              {successState === 'login_success' ? 'Identity Verified' : successState === 'mfa_success' ? 'Device Enrolled' : 'Account Registered'}
            </h3>
            <p style={{ color: 'var(--text-secondary)', fontSize: '14px', margin: 0, lineHeight: '1.5' }}>
              {successState === 'login_success' 
                ? 'Securing terminal channel and loading compliance modules...'
                : successState === 'mfa_success'
                  ? 'TOTP verification credentials accepted. Redirecting to workspace...'
                  : 'Administrative security account created successfully. Proceeding...'}
            </p>
          </div>

          <style>{`
            @keyframes shieldPulseRing {
              0% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.4); }
              70% { box-shadow: 0 0 0 15px rgba(16, 185, 129, 0); }
              100% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
            }
            @keyframes shieldLockVerify {
              0% { transform: scale(0.6) rotate(-45deg); opacity: 0; }
              70% { transform: scale(1.1) rotate(10deg); }
              100% { transform: scale(1) rotate(0); opacity: 1; }
            }
            @media (prefers-reduced-motion: reduce) {
              .pulse-ring-container, svg { animation: none !important; transition: none !important; }
            }
          `}</style>
        </div>
      </div>
    );
  }

  return (
    <div style={{
      width: '100%',
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      backgroundColor: 'var(--bg-landing, #020408)',
      padding: '24px',
      boxSizing: 'border-box'
    }}>
      {/* Container Card */}
      <div className="glass-card" style={{
        width: '100%',
        maxWidth: '420px',
        padding: '36px',
        position: 'relative',
        background: 'var(--bg-card, #05070d)',
        border: '1px solid var(--border-color, rgba(255,255,255,0.06))',
        boxShadow: '0 20px 50px rgba(0, 0, 0, 0.3)',
        borderRadius: '16px'
      }}>
        {/* Back navigation */}
        {onBackToLanding && step === 1 && (
          <button
            onClick={onBackToLanding}
            style={{
              position: 'absolute',
              top: '24px',
              left: '24px',
              background: 'none',
              border: 'none',
              color: 'var(--text-secondary)',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              fontSize: '13px',
              fontWeight: 500,
              fontFamily: 'var(--font-primary)'
            }}
          >
            <ArrowLeft size={15} /> Back
          </button>
        )}

        {/* Logo Header */}
        <div style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          marginBottom: '32px',
          marginTop: onBackToLanding ? '16px' : '0'
        }}>
          <div style={{
            background: 'linear-gradient(135deg, var(--primary, #4facfe), var(--cyan, #00f0ff))',
            padding: '12px',
            borderRadius: '12px',
            boxShadow: '0 0 20px var(--cyan-glow, rgba(0, 240, 255, 0.2))',
            marginBottom: '16px',
            display: 'flex',
            alignItems: 'center'
          }}>
            <Shield size={28} color="#040810" />
          </div>
          <h2 style={{ fontSize: '24px', fontWeight: 800, letterSpacing: '-0.02em', color: 'var(--text-main)' }}>SentinelCrypt EDR</h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '14px', marginTop: '6px', textAlign: 'center' }}>
            {step === 1 
              ? (isLogin ? 'Endpoint Detection & Response Console' : 'Create Admin Security Account') 
              : step === 2
                ? 'Two-Factor Authentication Enforced'
                : 'MFA Device Registration'}
          </p>
        </div>

        {error && (
          <div style={{
            background: error.includes('successfully') ? 'rgba(16, 185, 129, 0.08)' : 'rgba(239, 68, 68, 0.08)',
            border: error.includes('successfully') ? '1px solid rgba(16, 185, 129, 0.2)' : '1px solid rgba(239, 68, 68, 0.2)',
            borderRadius: '8px',
            padding: '12px 16px',
            color: error.includes('successfully') ? '#10b981' : '#ef4444',
            fontSize: '13.5px',
            marginBottom: '24px',
            display: 'flex',
            alignItems: 'center',
            gap: '10px'
          }}>
            <Info size={16} style={{ flexShrink: 0 }} />
            <span>{error}</span>
          </div>
        )}

        {step === 1 && (
          /* Credentials Form */
          <form onSubmit={handleCredentialsSubmit}>
            <div className="input-group">
              <label className="input-label" htmlFor="email-input">Email Address</label>
              <div style={{ position: 'relative' }}>
                <Mail size={18} color="var(--text-muted)" style={{
                  position: 'absolute',
                  left: '14px',
                  top: '50%',
                  transform: 'translateY(-50%)'
                }} />
                <input
                  id="email-input"
                  type="email"
                  required
                  placeholder="name@domain.com"
                  className="text-input"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  style={{ width: '100%', paddingLeft: '44px', boxSizing: 'border-box' }}
                />
              </div>
            </div>

            <div className="input-group" style={{ marginBottom: '24px' }}>
              <label className="input-label" htmlFor="password-input">Password</label>
              <div style={{ position: 'relative' }}>
                <KeyRound size={18} color="var(--text-muted)" style={{
                  position: 'absolute',
                  left: '14px',
                  top: '50%',
                  transform: 'translateY(-50%)'
                }} />
                <input
                  id="password-input"
                  type={showPassword ? 'text' : 'password'}
                  required
                  placeholder="••••••••"
                  className="text-input"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  style={{ width: '100%', paddingLeft: '44px', paddingRight: '44px', boxSizing: 'border-box' }}
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
              {isLogin && (
                <div style={{ textAlign: 'right', marginTop: '8px' }}>
                  <button
                    type="button"
                    onClick={() => setShowForgotPassword(true)}
                    style={{ background: 'none', border: 'none', color: 'var(--cyan, #00f0ff)', fontSize: '13px', fontWeight: 600, cursor: 'pointer' }}
                  >
                    Reset Password
                  </button>
                </div>
              )}
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn-primary"
              style={{ width: '100%', display: 'flex', justifyContent: 'center', alignItems: 'center' }}
            >
              {loading ? 'Validating Account...' : isLogin ? 'Access Portal Console' : 'Register Administrator Account'}
            </button>

            <div style={{ textAlign: 'center', marginTop: '24px' }}>
              <button
                type="button"
                onClick={() => {
                  setIsLogin(!isLogin);
                  setError('');
                }}
                style={{
                  background: 'none',
                  border: 'none',
                  color: 'var(--cyan, #00f0ff)',
                  fontSize: '14px',
                  fontWeight: 600,
                  cursor: 'pointer'
                }}
              >
                {isLogin ? "First setup? Create administrator account" : 'Existing account? Sign in'}
              </button>
            </div>
          </form>
        )}

        {step === 2 && (
          /* MFA Verification Form */
          <form onSubmit={handleOtpSubmit}>
            <div style={{ textAlign: 'center', marginBottom: '24px' }}>
              <p style={{ fontSize: '14px', color: 'var(--text-secondary)', lineHeight: '1.5' }}>
                🛡️ Enter the 6-digit verification code from your authenticator app (Google Authenticator, Microsoft Authenticator):
              </p>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px', marginTop: '14px' }}>
                <div style={{ width: '40px', height: '4px', background: 'rgba(255,255,255,0.06)', borderRadius: '2px', overflow: 'hidden', position: 'relative' }}>
                  <div style={{
                    width: `${(timeRemaining / 30) * 100}%`,
                    height: '100%',
                    background: 'var(--cyan, #00f0ff)',
                    transition: 'width 1s linear',
                    boxShadow: '0 0 6px var(--cyan)'
                  }}></div>
                </div>
                <span style={{ fontSize: '11.5px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>Code expires in {timeRemaining}s</span>
              </div>
            </div>

            <div className="input-group" style={{ marginBottom: '24px' }}>
              <input
                type="text"
                maxLength={6}
                required
                placeholder="000000"
                className="text-input"
                value={otpCode}
                onChange={(e) => setOtpCode(e.target.value.replace(/\D/g, ''))}
                style={{ 
                  width: '100%', 
                  textAlign: 'center', 
                  fontSize: '24px', 
                  letterSpacing: '8px',
                  fontWeight: 700,
                  boxSizing: 'border-box'
                }}
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn-primary"
              style={{ width: '100%' }}
            >
              {loading ? 'Verifying OTP...' : 'Verify TOTP & Log In'}
            </button>

            <div style={{ textAlign: 'center', marginTop: '24px' }}>
              <button
                type="button"
                onClick={() => {
                  setStep(1);
                  setOtpCode('');
                  setError('');
                }}
                style={{
                  background: 'none',
                  border: 'none',
                  color: 'var(--text-secondary)',
                  fontSize: '14px',
                  fontWeight: 500,
                  cursor: 'pointer'
                }}
              >
                ← Back to Login Credentials
              </button>
            </div>
          </form>
        )}

        {step === 3 && (
          /* MFA Enrollment Flow */
          <div>
            {enrollStep === 1 ? (
              /* Substep 1: Display QR code and Manual secret */
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '20px' }}>
                <div style={{ textAlign: 'center' }}>
                  <p style={{ fontSize: '13.5px', color: 'var(--text-secondary)', lineHeight: '1.5', margin: 0 }}>
                    🔒 Scan the QR code below with **Google Authenticator** or **Microsoft Authenticator** to secure your account:
                  </p>
                </div>

                <div style={{
                  background: '#ffffff',
                  padding: '12px',
                  borderRadius: '12px',
                  display: 'inline-block',
                  boxShadow: '0 0 25px rgba(255, 255, 255, 0.05)',
                  margin: '8px 0'
                }}>
                  <img
                    src={mfaSetupData?.qr_code}
                    alt="Authenticator Setup QR"
                    style={{ display: 'block', width: '160px', height: '160px' }}
                  />
                </div>

                <div style={{ width: '100%', textAlign: 'center' }}>
                  <button
                    type="button"
                    onClick={() => setShowManualKey(!showManualKey)}
                    style={{
                      background: 'none',
                      border: 'none',
                      color: 'var(--cyan)',
                      fontSize: '12px',
                      fontWeight: 600,
                      cursor: 'pointer',
                      textDecoration: 'underline'
                    }}
                  >
                    {showManualKey ? "Hide manual key setup" : "Can't scan the QR?"}
                  </button>

                  {showManualKey && (
                    <div style={{ width: '100%', marginTop: '12px', textAlign: 'left' }}>
                      <label style={{ fontSize: '11px', color: 'var(--text-muted)', display: 'block', marginBottom: '6px', fontWeight: 600 }}>Manual Secret Key</label>
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
                        <span style={{ wordBreak: 'break-all' }}>{mfaSetupData?.totp_secret}</span>
                        <button
                          type="button"
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
                  )}
                </div>

                <button
                  onClick={() => setEnrollStep(2)}
                  className="btn-primary"
                  style={{ width: '100%', marginTop: '8px' }}
                >
                  Continue to Verification →
                </button>

                <div style={{ textAlign: 'center', marginTop: '4px' }}>
                  <button
                    type="button"
                    onClick={() => {
                      setStep(1);
                      setError('');
                    }}
                    style={{
                      background: 'none',
                      border: 'none',
                      color: 'var(--text-secondary)',
                      fontSize: '13px',
                      fontWeight: 500,
                      cursor: 'pointer'
                    }}
                  >
                    ← Back to Login Credentials
                  </button>
                </div>
              </div>
            ) : (
              /* Substep 2: Ask user to enter the verification code */
              <form onSubmit={handleOtpSubmit} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '20px' }}>
                <div style={{ textAlign: 'center' }}>
                  <p style={{ fontSize: '13.5px', color: 'var(--text-secondary)', lineHeight: '1.5', margin: 0 }}>
                    🛡️ Enter the 6-digit confirmation code displayed in your authenticator app:
                  </p>
                  
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px', marginTop: '14px' }}>
                    <div style={{ width: '50px', height: '4px', background: 'rgba(255,255,255,0.06)', borderRadius: '2px', overflow: 'hidden', position: 'relative' }}>
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
                </div>

                <div className="input-group" style={{ width: '100%', marginBottom: '8px' }}>
                  <label className="input-label" htmlFor="mfa-verify-code">Verification Code</label>
                  <input
                    id="mfa-verify-code"
                    type="text"
                    maxLength={6}
                    required
                    placeholder="000000"
                    className="text-input"
                    value={otpCode}
                    onChange={(e) => setOtpCode(e.target.value.replace(/\D/g, ''))}
                    style={{ 
                      width: '100%', 
                      textAlign: 'center', 
                      fontSize: '22px', 
                      letterSpacing: '6px',
                      fontWeight: 700,
                      boxSizing: 'border-box'
                    }}
                  />
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="btn-primary"
                  style={{ width: '100%' }}
                >
                  {loading ? 'Activating MFA...' : 'Verify & Complete Setup'}
                </button>

                <div style={{ display: 'flex', justifyContent: 'space-between', width: '100%', marginTop: '8px' }}>
                  <button
                    type="button"
                    onClick={() => setEnrollStep(1)}
                    style={{
                      background: 'none',
                      border: 'none',
                      color: 'var(--text-secondary)',
                      fontSize: '13px',
                      fontWeight: 500,
                      cursor: 'pointer'
                    }}
                  >
                    ← Back to QR Code
                  </button>
                  
                  <button
                    type="button"
                    onClick={() => {
                      setStep(1);
                      setError('');
                    }}
                    style={{
                      background: 'none',
                      border: 'none',
                      color: 'var(--text-secondary)',
                      fontSize: '13px',
                      fontWeight: 500,
                      cursor: 'pointer'
                    }}
                  >
                    Cancel Setup
                  </button>
                </div>
              </form>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
