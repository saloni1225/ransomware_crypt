import React, { useState } from 'react';
import { api } from '../services/api';
import { Shield, Mail, KeyRound, Info, CheckCircle } from 'lucide-react';

export default function ForgotPassword({ onBackToLogin }) {
  const [step, setStep] = useState(1); // 1 = request email, 2 = reset password
  const [email, setEmail] = useState('');
  const [token, setToken] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);

  const handleRequestReset = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setLoading(true);
    try {
      const res = await api.forgotPassword(email);
      setSuccess('Reset link sent! For this demo, use the token provided below.');
      if (res.mock_token) {
        setToken(res.mock_token);
      }
      setStep(2);
    } catch (err) {
      setError(err.message || 'Error requesting password reset');
    } finally {
      setLoading(false);
    }
  };

  const handleResetPassword = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setLoading(true);
    try {
      await api.resetPassword(email, token, newPassword);
      setSuccess('Password reset successfully! You can now log in.');
      setTimeout(onBackToLogin, 3000);
    } catch (err) {
      setError(err.message || 'Invalid or expired token');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', width: '100%', padding: '20px'
    }}>
      <div className="glass-card" style={{
        width: '100%', maxWidth: '440px', padding: '40px', boxShadow: '0 20px 50px rgba(0,0,0,0.5)', border: '1px solid rgba(255, 255, 255, 0.08)'
      }}>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', marginBottom: '28px' }}>
          <div style={{
            background: 'linear-gradient(135deg, var(--primary), var(--cyan))', padding: '12px', borderRadius: '12px', boxShadow: '0 0 20px var(--cyan-glow)', marginBottom: '16px'
          }}>
            <Shield size={32} color="#040810" />
          </div>
          <h2 style={{ fontSize: '24px', fontWeight: 800 }}>Password Reset</h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '14px', marginTop: '4px' }}>
            {step === 1 ? 'Enter your email to receive a reset link' : 'Enter your new password'}
          </p>
        </div>

        {error && (
          <div style={{ background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.2)', borderRadius: '8px', padding: '12px', color: '#ef4444', fontSize: '14px', marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Info size={16} /> <span>{error}</span>
          </div>
        )}
        
        {success && (
          <div style={{ background: 'rgba(67, 233, 123, 0.1)', border: '1px solid rgba(67, 233, 123, 0.2)', borderRadius: '8px', padding: '12px', color: '#43e97b', fontSize: '14px', marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <CheckCircle size={16} /> <span>{success}</span>
          </div>
        )}

        {step === 1 ? (
          <form onSubmit={handleRequestReset}>
            <div className="input-group">
              <label className="input-label">Email Address</label>
              <div style={{ position: 'relative' }}>
                <Mail size={18} color="var(--text-muted)" style={{ position: 'absolute', left: '14px', top: '50%', transform: 'translateY(-50%)' }} />
                <input type="email" required placeholder="name@domain.com" className="text-input" value={email} onChange={(e) => setEmail(e.target.value)} style={{ width: '100%', paddingLeft: '44px' }} />
              </div>
            </div>
            <button type="submit" disabled={loading} className="btn-primary" style={{ width: '100%', marginTop: '8px' }}>
              {loading ? 'Sending...' : 'Send Reset Link'}
            </button>
          </form>
        ) : (
          <form onSubmit={handleResetPassword}>
            <div className="input-group">
              <label className="input-label">Reset Token</label>
              <input type="text" required placeholder="Paste token here" className="text-input" value={token} onChange={(e) => setToken(e.target.value)} style={{ width: '100%' }} />
            </div>
            <div className="input-group">
              <label className="input-label">New Password</label>
              <div style={{ position: 'relative' }}>
                <KeyRound size={18} color="var(--text-muted)" style={{ position: 'absolute', left: '14px', top: '50%', transform: 'translateY(-50%)' }} />
                <input type="password" required placeholder="••••••••" className="text-input" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} style={{ width: '100%', paddingLeft: '44px' }} />
              </div>
            </div>
            <button type="submit" disabled={loading} className="btn-primary" style={{ width: '100%', marginTop: '8px' }}>
              {loading ? 'Resetting...' : 'Reset Password'}
            </button>
          </form>
        )}

        <div style={{ textAlign: 'center', marginTop: '24px' }}>
          <button type="button" onClick={onBackToLogin} style={{ background: 'none', border: 'none', color: 'var(--text-secondary)', fontSize: '14px', fontWeight: 500, cursor: 'pointer' }}>
            ← Back to Login
          </button>
        </div>
      </div>
    </div>
  );
}
