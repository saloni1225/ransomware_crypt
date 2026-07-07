const API_BASE_URL = import.meta.env.VITE_API_URL || '/api';

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

const parseJwtPayload = (token) => {
  try {
    return JSON.parse(atob(token.split('.')[1]));
  } catch {
    return null;
  }
};

const isTokenExpired = (token) => {
  const payload = parseJwtPayload(token);
  if (!payload?.exp) return true;
  return payload.exp * 1000 <= Date.now();
};

const clearAuthSession = () => {
  localStorage.removeItem('token');
  localStorage.removeItem('email');
  localStorage.removeItem('role');
};

const persistAuthSession = (data) => {
  if (data.access_token) {
    localStorage.setItem('token', data.access_token);
  }
  if (data.email) {
    localStorage.setItem('email', data.email);
  }
  if (data.role) {
    localStorage.setItem('role', data.role);
  }
};

const getHeaders = () => {
  const token = localStorage.getItem('token');
  const headers = {
    'Content-Type': 'application/json',
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
};

export const api = {
  // Authentication
  register: async (email, password) => {
    const response = await fetch(`${API_BASE_URL}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.detail || 'Registration failed');
    }
    return response.json();
  },

  login: async (email, password) => {
    const response = await fetch(`${API_BASE_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.detail || 'Login failed');
    }
    const data = await response.json();
    if (data.access_token) {
      persistAuthSession(data);
    }
    return data;
  },

  verifyOtp: async (email, otpCode) => {
    const response = await fetch(`${API_BASE_URL}/auth/verify-otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, otp_code: otpCode }),
    });
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.detail || 'Invalid OTP');
    }
    const data = await response.json();
    persistAuthSession(data);
    return data;
  },

  getMe: async () => {
    const response = await fetch(`${API_BASE_URL}/auth/me`, {
      method: 'GET',
      headers: getHeaders(),
    });
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new ApiError(errorData.detail || 'Failed to fetch user context', response.status);
    }
    return response.json();
  },

  logout: () => {
    clearAuthSession();
  },

  isAuthenticated: () => {
    const token = localStorage.getItem('token');
    if (!token) return false;
    if (isTokenExpired(token)) {
      clearAuthSession();
      return false;
    }
    return true;
  },

  forgotPassword: async (email) => {
    const response = await fetch(`${API_BASE_URL}/auth/forgot-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.detail || 'Failed to request password reset');
    }
    return response.json();
  },

  resetPassword: async (email, token, newPassword) => {
    const response = await fetch(`${API_BASE_URL}/auth/reset-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, token, new_password: newPassword }),
    });
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.detail || 'Failed to reset password');
    }
    return response.json();
  },

  mfaSetup: async () => {
    const response = await fetch(`${API_BASE_URL}/auth/mfa/setup`, {
      method: 'POST',
      headers: getHeaders(),
    });
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.detail || 'Failed to set up MFA');
    }
    return response.json();
  },

  mfaVerify: async (otpCode) => {
    const response = await fetch(`${API_BASE_URL}/auth/mfa/verify`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify({ otp_code: otpCode }),
    });
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.detail || 'MFA verification failed');
    }
    return response.json();
  },

  mfaDisable: async (password) => {
    const response = await fetch(`${API_BASE_URL}/auth/mfa/disable`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify({ password }),
    });
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.detail || 'Failed to disable MFA');
    }
    return response.json();
  },

  // Devices
  listDevices: async () => {
    const response = await fetch(`${API_BASE_URL}/devices/`, {
      method: 'GET',
      headers: getHeaders(),
    });
    if (!response.ok) throw new Error('Failed to load devices');
    return response.json();
  },

  getDeviceTrust: async (deviceId) => {
    const response = await fetch(`${API_BASE_URL}/devices/${deviceId}/trust-breakdown`, {
      method: 'GET',
      headers: getHeaders(),
    });
    if (!response.ok) throw new Error('Failed to load trust score breakdown');
    return response.json();
  },

  // Threats
  listThreatEvents: async () => {
    const response = await fetch(`${API_BASE_URL}/threats/events`, {
      method: 'GET',
      headers: getHeaders(),
    });
    if (!response.ok) throw new Error('Failed to load threat events');
    return response.json();
  },

  getThreatDetails: async (eventId) => {
    const response = await fetch(`${API_BASE_URL}/threats/events/${eventId}`, {
      method: 'GET',
      headers: getHeaders(),
    });
    if (!response.ok) throw new Error('Failed to load event details');
    return response.json();
  },

  updateThreatStatus: async (eventId, status) => {
    const response = await fetch(`${API_BASE_URL}/threats/events/${eventId}/status?status_update=${status}`, {
      method: 'PUT',
      headers: getHeaders(),
    });
    if (!response.ok) throw new Error('Failed to update event status');
    return response.json();
  },

  getThreatExplanation: async (eventId) => {
    const response = await fetch(`${API_BASE_URL}/threats/events/${eventId}/explanation`, {
      method: 'GET',
      headers: getHeaders(),
    });
    if (!response.ok) throw new Error('Failed to load threat explanation');
    return response.json();
  },

  getThreatStoryline: async (eventId) => {
    const response = await fetch(`${API_BASE_URL}/threats/events/${eventId}/storyline`, {
      method: 'GET',
      headers: getHeaders(),
    });
    if (!response.ok) throw new Error('Failed to load attack storyline');
    return response.json();
  },

  // Reports
  getDashboardSummary: async () => {
    const response = await fetch(`${API_BASE_URL}/reports/summary`, {
      method: 'GET',
      headers: getHeaders(),
    });
    if (!response.ok) throw new Error('Failed to load dashboard statistics');
    return response.json();
  },

  getExportReportUrl: () => {
    const token = localStorage.getItem('token');
    return `${API_BASE_URL}/reports/export-html?token=${token}`; // For opening in new window
  },

  getExportReportPdfUrl: () => {
    const token = localStorage.getItem('token');
    return `${API_BASE_URL}/reports/export-pdf?token=${token}`; // For downloading PDF
  },

  getExportReportCsvUrl: () => {
    const token = localStorage.getItem('token');
    return `${API_BASE_URL}/reports/export-csv?token=${token}`; // For downloading CSV
  },

  // ── Phase 2: Malware ─────────────────────────────────────────────────────
  triggerScan: async (deviceId) => {
    const response = await fetch(`${API_BASE_URL}/malware/scan?device_id=${deviceId}`, {
      method: 'POST', headers: getHeaders(),
    });
    if (!response.ok) throw new Error('Scan failed');
    return response.json();
  },

  listScans: async (limit = 100) => {
    const response = await fetch(`${API_BASE_URL}/malware/scans?limit=${limit}`, { headers: getHeaders() });
    if (!response.ok) throw new Error('Failed to load scans');
    return response.json();
  },

  quarantineFile: async (scanId) => {
    const response = await fetch(`${API_BASE_URL}/malware/scans/${scanId}/quarantine`, {
      method: 'PUT', headers: getHeaders(),
    });
    if (!response.ok) throw new Error('Failed to quarantine');
    return response.json();
  },

  getMalwareStats: async () => {
    const response = await fetch(`${API_BASE_URL}/malware/stats`, { headers: getHeaders() });
    if (!response.ok) throw new Error('Failed to load malware stats');
    return response.json();
  },

  // ── Phase 2: Network ─────────────────────────────────────────────────────
  listConnections: async (limit = 100) => {
    const response = await fetch(`${API_BASE_URL}/network/connections?limit=${limit}`, { headers: getHeaders() });
    if (!response.ok) throw new Error('Failed to load connections');
    return response.json();
  },

  simulateConnections: async () => {
    const response = await fetch(`${API_BASE_URL}/network/simulate`, {
      method: 'POST', headers: getHeaders(),
    });
    if (!response.ok) throw new Error('Simulation failed');
    return response.json();
  },

  getNetworkStats: async () => {
    const response = await fetch(`${API_BASE_URL}/network/stats`, { headers: getHeaders() });
    if (!response.ok) throw new Error('Failed to load network stats');
    return response.json();
  },

  // ── Phase 2: Wi-Fi ──────────────────────────────────────────────────────
  listWifiNetworks: async () => {
    const response = await fetch(`${API_BASE_URL}/wifi/networks`, { headers: getHeaders() });
    if (!response.ok) throw new Error('Failed to load WiFi networks');
    return response.json();
  },

  triggerWifiScan: async (deviceId) => {
    const response = await fetch(`${API_BASE_URL}/wifi/scan?device_id=${deviceId}`, {
      method: 'POST', headers: getHeaders(),
    });
    if (!response.ok) throw new Error('Wi-Fi scan failed');
    return response.json();
  },

  getWifiStats: async () => {
    const response = await fetch(`${API_BASE_URL}/wifi/stats`, { headers: getHeaders() });
    if (!response.ok) throw new Error('Failed to load WiFi stats');
    return response.json();
  },

  // ── Phase 2: Firewall ───────────────────────────────────────────────────
  listFirewallRules: async () => {
    const response = await fetch(`${API_BASE_URL}/firewall/rules`, { headers: getHeaders() });
    if (!response.ok) throw new Error('Failed to load firewall rules');
    return response.json();
  },

  createFirewallRule: async (rule) => {
    const response = await fetch(`${API_BASE_URL}/firewall/rules`, {
      method: 'POST', headers: getHeaders(), body: JSON.stringify(rule),
    });
    if (!response.ok) throw new Error('Failed to create rule');
    return response.json();
  },

  toggleFirewallRule: async (ruleId) => {
    const response = await fetch(`${API_BASE_URL}/firewall/rules/${ruleId}/toggle`, {
      method: 'PUT', headers: getHeaders(),
    });
    if (!response.ok) throw new Error('Failed to toggle rule');
    return response.json();
  },

  deleteFirewallRule: async (ruleId) => {
    const response = await fetch(`${API_BASE_URL}/firewall/rules/${ruleId}`, {
      method: 'DELETE', headers: getHeaders(),
    });
    if (!response.ok) throw new Error('Failed to delete rule');
    return response.json();
  },

  getFirewallStats: async () => {
    const response = await fetch(`${API_BASE_URL}/firewall/stats`, { headers: getHeaders() });
    if (!response.ok) throw new Error('Failed to load firewall stats');
    return response.json();
  },

  // ── Phase 3: Deception ──────────────────────────────────────────────────
  listDeceptionAssets: async () => {
    const response = await fetch(`${API_BASE_URL}/deception/assets`, { headers: getHeaders() });
    if (!response.ok) throw new Error('Failed to load deception assets');
    return response.json();
  },

  createDeceptionAsset: async (asset) => {
    const response = await fetch(`${API_BASE_URL}/deception/assets`, {
      method: 'POST', headers: getHeaders(), body: JSON.stringify(asset),
    });
    if (!response.ok) throw new Error('Failed to create asset');
    return response.json();
  },

  triggerDeceptionAsset: async (assetId, deviceId, triggeredBy) => {
    const response = await fetch(`${API_BASE_URL}/deception/trigger`, {
      method: 'POST', headers: getHeaders(),
      body: JSON.stringify({ asset_id: assetId, device_id: deviceId, triggered_by: triggeredBy }),
    });
    if (!response.ok) throw new Error('Failed to trigger asset');
    return response.json();
  },

  toggleDeceptionAsset: async (assetId) => {
    const response = await fetch(`${API_BASE_URL}/deception/assets/${assetId}/toggle`, {
      method: 'PUT', headers: getHeaders(),
    });
    if (!response.ok) throw new Error('Failed to toggle asset');
    return response.json();
  },

  deleteDeceptionAsset: async (assetId) => {
    const response = await fetch(`${API_BASE_URL}/deception/assets/${assetId}`, {
      method: 'DELETE', headers: getHeaders(),
    });
    if (!response.ok) throw new Error('Failed to delete deception asset');
    return response.json();
  },

  getDeceptionStats: async () => {
    const response = await fetch(`${API_BASE_URL}/deception/stats`, { headers: getHeaders() });
    if (!response.ok) throw new Error('Failed to load deception stats');
    return response.json();
  },

  // ── Phase 3: Privacy ────────────────────────────────────────────────────
  listPrivacyEvents: async () => {
    const response = await fetch(`${API_BASE_URL}/privacy/events`, { headers: getHeaders() });
    if (!response.ok) throw new Error('Failed to load privacy events');
    return response.json();
  },

  getPrivacyScore: async () => {
    const response = await fetch(`${API_BASE_URL}/privacy/score`, { headers: getHeaders() });
    if (!response.ok) throw new Error('Failed to load privacy score');
    return response.json();
  },

  getPrivacyStats: async () => {
    const response = await fetch(`${API_BASE_URL}/privacy/stats`, { headers: getHeaders() });
    if (!response.ok) throw new Error('Failed to load privacy stats');
    return response.json();
  },

  // ── Phase 3: Trust Score ────────────────────────────────────────────────
  getDeviceTrustScore: async (deviceId) => {
    const response = await fetch(`${API_BASE_URL}/devices/${deviceId}/trust-score`, { headers: getHeaders() });
    if (!response.ok) throw new Error('Failed to load trust score');
    return response.json();
  },

  // ── Recovery & Rollback ─────────────────────────────────────────────────
  listQuarantinedFiles: async () => {
    const response = await fetch(`${API_BASE_URL}/recovery/quarantine`, { headers: getHeaders() });
    if (!response.ok) throw new Error('Failed to load quarantined files');
    return response.json();
  },

  restoreFile: async (scanId, notes = '') => {
    const response = await fetch(`${API_BASE_URL}/recovery/restore/${scanId}`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify({ notes }),
    });
    if (!response.ok) throw new Error('Failed to restore file');
    return response.json();
  },

  deleteFile: async (scanId, notes = '') => {
    const response = await fetch(`${API_BASE_URL}/recovery/delete/${scanId}`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify({ notes }),
    });
    if (!response.ok) throw new Error('Failed to permanently delete file');
    return response.json();
  },

  rollbackThreatEvent: async (eventId, notes = '') => {
    const response = await fetch(`${API_BASE_URL}/recovery/rollback/${eventId}`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify({ notes }),
    });
    if (!response.ok) throw new Error('Failed to rollback threat event');
    return response.json();
  },

  getRecoveryHistory: async (skip = 0, limit = 50) => {
    const response = await fetch(`${API_BASE_URL}/recovery/history?skip=${skip}&limit=${limit}`, {
      headers: getHeaders(),
    });
    if (!response.ok) throw new Error('Failed to load recovery history');
    return response.json();
  },

  getRecoveryStats: async () => {
    const response = await fetch(`${API_BASE_URL}/recovery/stats`, { headers: getHeaders() });
    if (!response.ok) throw new Error('Failed to load recovery stats');
    return response.json();
  },

  // ── Phase 3: Browser Protection ─────────────────────────────────────────
  checkUrlSafety: async (url) => {
    const response = await fetch(`${API_BASE_URL}/browser/check-url`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify({ url }),
    });
    if (!response.ok) throw new Error('Failed to check URL safety');
    return response.json();
  },

  listBrowserEvents: async (limit = 100) => {
    const response = await fetch(`${API_BASE_URL}/browser/events?limit=${limit}`, { headers: getHeaders() });
    if (!response.ok) throw new Error('Failed to load browser events');
    return response.json();
  },

  getBrowserStats: async () => {
    const response = await fetch(`${API_BASE_URL}/browser/stats`, { headers: getHeaders() });
    if (!response.ok) throw new Error('Failed to load browser stats');
    return response.json();
  },
};



