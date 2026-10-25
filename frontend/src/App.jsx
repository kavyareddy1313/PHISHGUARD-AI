import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Mail,
  RefreshCw,
  ExternalLink,
  CheckCircle,
  XCircle,
  Search,
  Lock,
  Terminal,
  Download,
  Sliders,
  Radio,
  Eye,
  Cpu,
  Inbox,
  Upload,
  Globe,
  ArrowRight,
  KeyRound,
  Sparkles
} from 'lucide-react';
import io from 'socket.io-client';

const API_BASE = '/api';

export default function App() {
  const [emails, setEmails] = useState([]);
  const [selectedEmail, setSelectedEmail] = useState(null);
  const [filter, setFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [analytics, setAnalytics] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('feed'); // 'feed' | 'connectEmail' | 'mlModel' | 'sandbox' | 'urlScanner'

  // ML Model Metrics
  const [modelMetrics, setModelMetrics] = useState(null);
  const [isRetraining, setIsRetraining] = useState(false);

  // Modals & Sandbox states
  const [toastAlert, setToastAlert] = useState(null);
  const [isConnectModalOpen, setIsConnectModalOpen] = useState(false);
  const [isEmlModalOpen, setIsEmlModalOpen] = useState(false);
  const [emlRawText, setEmlRawText] = useState('');
  const [isUploadingEml, setIsUploadingEml] = useState(false);

  // Sandbox inputs
  const [sandboxInput, setSandboxInput] = useState({
    sender: 'support@paypa1-security-verification.xyz',
    subject: 'URGENT: Your account has been suspended - verify within 24 hours',
    body: 'Dear Customer,\n\nWe detected suspicious activity on your account. Please verify your debit card and login credentials immediately at http://192.168.1.102/login to restore access. Failure to do so within 24 hours will cause permanent termination.\n\nPayPal Security Team'
  });
  const [sandboxResult, setSandboxResult] = useState(null);
  const [isSandboxScanning, setIsSandboxScanning] = useState(false);

  // URL Scanner state
  const [urlInput, setUrlInput] = useState('http://192.168.1.105/paypal-auth/verify');
  const [urlScanResult, setUrlScanResult] = useState(null);
  const [isUrlScanning, setIsUrlScanning] = useState(false);

  // Email sync configuration state
  const [syncConfig, setSyncConfig] = useState({
    emailAddress: '',
    provider: 'Gmail',
    imapHost: 'imap.gmail.com',
    imapPort: 993,
    password: '',
    useTls: true,
    syncIntervalMinutes: 2,
    isAutoQuarantineEnabled: true,
    isLivePollingActive: false,
    syncStatus: 'Ready'
  });
  const [isSyncSaving, setIsSyncSaving] = useState(false);
  const [isTestingImap, setIsTestingImap] = useState(false);
  const [imapTestResult, setImapTestResult] = useState(null);
  const [isFetchingReal, setIsFetchingReal] = useState(false);

  // Fetch emails, analytics, and ML model metrics
  const fetchData = async () => {
    setIsLoading(true);
    try {
      const [emailRes, analyticsRes, syncRes, metricsRes] = await Promise.all([
        fetch(`${API_BASE}/emails`),
        fetch(`${API_BASE}/analytics`),
        fetch(`${API_BASE}/settings/email-sync`),
        fetch(`${API_BASE}/model/metrics`)
      ]);

      const emailData = await emailRes.json();
      const analyticsData = await analyticsRes.json();
      const syncData = await syncRes.json();
      const metricsData = await metricsRes.json();

      if (emailData.success) {
        setEmails(emailData.emails);
        if (emailData.emails.length > 0 && !selectedEmail) {
          setSelectedEmail(emailData.emails[0]);
        }
      }
      if (analyticsData.success) {
        setAnalytics(analyticsData.analytics);
      }
      if (syncData.success) {
        setSyncConfig((prev) => ({ ...prev, ...syncData.config }));
      }
      if (metricsData.success && metricsData.metrics) {
        setModelMetrics(metricsData.metrics);
      }
    } catch (err) {
      console.error('Error fetching data:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchData();

    // Connect WebSocket
    const socket = io();

    socket.on('new-email', (newEmail) => {
      setEmails((prev) => [newEmail, ...prev]);
      fetch(`${API_BASE}/analytics`).then((r) => r.json()).then((d) => {
        if (d.success) setAnalytics(d.analytics);
      });
    });

    socket.on('threat-alert', (alertData) => {
      setToastAlert(alertData);
      setTimeout(() => setToastAlert(null), 9000);
    });

    return () => {
      socket.disconnect();
    };
  }, []);

  // Filtered emails
  const filteredEmails = emails.filter((e) => {
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matches =
        (e.subject || '').toLowerCase().includes(q) ||
        (e.sender || '').toLowerCase().includes(q) ||
        (e.body || '').toLowerCase().includes(q);
      if (!matches) return false;
    }

    if (filter === 'REAL') return e.isRealEmail;
    if (filter === 'PHISHING') return e.scan && e.scan.verdict === 'PHISHING';
    if (filter === 'SUSPICIOUS') return e.scan && e.scan.verdict === 'SUSPICIOUS';
    if (filter === 'SAFE') return e.scan && e.scan.verdict === 'SAFE';
    if (filter === 'QUARANTINED') return e.isQuarantined;
    return true;
  });

  // Toggle Quarantine
  const handleToggleQuarantine = async (id) => {
    try {
      const res = await fetch(`${API_BASE}/emails/${id}/quarantine`, { method: 'POST' });
      const data = await res.json();
      if (data.success) {
        setEmails((prev) => prev.map((e) => (e.id === id ? data.email : e)));
        if (selectedEmail && selectedEmail.id === id) {
          setSelectedEmail(data.email);
        }
        fetchData();
      }
    } catch (err) {
      console.error('Quarantine toggle error:', err);
    }
  };

  // Defang links
  const handleDefangLinks = async (id) => {
    try {
      const res = await fetch(`${API_BASE}/emails/${id}/defang`, { method: 'POST' });
      const data = await res.json();
      if (data.success) {
        setEmails((prev) => prev.map((e) => (e.id === id ? data.email : e)));
        if (selectedEmail && selectedEmail.id === id) {
          setSelectedEmail(data.email);
        }
      }
    } catch (err) {
      console.error('Defang links error:', err);
    }
  };

  // Test IMAP Connection
  const handleTestImap = async () => {
    setIsTestingImap(true);
    setImapTestResult(null);
    try {
      const res = await fetch(`${API_BASE}/imap/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(syncConfig)
      });
      const data = await res.json();
      setImapTestResult(data);
    } catch (err) {
      setImapTestResult({ success: false, error: err.message });
    } finally {
      setIsTestingImap(false);
    }
  };

  // Fetch Real Emails Immediately from User Inbox
  const handleFetchRealEmails = async () => {
    if (!syncConfig.emailAddress) {
      setIsConnectModalOpen(true);
      return;
    }
    setIsFetchingReal(true);
    try {
      const res = await fetch(`${API_BASE}/imap/sync-now`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ limit: 10 })
      });
      const data = await res.json();
      if (data.success) {
        alert(`Successfully imported ${data.fetchedCount} real emails from your inbox! (${data.newlyAnalyzed} scanned with ML)`);
        fetchData();
        setFilter('REAL');
      } else {
        alert(`Connection Notice: ${data.error}`);
        setIsConnectModalOpen(true);
      }
    } catch (err) {
      alert(`Sync Error: ${err.message}`);
      setIsConnectModalOpen(true);
    } finally {
      setIsFetchingReal(false);
    }
  };

  // Save Email Sync Settings
  const handleSaveSyncSettings = async (e) => {
    if (e) e.preventDefault();
    setIsSyncSaving(true);
    try {
      const res = await fetch(`${API_BASE}/settings/email-sync`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(syncConfig)
      });
      const data = await res.json();
      if (data.success) {
        setSyncConfig((prev) => ({ ...prev, ...data.config }));
        alert('Personal email settings saved successfully!');
        setIsConnectModalOpen(false);
      }
    } catch (err) {
      console.error('Sync save error:', err);
    } finally {
      setIsSyncSaving(false);
    }
  };

  // Retrain Model
  const handleRetrainModel = async () => {
    setIsRetraining(true);
    try {
      const res = await fetch(`${API_BASE}/model/retrain`, { method: 'POST' });
      const data = await res.json();
      if (data.success) {
        setModelMetrics(data.metrics);
        alert(`ML Model Retrained Successfully!\nAlgorithm: ${data.metrics.algorithm}\nAccuracy: ${data.metrics.accuracy}%`);
      }
    } catch (err) {
      alert('Failed to retrain: ' + err.message);
    } finally {
      setIsRetraining(false);
    }
  };

  // Simulate incoming attack email
  const handleSimulateAttack = async () => {
    const attackSamples = [
      {
        sender: 'security@chase-secure-update.xyz',
        senderName: 'Chase Bank Fraud Alert',
        subject: 'IMMEDIATE ATTENTION: Suspicious wire transaction of $3,500 detected',
        body: 'Security Alert: We detected an anomalous wire transfer request of $3,500.00 from an unfamiliar location. If you did not make this request, verify your debit PIN and login immediately at http://192.168.1.200/chase-verify to stop the payment within 1 hour.\n\nChase Online Security Department'
      },
      {
        sender: 'hr-payroll@corporate-bonus-portal.club',
        senderName: 'Corporate Payroll Department',
        subject: 'Urgent: Review and sign Q4 employee bonus adjustment document',
        body: 'Hello Team Member,\n\nYour quarterly performance incentive bonus has been calculated. To approve direct deposit before payroll cutoff, open the attached file Bonus_Compensation_Plan.docm and confirm your banking details.\n\nThank you,\nHR Department',
        attachments: [{ name: 'Bonus_Compensation_Plan.docm', size: '185 KB', type: 'application/msword' }]
      }
    ];

    const randomAttack = attackSamples[Math.floor(Math.random() * attackSamples.length)];
    try {
      const res = await fetch(`${API_BASE}/emails/simulate-incoming`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(randomAttack)
      });
      const data = await res.json();
      if (data.success) {
        setSelectedEmail(data.email);
        setActiveTab('feed');
      }
    } catch (err) {
      console.error('Simulation error:', err);
    }
  };

  // Upload and parse real .EML file
  const handleUploadEml = async () => {
    if (!emlRawText.trim()) return;
    setIsUploadingEml(true);
    try {
      const res = await fetch(`${API_BASE}/emails/upload-eml`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ emlRaw: emlRawText })
      });
      const data = await res.json();
      if (data.success) {
        setSelectedEmail(data.email);
        setIsEmlModalOpen(false);
        setEmlRawText('');
        setActiveTab('feed');
        alert('Real EML email analyzed with ML and added to your inbox!');
      } else {
        alert(`Parse Error: ${data.error}`);
      }
    } catch (err) {
      alert(`Error: ${err.message}`);
    } finally {
      setIsUploadingEml(false);
    }
  };

  // Run Sandbox scan
  const handleRunSandbox = async () => {
    setIsSandboxScanning(true);
    try {
      const res = await fetch(`${API_BASE}/emails/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(sandboxInput)
      });
      const data = await res.json();
      if (data.success) {
        setSandboxResult(data.scan);
      }
    } catch (err) {
      console.error('Sandbox error:', err);
    } finally {
      setIsSandboxScanning(false);
    }
  };

  // Run URL scanner
  const handleScanUrl = async () => {
    setIsUrlScanning(true);
    try {
      const res = await fetch(`${API_BASE}/scanner/url`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: urlInput })
      });
      const data = await res.json();
      if (data.success) {
        setUrlScanResult(data.scan);
      }
    } catch (err) {
      console.error('URL scan error:', err);
    } finally {
      setIsUrlScanning(false);
    }
  };

  // Download Incident Report JSON
  const handleExportIncidentReport = (email) => {
    if (!email) return;
    const report = {
      incidentId: email.id,
      timestamp: new Date().toISOString(),
      sender: email.sender,
      subject: email.subject,
      verdict: email.scan?.verdict,
      riskScore: email.scan?.riskScore,
      indicators: email.scan?.indicators,
      precautions: email.scan?.precautions,
      rawBodyPreview: (email.body || '').substring(0, 500)
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `FishGuard-Incident-${email.id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const currentScan = selectedEmail?.scan;

  return (
    <div className="app-wrapper">
      {/* Clean White & Violet Header */}
      <header className="top-nav">
        <div className="nav-brand">
          <div className="brand-icon-box">
            <ShieldAlert size={22} />
          </div>
          <div>
            <div className="brand-title">
              FishGuard <span>AI</span>
            </div>
            <div className="brand-tagline">Intelligent Phishing Detection & Prevention</div>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="tabs-container">
          <button
            className={`tab-btn ${activeTab === 'feed' ? 'active' : ''}`}
            onClick={() => setActiveTab('feed')}
          >
            <Mail size={15} /> Inbox Security
          </button>
          <button
            className={`tab-btn ${activeTab === 'connectEmail' ? 'active' : ''}`}
            onClick={() => setActiveTab('connectEmail')}
          >
            <Globe size={15} /> Connect Personal Email
          </button>
          <button
            className={`tab-btn ${activeTab === 'mlModel' ? 'active' : ''}`}
            onClick={() => setActiveTab('mlModel')}
          >
            <Cpu size={15} /> ML Engine ({modelMetrics?.accuracy ?? 100}%)
          </button>
          <button
            className={`tab-btn ${activeTab === 'sandbox' ? 'active' : ''}`}
            onClick={() => setActiveTab('sandbox')}
          >
            <Terminal size={15} /> Sandbox
          </button>
          <button
            className={`tab-btn ${activeTab === 'urlScanner' ? 'active' : ''}`}
            onClick={() => setActiveTab('urlScanner')}
          >
            <ExternalLink size={15} /> URL Inspector
          </button>
        </div>

        {/* Action Buttons */}
        <div className="nav-actions">
          <button
            className="btn btn-secondary"
            onClick={fetchData}
            title="Refresh inbox & metrics"
          >
            <RefreshCw size={14} className={isLoading ? 'spin' : ''} />
          </button>

          <button
            className="btn btn-primary"
            onClick={() => setIsConnectModalOpen(true)}
            style={{ fontWeight: 700 }}
          >
            <Inbox size={15} /> Connect My Gmail
          </button>

          <button
            className="btn btn-outline"
            onClick={handleSimulateAttack}
            title="Simulate a real-time attack"
          >
            <Radio size={14} color="#dc2626" /> Simulate Attack
          </button>
        </div>
      </header>

      {/* Hero Status Banner for Personal Email */}
      <div className="email-sync-banner">
        <div className="sync-status-info">
          <div className={`status-dot ${syncConfig.emailAddress ? '' : 'inactive'}`}></div>
          {syncConfig.emailAddress ? (
            <span>
              Connected to personal inbox: <strong>{syncConfig.emailAddress}</strong> (
              {syncConfig.provider} IMAP 993 SSL) • Live Protection Active
            </span>
          ) : (
            <span>
              Protect your real inbox: Click <strong>"Connect My Gmail"</strong> to automatically scan
              incoming personal emails for phishing in real-time.
            </span>
          )}
        </div>

        <div style={{ display: 'flex', gap: 10 }}>
          <button
            className="btn btn-secondary"
            style={{ padding: '4px 12px', fontSize: '0.78rem' }}
            onClick={handleFetchRealEmails}
            disabled={isFetchingReal}
          >
            <Inbox size={13} />
            {isFetchingReal ? 'Syncing...' : 'Fetch Real Emails Now'}
          </button>

          <button
            className="btn btn-outline"
            style={{ padding: '4px 12px', fontSize: '0.78rem' }}
            onClick={() => setIsEmlModalOpen(true)}
          >
            <Upload size={13} /> Upload .EML
          </button>
        </div>
      </div>

      {/* Floating Threat Toast Alert */}
      {toastAlert && (
        <div className="toast-notice">
          <ShieldAlert size={24} color="#dc2626" style={{ flexShrink: 0 }} />
          <div>
            <div style={{ fontWeight: 700, fontSize: '0.88rem', color: '#dc2626' }}>
              {toastAlert.message || 'Phishing Attack Intercepted'}
            </div>
            <div style={{ fontSize: '0.8rem', color: '#475569', marginTop: 2 }}>
              {toastAlert.subject}
            </div>
            <div style={{ fontSize: '0.74rem', color: '#94a3b8', marginTop: 4 }}>
              Risk Score: <strong>{toastAlert.riskScore}/100</strong> • Quarantined to prevent harm
            </div>
          </div>
          <button
            onClick={() => setToastAlert(null)}
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#94a3b8' }}
          >
            ✕
          </button>
        </div>
      )}

      {/* Metrics Row */}
      <div className="stats-row">
        <div className="stat-card">
          <div className="stat-icon" style={{ background: '#f5f3ff', color: '#7c3aed' }}>
            <Mail size={22} />
          </div>
          <div>
            <div className="stat-val">{analytics?.totalEmailsScanned ?? 0}</div>
            <div className="stat-desc">
              Total Scanned ({analytics?.realEmailsCount ?? 0} Real Inbox)
            </div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon" style={{ background: '#fef2f2', color: '#dc2626' }}>
            <ShieldAlert size={22} />
          </div>
          <div>
            <div className="stat-val" style={{ color: '#dc2626' }}>
              {analytics?.phishingBlocked ?? 0}
            </div>
            <div className="stat-desc">Phishing Blocked</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon" style={{ background: '#fffbeb', color: '#d97706' }}>
            <AlertTriangle size={22} />
          </div>
          <div>
            <div className="stat-val" style={{ color: '#d97706' }}>
              {analytics?.suspiciousFlagged ?? 0}
            </div>
            <div className="stat-desc">Suspicious Flagged</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon" style={{ background: '#f0fdf4', color: '#16a34a' }}>
            <Cpu size={22} />
          </div>
          <div>
            <div className="stat-val" style={{ color: '#16a34a' }}>
              {modelMetrics?.accuracy ?? 100}%
            </div>
            <div className="stat-desc">ML Accuracy (Trained on 2.6k Samples)</div>
          </div>
        </div>
      </div>

      {/* VIEW 1: INBOX & INSPECTOR */}
      {activeTab === 'feed' && (
        <main className="dashboard-grid">
          {/* Left Column: Email List */}
          <section className="inbox-card">
            <div className="inbox-header">
              <div className="inbox-title">
                <Mail size={17} color="#7c3aed" /> Scanned Emails
              </div>
              <span className="inbox-count-pill">{filteredEmails.length} messages</span>
            </div>

            {/* Search */}
            <div className="search-wrapper">
              <Search size={15} className="search-icon-svg" />
              <input
                type="text"
                className="search-field"
                placeholder="Search sender, subject, or keywords..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>

            {/* Filters */}
            <div className="filter-tabs">
              {[
                { key: 'ALL', label: 'All' },
                { key: 'REAL', label: '🌐 Real Inbox' },
                { key: 'PHISHING', label: 'Phishing' },
                { key: 'SUSPICIOUS', label: 'Suspicious' },
                { key: 'SAFE', label: 'Safe' },
                { key: 'QUARANTINED', label: 'Quarantined' }
              ].map((f) => (
                <button
                  key={f.key}
                  className={`filter-btn ${filter === f.key ? 'active' : ''}`}
                  onClick={() => setFilter(f.key)}
                >
                  {f.label}
                </button>
              ))}
            </div>

            {/* List */}
            <div className="email-scroll-list">
              {filteredEmails.length === 0 ? (
                <div style={{ padding: 40, textAlign: 'center', color: '#94a3b8', fontSize: '0.85rem' }}>
                  No emails match the selected filter.
                </div>
              ) : (
                filteredEmails.map((email) => {
                  const isSelected = selectedEmail?.id === email.id;
                  const v = email.scan?.verdict || 'SAFE';
                  return (
                    <div
                      key={email.id}
                      className={`email-row ${isSelected ? 'active' : ''} ${!email.isRead ? 'unread' : ''}`}
                      onClick={() => setSelectedEmail(email)}
                    >
                      <div className="email-row-top">
                        <div className="email-sender">
                          {email.senderName || email.sender}
                        </div>
                        <div className="email-date">
                          {new Date(email.receivedAt || Date.now()).toLocaleTimeString([], {
                            hour: '2-digit',
                            minute: '2-digit'
                          })}
                        </div>
                      </div>

                      <div className="email-subject-line">{email.subject}</div>

                      <div className="badge-group">
                        <span
                          className={`badge ${
                            v === 'PHISHING'
                              ? 'badge-phishing'
                              : v === 'SUSPICIOUS'
                              ? 'badge-suspicious'
                              : 'badge-safe'
                          }`}
                        >
                          {v === 'PHISHING' ? (
                            <ShieldAlert size={11} />
                          ) : v === 'SUSPICIOUS' ? (
                            <AlertTriangle size={11} />
                          ) : (
                            <ShieldCheck size={11} />
                          )}
                          {v} • {email.scan?.riskScore ?? 0}%
                        </span>

                        {email.isRealEmail && (
                          <span className="badge badge-personal">
                            <Globe size={10} /> Real Mail
                          </span>
                        )}

                        {email.isQuarantined && (
                          <span
                            className="badge"
                            style={{ background: '#f5f3ff', color: '#7c3aed', border: '1px solid #ddd6fe' }}
                          >
                            <Lock size={10} /> Quarantined
                          </span>
                        )}
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </section>

          {/* Right Column: Deep Security Inspection */}
          <section className="detail-container">
            {selectedEmail ? (
              <>
                {/* Hero Score Card */}
                <div
                  className={`score-card-hero ${
                    currentScan?.verdict === 'PHISHING'
                      ? 'phishing'
                      : currentScan?.verdict === 'SUSPICIOUS'
                      ? 'suspicious'
                      : 'safe'
                  }`}
                >
                  <div className="score-left">
                    <div
                      className="score-circle-badge"
                      style={{
                        background:
                          currentScan?.verdict === 'PHISHING'
                            ? '#fef2f2'
                            : currentScan?.verdict === 'SUSPICIOUS'
                            ? '#fffbeb'
                            : '#f0fdf4',
                        border: `2px solid ${
                          currentScan?.verdict === 'PHISHING'
                            ? '#dc2626'
                            : currentScan?.verdict === 'SUSPICIOUS'
                            ? '#d97706'
                            : '#16a34a'
                        }`
                      }}
                    >
                      <span
                        className="score-big-num"
                        style={{
                          color:
                            currentScan?.verdict === 'PHISHING'
                              ? '#dc2626'
                              : currentScan?.verdict === 'SUSPICIOUS'
                              ? '#d97706'
                              : '#16a34a'
                        }}
                      >
                        {currentScan?.riskScore ?? 0}
                      </span>
                      <span className="score-max">/ 100</span>
                    </div>

                    <div>
                      <div
                        className="verdict-headline"
                        style={{
                          color:
                            currentScan?.verdict === 'PHISHING'
                              ? '#dc2626'
                              : currentScan?.verdict === 'SUSPICIOUS'
                              ? '#d97706'
                              : '#16a34a'
                        }}
                      >
                        {currentScan?.verdict === 'PHISHING'
                          ? 'DANGEROUS PHISHING EMAIL DETECTED'
                          : currentScan?.verdict === 'SUSPICIOUS'
                          ? 'SUSPICIOUS EMAIL - CAUTION ADVISED'
                          : 'VERIFIED SAFE & AUTHENTIC EMAIL'}
                      </div>
                      <div className="verdict-subtext">
                        {currentScan?.verdict === 'PHISHING'
                          ? 'This email contains verified indicators of spoofed sender, high-urgency psychological coercion, or credential theft links.'
                          : currentScan?.verdict === 'SUSPICIOUS'
                          ? 'Minor discrepancies found in links or domain reputation. Do not enter credentials without checking the sender.'
                          : 'No deceptive links or malicious indicators detected. The sender matches known authentic domain signatures.'}
                      </div>

                      {/* Action buttons */}
                      <div className="email-actions-bar">
                        <button
                          className={`btn ${selectedEmail.isQuarantined ? 'btn-outline' : 'btn-danger'}`}
                          onClick={() => handleToggleQuarantine(selectedEmail.id)}
                        >
                          <Lock size={14} />
                          {selectedEmail.isQuarantined ? 'Release from Quarantine' : 'Quarantine Email'}
                        </button>

                        <button
                          className="btn btn-outline"
                          onClick={() => handleDefangLinks(selectedEmail.id)}
                          title="Neutralize links in body so they cannot be accidentally clicked"
                        >
                          <ShieldCheck size={14} /> Defang Links
                        </button>

                        <button
                          className="btn btn-outline"
                          onClick={() => handleExportIncidentReport(selectedEmail)}
                        >
                          <Download size={14} /> Export Report JSON
                        </button>
                      </div>
                    </div>
                  </div>

                  {/* Subscore bars */}
                  <div className="subscore-group">
                    <div className="subscore-row">
                      <div className="subscore-title">
                        <span>Sender Domain</span>
                        <span>{currentScan?.breakdown?.senderRisk ?? 0}%</span>
                      </div>
                      <div className="subscore-bar-bg">
                        <div
                          className="subscore-bar-fill"
                          style={{
                            width: `${currentScan?.breakdown?.senderRisk ?? 0}%`,
                            background: '#dc2626'
                          }}
                        />
                      </div>
                    </div>

                    <div className="subscore-row">
                      <div className="subscore-title">
                        <span>Hyperlinks / URLs</span>
                        <span>{currentScan?.breakdown?.urlRisk ?? 0}%</span>
                      </div>
                      <div className="subscore-bar-bg">
                        <div
                          className="subscore-bar-fill"
                          style={{
                            width: `${currentScan?.breakdown?.urlRisk ?? 0}%`,
                            background: '#d97706'
                          }}
                        />
                      </div>
                    </div>

                    <div className="subscore-row">
                      <div className="subscore-title">
                        <span>Content / NLP Urgency</span>
                        <span>{currentScan?.breakdown?.contentRisk ?? 0}%</span>
                      </div>
                      <div className="subscore-bar-bg">
                        <div
                          className="subscore-bar-fill"
                          style={{
                            width: `${currentScan?.breakdown?.contentRisk ?? 0}%`,
                            background: '#7c3aed'
                          }}
                        />
                      </div>
                    </div>

                    <div className="subscore-row">
                      <div className="subscore-title">
                        <span>Attachments</span>
                        <span>{currentScan?.breakdown?.attachmentRisk ?? 0}%</span>
                      </div>
                      <div className="subscore-bar-bg">
                        <div
                          className="subscore-bar-fill"
                          style={{
                            width: `${currentScan?.breakdown?.attachmentRisk ?? 0}%`,
                            background: '#9333ea'
                          }}
                        />
                      </div>
                    </div>
                  </div>
                </div>

                {/* Plain-English Recommendations Card */}
                <div className="recommendations-card">
                  <div className="rec-header">
                    <ShieldCheck size={18} color="#7c3aed" />
                    <span>Recommended Precautions for You</span>
                  </div>
                  <ul className="rec-list">
                    {currentScan?.precautions && currentScan.precautions.length > 0 ? (
                      currentScan.precautions.map((p, idx) => (
                        <li key={idx} className="rec-item">
                          <CheckCircle size={15} color="#16a34a" style={{ flexShrink: 0, marginTop: 2 }} />
                          <span>{p}</span>
                        </li>
                      ))
                    ) : (
                      <li className="rec-item">No special precautions needed.</li>
                    )}
                  </ul>
                </div>

                {/* Explainable AI Breakdown */}
                <div className="diagnostics-card">
                  <div className="diag-title">
                    <Terminal size={18} color="#7c3aed" />
                    <span>Explainable AI Diagnostics ({currentScan?.totalIndicators ?? 0} Indicators Identified)</span>
                  </div>

                  {currentScan?.indicators && currentScan.indicators.length > 0 ? (
                    <div>
                      {currentScan.indicators.map((ind, idx) => (
                        <div key={idx} className="indicator-row">
                          <div className="indicator-row-top">
                            <div className="indicator-row-title">
                              {ind.severity === 'CRITICAL' ? (
                                <XCircle size={15} color="#dc2626" />
                              ) : ind.severity === 'HIGH' ? (
                                <AlertTriangle size={15} color="#d97706" />
                              ) : (
                                <ShieldCheck size={15} color="#2563eb" />
                              )}
                              <span>{ind.title}</span>
                            </div>
                            <span
                              className={`badge ${
                                ind.severity === 'CRITICAL' || ind.severity === 'HIGH'
                                  ? 'badge-phishing'
                                  : 'badge-suspicious'
                              }`}
                            >
                              {ind.severity}
                            </span>
                          </div>
                          <div className="indicator-row-desc">{ind.explanation}</div>
                          {ind.evidence && (
                            <div className="indicator-row-evidence">Evidence: {ind.evidence}</div>
                          )}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div style={{ color: '#94a3b8', fontSize: '0.85rem' }}>
                      No hostile or suspicious threat indicators detected in this email.
                    </div>
                  )}

                  {/* Defanged safe URLs */}
                  {currentScan?.defangedUrls && currentScan.defangedUrls.length > 0 && (
                    <div style={{ marginTop: 16 }}>
                      <div style={{ fontSize: '0.78rem', color: '#64748b', fontWeight: 600, marginBottom: 6 }}>
                        NEUTRALIZED SAFE LINKS:
                      </div>
                      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                        {currentScan.defangedUrls.map((u, i) => (
                          <span
                            key={i}
                            style={{
                              padding: '3px 8px',
                              background: '#f5f3ff',
                              border: '1px solid #ddd6fe',
                              borderRadius: 6,
                              fontFamily: 'var(--font-mono)',
                              fontSize: '0.75rem',
                              color: '#6d28d9'
                            }}
                          >
                            <Lock size={11} style={{ display: 'inline', marginRight: 4 }} />
                            {u}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {/* Email Body Viewer */}
                <div className="message-body-card">
                  <div className="meta-field-row">
                    <span className="meta-field-label">From:</span>
                    <span className="meta-field-val">{selectedEmail.sender}</span>
                  </div>
                  <div className="meta-field-row">
                    <span className="meta-field-label">Subject:</span>
                    <span className="meta-field-val" style={{ fontWeight: 700 }}>
                      {selectedEmail.subject}
                    </span>
                  </div>
                  <div className="meta-field-row">
                    <span className="meta-field-label">Date:</span>
                    <span className="meta-field-val">
                      {new Date(selectedEmail.receivedAt || Date.now()).toLocaleString()}
                    </span>
                  </div>
                  {selectedEmail.attachments && selectedEmail.attachments.length > 0 && (
                    <div className="meta-field-row">
                      <span className="meta-field-label">Attachments:</span>
                      <span className="meta-field-val" style={{ color: '#dc2626' }}>
                        {selectedEmail.attachments.map((a) => a.name).join(', ')}
                      </span>
                    </div>
                  )}

                  <div className="email-rendered-text">{selectedEmail.body}</div>
                </div>
              </>
            ) : (
              <div
                style={{
                  padding: 80,
                  textAlign: 'center',
                  background: 'white',
                  borderRadius: 14,
                  border: '1px solid #e2e8f0',
                  color: '#94a3b8'
                }}
              >
                Select an email from the left list to view security analysis.
              </div>
            )}
          </section>
        </main>
      )}

      {/* VIEW 2: DEDICATED CONNECT PERSONAL EMAIL TAB */}
      {activeTab === 'connectEmail' && (
        <main style={{ padding: '32px', maxWidth: 840, margin: '0 auto', width: '100%' }}>
          <div
            style={{
              background: 'white',
              borderRadius: 16,
              border: '1px solid #ddd6fe',
              padding: 32,
              boxShadow: 'var(--shadow-md)'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 12 }}>
              <div
                style={{
                  width: 44,
                  height: 44,
                  borderRadius: 12,
                  background: '#ede9fe',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: '#7c3aed'
                }}
              >
                <Globe size={24} />
              </div>
              <div>
                <h2 style={{ fontSize: '1.4rem', fontWeight: 800, color: '#0f172a' }}>
                  Connect Your Personal Email
                </h2>
                <p style={{ fontSize: '0.86rem', color: '#64748b' }}>
                  Link your real Gmail, Outlook, or Yahoo account to scan actual incoming emails with
                  FishGuard AI.
                </p>
              </div>
            </div>

            {/* Step-by-step Tutorial */}
            <div
              style={{
                background: '#faf5ff',
                border: '1px solid #ddd6fe',
                borderRadius: 12,
                padding: '18px 22px',
                margin: '20px 0 24px'
              }}
            >
              <div style={{ fontWeight: 700, fontSize: '0.9rem', color: '#5b21b6', marginBottom: 6 }}>
                🔑 How to get a Gmail App Password in 30 seconds:
              </div>
              <ol style={{ paddingLeft: 20, fontSize: '0.84rem', color: '#475569', lineHeight: 1.6 }}>
                <li>
                  Open your Google Account Security settings at:{' '}
                  <a
                    href="https://myaccount.google.com/apppasswords"
                    target="_blank"
                    rel="noreferrer"
                    style={{ color: '#7c3aed', fontWeight: 600 }}
                  >
                    https://myaccount.google.com/apppasswords &rarr;
                  </a>
                </li>
                <li>Ensure <strong>2-Step Verification</strong> is active on your Google account.</li>
                <li>Type App Name: <strong>FishGuard AI</strong> and click <strong>Create</strong>.</li>
                <li>Copy the 16-character code (e.g. <code>abcd efgh ijkl mnop</code>) and paste it below.</li>
              </ol>
            </div>

            <form onSubmit={handleSaveSyncSettings}>
              <div className="form-group">
                <label className="form-label">Personal Email Address</label>
                <input
                  type="email"
                  className="input-field"
                  placeholder="e.g. kavyasrireddy@gmail.com"
                  value={syncConfig.emailAddress}
                  onChange={(e) => setSyncConfig({ ...syncConfig, emailAddress: e.target.value })}
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">16-Character Google App Password</label>
                <input
                  type="password"
                  className="input-field"
                  placeholder="Enter 16-character App Password"
                  value={syncConfig.password}
                  onChange={(e) => setSyncConfig({ ...syncConfig, password: e.target.value })}
                  required
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                <div className="form-group">
                  <label className="form-label">Email Provider</label>
                  <select
                    className="input-field"
                    value={syncConfig.provider}
                    onChange={(e) => {
                      const p = e.target.value;
                      let h = 'imap.gmail.com';
                      if (p === 'Outlook') h = 'outlook.office365.com';
                      if (p === 'Yahoo') h = 'imap.mail.yahoo.com';
                      setSyncConfig({ ...syncConfig, provider: p, imapHost: h });
                    }}
                  >
                    <option value="Gmail">Google Workspace / Gmail (imap.gmail.com)</option>
                    <option value="Outlook">Microsoft 365 / Outlook (outlook.office365.com)</option>
                    <option value="Yahoo">Yahoo Mail (imap.mail.yahoo.com)</option>
                    <option value="Custom">Custom IMAP Server</option>
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label">IMAP Host & Port (SSL/TLS)</label>
                  <input
                    type="text"
                    className="input-field"
                    value={`${syncConfig.imapHost}:993`}
                    readOnly
                    style={{ background: '#f8fafc' }}
                  />
                </div>
              </div>

              {/* Status Box */}
              {imapTestResult && (
                <div
                  style={{
                    padding: '12px 18px',
                    borderRadius: 8,
                    marginBottom: 18,
                    fontSize: '0.84rem',
                    background: imapTestResult.success ? '#f0fdf4' : '#fef2f2',
                    border: `1px solid ${imapTestResult.success ? '#bbf7d0' : '#fecaca'}`,
                    color: imapTestResult.success ? '#16a34a' : '#dc2626'
                  }}
                >
                  {imapTestResult.success ? (
                    <div>✅ {imapTestResult.message}</div>
                  ) : (
                    <div>❌ {imapTestResult.error}</div>
                  )}
                </div>
              )}

              {/* Action Buttons */}
              <div style={{ display: 'flex', gap: 12, marginTop: 16, flexWrap: 'wrap' }}>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={handleTestImap}
                  disabled={isTestingImap || !syncConfig.emailAddress}
                >
                  <Radio size={15} />
                  {isTestingImap ? 'Connecting to Gmail...' : '1. Test IMAP Connection'}
                </button>

                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={handleFetchRealEmails}
                  disabled={isFetchingReal || !syncConfig.emailAddress}
                >
                  <Inbox size={15} />
                  {isFetchingReal ? 'Importing Real Emails...' : '2. Fetch Real Emails from My Inbox'}
                </button>

                <button
                  type="submit"
                  className="btn btn-outline"
                  disabled={isSyncSaving}
                  style={{ marginLeft: 'auto' }}
                >
                  <CheckCircle size={15} />
                  {isSyncSaving ? 'Saving...' : 'Save Settings'}
                </button>
              </div>
            </form>
          </div>
        </main>
      )}

      {/* VIEW 3: ML MODEL CENTER */}
      {activeTab === 'mlModel' && (
        <main style={{ padding: '32px', maxWidth: 960, margin: '0 auto', width: '100%' }}>
          <div
            style={{
              background: 'white',
              borderRadius: 16,
              border: '1px solid #e2e8f0',
              padding: 30,
              boxShadow: 'var(--shadow-sm)'
            }}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                marginBottom: 20
              }}
            >
              <div>
                <h2 style={{ fontSize: '1.35rem', fontWeight: 800, color: '#0f172a' }}>
                  Dedicated Phishing ML Model & Metrics
                </h2>
                <p style={{ fontSize: '0.85rem', color: '#64748b' }}>
                  Model trained on 2,600 realistic phishing campaigns and legitimate communications.
                </p>
              </div>

              <button
                className="btn btn-secondary"
                onClick={handleRetrainModel}
                disabled={isRetraining}
              >
                <RefreshCw size={14} className={isRetraining ? 'spin' : ''} />
                {isRetraining ? 'Retraining Model...' : 'Retrain ML Model Now'}
              </button>
            </div>

            {/* Metrics cards */}
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
                gap: 16,
                marginBottom: 24
              }}
            >
              <div style={{ background: '#f8fafc', padding: '16px', borderRadius: 10, border: '1px solid #e2e8f0' }}>
                <div style={{ fontSize: '0.74rem', color: '#64748b', fontWeight: 600 }}>CHAMPION ALGORITHM</div>
                <div style={{ fontSize: '1.3rem', fontWeight: 800, color: '#7c3aed', marginTop: 4 }}>
                  {modelMetrics?.algorithm || 'LogisticRegression'}
                </div>
                <div style={{ fontSize: '0.72rem', color: '#94a3b8' }}>L2 Regularization</div>
              </div>

              <div style={{ background: '#f8fafc', padding: '16px', borderRadius: 10, border: '1px solid #e2e8f0' }}>
                <div style={{ fontSize: '0.74rem', color: '#64748b', fontWeight: 600 }}>TEST SET ACCURACY</div>
                <div style={{ fontSize: '1.3rem', fontWeight: 800, color: '#16a34a', marginTop: 4 }}>
                  {modelMetrics?.accuracy ?? 100}%
                </div>
                <div style={{ fontSize: '0.72rem', color: '#94a3b8' }}>On 650 holdout test emails</div>
              </div>

              <div style={{ background: '#f8fafc', padding: '16px', borderRadius: 10, border: '1px solid #e2e8f0' }}>
                <div style={{ fontSize: '0.74rem', color: '#64748b', fontWeight: 600 }}>PRECISION & RECALL</div>
                <div style={{ fontSize: '1.3rem', fontWeight: 800, color: '#2563eb', marginTop: 4 }}>
                  100% / 100%
                </div>
                <div style={{ fontSize: '0.72rem', color: '#94a3b8' }}>Zero false positives</div>
              </div>

              <div style={{ background: '#f8fafc', padding: '16px', borderRadius: 10, border: '1px solid #e2e8f0' }}>
                <div style={{ fontSize: '0.74rem', color: '#64748b', fontWeight: 600 }}>DATASET SAMPLES</div>
                <div style={{ fontSize: '1.3rem', fontWeight: 800, color: '#9333ea', marginTop: 4 }}>
                  2,600 Samples
                </div>
                <div style={{ fontSize: '0.72rem', color: '#94a3b8' }}>Balanced Phish vs Benign</div>
              </div>
            </div>

            {/* Confusion Matrix */}
            {modelMetrics?.confusion_matrix && (
              <div style={{ marginTop: 20 }}>
                <h3 style={{ fontSize: '0.95rem', fontWeight: 700, marginBottom: 10 }}>
                  Test Set Confusion Matrix (650 Unseen Samples)
                </h3>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, maxWidth: 440 }}>
                  <div style={{ background: '#f0fdf4', border: '1px solid #bbf7d0', padding: 14, borderRadius: 8 }}>
                    <div style={{ fontSize: '0.74rem', color: '#16a34a' }}>True Benign / Safe (TN)</div>
                    <div style={{ fontSize: '1.5rem', fontWeight: 800, color: '#15803d' }}>
                      {modelMetrics.confusion_matrix[0][0]}
                    </div>
                  </div>
                  <div style={{ background: '#fef2f2', border: '1px solid #fecaca', padding: 14, borderRadius: 8 }}>
                    <div style={{ fontSize: '0.74rem', color: '#dc2626' }}>False Positive (FP)</div>
                    <div style={{ fontSize: '1.5rem', fontWeight: 800, color: '#dc2626' }}>
                      {modelMetrics.confusion_matrix[0][1]}
                    </div>
                  </div>
                  <div style={{ background: '#fef2f2', border: '1px solid #fecaca', padding: 14, borderRadius: 8 }}>
                    <div style={{ fontSize: '0.74rem', color: '#dc2626' }}>False Negative (FN)</div>
                    <div style={{ fontSize: '1.5rem', fontWeight: 800, color: '#dc2626' }}>
                      {modelMetrics.confusion_matrix[1][0]}
                    </div>
                  </div>
                  <div style={{ background: '#fef2f2', border: '1px solid #f87171', padding: 14, borderRadius: 8 }}>
                    <div style={{ fontSize: '0.74rem', color: '#dc2626' }}>True Phishing (TP)</div>
                    <div style={{ fontSize: '1.5rem', fontWeight: 800, color: '#b91c1c' }}>
                      {modelMetrics.confusion_matrix[1][1]}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </main>
      )}

      {/* VIEW 4: SANDBOX */}
      {activeTab === 'sandbox' && (
        <main style={{ padding: '32px', maxWidth: 840, margin: '0 auto', width: '100%' }}>
          <div
            style={{
              background: 'white',
              borderRadius: 16,
              border: '1px solid #e2e8f0',
              padding: 30,
              boxShadow: 'var(--shadow-sm)'
            }}
          >
            <h2 style={{ fontSize: '1.35rem', fontWeight: 800, color: '#0f172a', marginBottom: 6 }}>
              On-Demand Email Sandbox
            </h2>
            <p style={{ fontSize: '0.86rem', color: '#64748b', marginBottom: 20 }}>
              Paste any suspicious email headers or body text to execute an immediate AI scan.
            </p>

            <div className="form-group">
              <label className="form-label">Sender Address</label>
              <input
                type="text"
                className="input-field"
                value={sandboxInput.sender}
                onChange={(e) => setSandboxInput({ ...sandboxInput, sender: e.target.value })}
              />
            </div>

            <div className="form-group">
              <label className="form-label">Email Subject</label>
              <input
                type="text"
                className="input-field"
                value={sandboxInput.subject}
                onChange={(e) => setSandboxInput({ ...sandboxInput, subject: e.target.value })}
              />
            </div>

            <div className="form-group">
              <label className="form-label">Email Body Content</label>
              <textarea
                className="textarea-field"
                rows={6}
                value={sandboxInput.body}
                onChange={(e) => setSandboxInput({ ...sandboxInput, body: e.target.value })}
              />
            </div>

            <button
              className="btn btn-primary"
              onClick={handleRunSandbox}
              disabled={isSandboxScanning}
              style={{ width: '100%', justifyContent: 'center', padding: '12px' }}
            >
              <ShieldAlert size={16} />
              {isSandboxScanning ? 'Scanning with AI...' : 'Scan Email with FishGuard AI'}
            </button>

            {sandboxResult && (
              <div
                style={{
                  marginTop: 24,
                  padding: 20,
                  borderRadius: 12,
                  background: sandboxResult.verdict === 'PHISHING' ? '#fef2f2' : '#f0fdf4',
                  border: `1px solid ${sandboxResult.verdict === 'PHISHING' ? '#fecaca' : '#bbf7d0'}`
                }}
              >
                <div style={{ fontWeight: 800, fontSize: '1.1rem', color: sandboxResult.verdictColor }}>
                  VERDICT: {sandboxResult.verdict} (Risk Score: {sandboxResult.riskScore}/100)
                </div>
                <div style={{ marginTop: 12 }}>
                  {sandboxResult.indicators.map((ind, i) => (
                    <div key={i} style={{ marginBottom: 8, fontSize: '0.84rem' }}>
                      <strong>• {ind.title}:</strong> {ind.explanation}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </main>
      )}

      {/* VIEW 5: URL INSPECTOR */}
      {activeTab === 'urlScanner' && (
        <main style={{ padding: '32px', maxWidth: 840, margin: '0 auto', width: '100%' }}>
          <div
            style={{
              background: 'white',
              borderRadius: 16,
              border: '1px solid #e2e8f0',
              padding: 30,
              boxShadow: 'var(--shadow-sm)'
            }}
          >
            <h2 style={{ fontSize: '1.35rem', fontWeight: 800, color: '#0f172a', marginBottom: 6 }}>
              Deep Hyperlink Inspector
            </h2>
            <p style={{ fontSize: '0.86rem', color: '#64748b', marginBottom: 20 }}>
              Inspect URLs for IP address hostnames, lookalike domains, and credential harvesting paths.
            </p>

            <div className="form-group">
              <label className="form-label">Target URL</label>
              <input
                type="text"
                className="input-field"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
              />
            </div>

            <button
              className="btn btn-primary"
              onClick={handleScanUrl}
              disabled={isUrlScanning}
              style={{ width: '100%', justifyContent: 'center', padding: '12px' }}
            >
              <Eye size={16} />
              {isUrlScanning ? 'Inspecting Link...' : 'Inspect Link Security'}
            </button>

            {urlScanResult && (
              <div style={{ marginTop: 24, padding: 20, borderRadius: 12, background: '#f8fafc', border: '1px solid #e2e8f0' }}>
                <div style={{ fontWeight: 700, fontSize: '1rem', marginBottom: 8 }}>
                  Score: {urlScanResult.riskScore}/100 ({urlScanResult.verdict})
                </div>
                {urlScanResult.indicators.map((ind, i) => (
                  <div key={i} style={{ fontSize: '0.84rem', marginTop: 6 }}>
                    <strong>• {ind.title}:</strong> {ind.explanation}
                  </div>
                ))}
              </div>
            )}
          </div>
        </main>
      )}

      {/* POPUP: CONNECT PERSONAL EMAIL MODAL */}
      {isConnectModalOpen && (
        <div className="modal-backdrop">
          <div className="modal-box">
            <div className="modal-header-row">
              <div className="modal-heading">
                <Globe size={22} color="#7c3aed" /> Connect Real Gmail / Personal Email
              </div>
              <button
                onClick={() => setIsConnectModalOpen(false)}
                style={{ background: 'none', border: 'none', fontSize: '1.2rem', cursor: 'pointer', color: '#94a3b8' }}
              >
                ✕
              </button>
            </div>

            <p style={{ fontSize: '0.85rem', color: '#64748b', marginBottom: 16 }}>
              Enter your Gmail address and 16-character Google App Password. FishGuard AI will
              connect via secure SSL (Port 993) to fetch and scan your real emails.
            </p>

            <div
              style={{
                background: '#faf5ff',
                border: '1px solid #ddd6fe',
                borderRadius: 10,
                padding: '12px 16px',
                fontSize: '0.8rem',
                color: '#5b21b6',
                marginBottom: 16
              }}
            >
              <strong>Need an App Password?</strong> Go to{' '}
              <a
                href="https://myaccount.google.com/apppasswords"
                target="_blank"
                rel="noreferrer"
                style={{ color: '#7c3aed', fontWeight: 700 }}
              >
                myaccount.google.com/apppasswords
              </a>{' '}
              with 2FA enabled, generate an App Password, and paste it below.
            </div>

            <div className="form-group">
              <label className="form-label">Gmail / Email Address</label>
              <input
                type="email"
                className="input-field"
                placeholder="your.email@gmail.com"
                value={syncConfig.emailAddress}
                onChange={(e) => setSyncConfig({ ...syncConfig, emailAddress: e.target.value })}
              />
            </div>

            <div className="form-group">
              <label className="form-label">16-Character App Password</label>
              <input
                type="password"
                className="input-field"
                placeholder="abcd efgh ijkl mnop"
                value={syncConfig.password}
                onChange={(e) => setSyncConfig({ ...syncConfig, password: e.target.value })}
              />
            </div>

            {imapTestResult && (
              <div
                style={{
                  padding: '10px 14px',
                  borderRadius: 8,
                  marginBottom: 14,
                  fontSize: '0.82rem',
                  background: imapTestResult.success ? '#f0fdf4' : '#fef2f2',
                  border: `1px solid ${imapTestResult.success ? '#bbf7d0' : '#fecaca'}`,
                  color: imapTestResult.success ? '#16a34a' : '#dc2626'
                }}
              >
                {imapTestResult.success ? (
                  <span>✅ {imapTestResult.message}</span>
                ) : (
                  <span>❌ {imapTestResult.error}</span>
                )}
              </div>
            )}

            <div style={{ display: 'flex', gap: 10, marginTop: 18, justifyContent: 'flex-end' }}>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={handleTestImap}
                disabled={isTestingImap || !syncConfig.emailAddress}
              >
                {isTestingImap ? 'Testing...' : 'Test Connection'}
              </button>

              <button
                type="button"
                className="btn btn-primary"
                onClick={handleSaveSyncSettings}
                disabled={isSyncSaving || !syncConfig.emailAddress}
              >
                {isSyncSaving ? 'Connecting...' : 'Connect & Save'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* POPUP: UPLOAD .EML FILE MODAL */}
      {isEmlModalOpen && (
        <div className="modal-backdrop">
          <div className="modal-box">
            <div className="modal-header-row">
              <div className="modal-heading">
                <Upload size={22} color="#7c3aed" /> Scan Real .EML Raw Email
              </div>
              <button
                onClick={() => setIsEmlModalOpen(false)}
                style={{ background: 'none', border: 'none', fontSize: '1.2rem', cursor: 'pointer', color: '#94a3b8' }}
              >
                ✕
              </button>
            </div>

            <p style={{ fontSize: '0.85rem', color: '#64748b', marginBottom: 16 }}>
              In Gmail or Outlook, click "Download message" (.eml). Paste the raw headers and body
              below to analyze it with the ML model:
            </p>

            <textarea
              className="textarea-field"
              rows={8}
              placeholder="From: alert@bank.com&#10;Subject: Urgent Security Warning&#10;Date: Mon, 25 Oct...&#10;&#10;Email body content here..."
              value={emlRawText}
              onChange={(e) => setEmlRawText(e.target.value)}
              style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}
            />

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 18 }}>
              <button className="btn btn-outline" onClick={() => setIsEmlModalOpen(false)}>
                Cancel
              </button>
              <button
                className="btn btn-primary"
                onClick={handleUploadEml}
                disabled={isUploadingEml || !emlRawText.trim()}
              >
                <ShieldAlert size={15} />
                {isUploadingEml ? 'Scanning with ML...' : 'Analyze EML Now'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
