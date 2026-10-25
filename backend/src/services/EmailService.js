/**
 * FishGuard AI - Email Management, Threat Intelligence & Real-Time IMAP Service
 */

const http = require('http');
const mockEmails = require('../data/mockEmails');
const PhishingAnalyzerEngine = require('./PhishingAnalyzerEngine');

class EmailService {
  constructor(io) {
    this.io = io;
    this.analyzer = new PhishingAnalyzerEngine();
    this.emails = [];
    this.syncConfig = {
      emailAddress: '',
      provider: 'Gmail',
      imapHost: 'imap.gmail.com',
      imapPort: 993,
      password: '',
      useTls: true,
      syncIntervalMinutes: 2,
      isAutoQuarantineEnabled: true,
      isLivePollingActive: false,
      lastSyncTimestamp: null,
      syncStatus: 'Configured'
    };

    this.pollingTimer = null;
    this.seenMessageIds = new Set();

    // Initialize repository
    this.init();
  }

  async init() {
    console.log('[FishGuard-Backend] Initializing email repository...');
    for (const raw of mockEmails) {
      const scanResult = await this.analyzer.analyze(raw);
      this.emails.push({
        ...raw,
        scan: scanResult
      });
      this.seenMessageIds.add(raw.id);
    }
  }

  getAllEmails(filter = 'ALL', searchQuery = '') {
    let result = [...this.emails];

    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      result = result.filter(e =>
        (e.subject || '').toLowerCase().includes(q) ||
        (e.sender || '').toLowerCase().includes(q) ||
        (e.body || '').toLowerCase().includes(q)
      );
    }

    if (filter === 'PHISHING') {
      result = result.filter(e => e.scan && e.scan.verdict === 'PHISHING');
    } else if (filter === 'SUSPICIOUS') {
      result = result.filter(e => e.scan && e.scan.verdict === 'SUSPICIOUS');
    } else if (filter === 'SAFE') {
      result = result.filter(e => e.scan && e.scan.verdict === 'SAFE');
    } else if (filter === 'QUARANTINED') {
      result = result.filter(e => e.isQuarantined);
    } else if (filter === 'REAL') {
      result = result.filter(e => e.isRealEmail);
    }

    result.sort((a, b) => new Date(b.receivedAt || 0) - new Date(a.receivedAt || 0));
    return result;
  }

  getEmailById(id) {
    const email = this.emails.find(e => e.id === id);
    if (email) {
      email.isRead = true;
    }
    return email;
  }

  async processIncomingEmail(emailData) {
    const id = emailData.id || ('em-' + Date.now());
    const urls = emailData.urls || this.analyzer.extractUrls(emailData.body);

    const emailPayload = {
      id,
      sender: emailData.sender || 'unknown@domain.com',
      senderName: emailData.senderName || emailData.sender || 'Unknown Sender',
      recipient: emailData.recipient || this.syncConfig.emailAddress || 'user@inbox.com',
      subject: emailData.subject || 'No Subject',
      body: emailData.body || '',
      urls,
      attachments: emailData.attachments || [],
      receivedAt: emailData.receivedAt || new Date().toISOString(),
      isRead: false,
      isQuarantined: false,
      isRealEmail: Boolean(emailData.isRealEmail)
    };

    // Deep multi-vector AI scan
    const scanResult = await this.analyzer.analyze(emailPayload);
    emailPayload.scan = scanResult;

    if (this.syncConfig.isAutoQuarantineEnabled && scanResult.verdict === 'PHISHING') {
      emailPayload.isQuarantined = true;
    }

    // Prepend to feed
    this.emails.unshift(emailPayload);
    this.seenMessageIds.add(id);

    if (this.io) {
      this.io.emit('new-email', emailPayload);
      if (scanResult.verdict === 'PHISHING') {
        this.io.emit('threat-alert', {
          id: emailPayload.id,
          subject: emailPayload.subject,
          sender: emailPayload.sender,
          riskScore: scanResult.riskScore,
          isReal: emailPayload.isRealEmail,
          message: emailPayload.isRealEmail 
            ? '🚨 REAL INBOX THREAT: Malicious phishing email detected in your inbox!'
            : 'CRITICAL: Phishing email detected and quarantined!'
        });
      }
    }

    return emailPayload;
  }

  /**
   * Syncs real emails from the user's real email inbox via the ML engine's IMAP client
   */
  async syncRealEmails(limit = 10) {
    if (!this.syncConfig.emailAddress || !this.syncConfig.password) {
      throw new Error('Please configure your email address and App Password in the Email Integration tab first.');
    }

    const payload = JSON.stringify({
      host: this.syncConfig.imapHost || 'imap.gmail.com',
      port: this.syncConfig.imapPort || 993,
      username: this.syncConfig.emailAddress,
      password: this.syncConfig.password,
      use_ssl: this.syncConfig.useTls !== false,
      folder: 'INBOX',
      limit
    });

    const mlHost = new URL(this.analyzer.mlServiceUrl);
    const fetchedEmails = await new Promise((resolve, reject) => {
      const req = http.request({
        hostname: mlHost.hostname,
        port: mlHost.port || 8001,
        path: '/imap/fetch',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload)
        },
        timeout: 15000
      }, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            const parsed = JSON.parse(data);
            if (parsed.success) {
              resolve(parsed.emails || []);
            } else {
              reject(new Error(parsed.error || 'Failed to fetch from IMAP server'));
            }
          } catch (e) {
            reject(new Error('Invalid response from IMAP service: ' + data));
          }
        });
      });

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('IMAP connection timed out'));
      });

      req.write(payload);
      req.end();
    });

    // Process each fetched real email through the AI threat engine
    const newlyAdded = [];
    for (const rawEmail of fetchedEmails) {
      if (!this.seenMessageIds.has(rawEmail.id)) {
        const processed = await this.processIncomingEmail({
          ...rawEmail,
          isRealEmail: true
        });
        newlyAdded.push(processed);
      }
    }

    this.syncConfig.lastSyncTimestamp = new Date().toISOString();
    return {
      fetchedCount: fetchedEmails.length,
      newlyAnalyzed: newlyAdded.length,
      emails: newlyAdded
    };
  }

  toggleQuarantine(id) {
    const email = this.emails.find(e => e.id === id);
    if (!email) return null;
    email.isQuarantined = !email.isQuarantined;
    return email;
  }

  defangEmailLinks(id) {
    const email = this.emails.find(e => e.id === id);
    if (!email) return null;

    if (email.scan && email.scan.defangedUrls) {
      let defangedBody = email.body;
      email.urls.forEach((origUrl, idx) => {
        const safeUrl = email.scan.defangedUrls[idx] || origUrl;
        defangedBody = defangedBody.split(origUrl).join(safeUrl);
      });
      email.body = defangedBody;
      email.linksDefanged = true;
    }
    return email;
  }

  getAnalytics() {
    const total = this.emails.length;
    let phishingCount = 0;
    let suspiciousCount = 0;
    let safeCount = 0;
    let quarantinedCount = 0;
    let totalRisk = 0;
    let realEmailsCount = 0;

    const categoryBreakdown = {
      'Domain & Sender Spoofing': 0,
      'Malicious Links': 0,
      'Social Engineering': 0,
      'Credential Harvesting': 0,
      'Malicious Attachment': 0
    };

    this.emails.forEach(e => {
      if (e.isRealEmail) realEmailsCount++;
      const verdict = e.scan ? e.scan.verdict : 'SAFE';
      if (verdict === 'PHISHING') phishingCount++;
      else if (verdict === 'SUSPICIOUS') suspiciousCount++;
      else safeCount++;

      if (e.isQuarantined) quarantinedCount++;
      if (e.scan) totalRisk += e.scan.riskScore;

      if (e.scan && e.scan.indicators) {
        e.scan.indicators.forEach(ind => {
          if (categoryBreakdown[ind.category] !== undefined) {
            categoryBreakdown[ind.category]++;
          }
        });
      }
    });

    const averageRisk = total > 0 ? Math.round(totalRisk / total) : 0;
    const threatDetectionRate = total > 0 ? Math.round(((phishingCount + suspiciousCount) / total) * 100) : 0;

    return {
      totalEmailsScanned: total,
      realEmailsCount,
      phishingBlocked: phishingCount,
      suspiciousFlagged: suspiciousCount,
      benignVerified: safeCount,
      quarantinedCount,
      averageRiskScore: averageRisk,
      threatDetectionRate,
      categoryBreakdown,
      syncConfig: {
        ...this.syncConfig,
        password: this.syncConfig.password ? '••••••••••••••••' : ''
      }
    };
  }

  updateSyncConfig(newConfig) {
    this.syncConfig = {
      ...this.syncConfig,
      ...newConfig
    };

    // Toggle background polling listener if requested
    if (this.syncConfig.isLivePollingActive && !this.pollingTimer) {
      const intervalMs = Math.max(1, this.syncConfig.syncIntervalMinutes || 2) * 60 * 1000;
      console.log(`[FishGuard-IMAP] Starting live background email sync every ${intervalMs / 1000}s`);
      this.pollingTimer = setInterval(async () => {
        try {
          console.log('[FishGuard-IMAP] Polling inbox for new messages...');
          await this.syncRealEmails(5);
        } catch (e) {
          console.log('[FishGuard-IMAP] Polling check:', e.message);
        }
      }, intervalMs);
    } else if (!this.syncConfig.isLivePollingActive && this.pollingTimer) {
      clearInterval(this.pollingTimer);
      this.pollingTimer = null;
      console.log('[FishGuard-IMAP] Live background polling stopped.');
    }

    return {
      ...this.syncConfig,
      password: this.syncConfig.password ? '••••••••••••••••' : ''
    };
  }
}

module.exports = EmailService;
