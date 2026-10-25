/**
 * FishGuard AI - REST API Routes with Real-Time IMAP & ML Model Endpoints
 */

const express = require('express');
const http = require('http');

module.exports = function createApiRouter(emailService) {
  const router = express.Router();

  // List all scanned emails
  router.get('/emails', (req, res) => {
    try {
      const { filter, search } = req.query;
      const emails = emailService.getAllEmails(filter, search);
      res.json({ success: true, count: emails.length, emails });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // Get specific email by ID
  router.get('/emails/:id', (req, res) => {
    try {
      const email = emailService.getEmailById(req.params.id);
      if (!email) {
        return res.status(404).json({ success: false, error: 'Email not found' });
      }
      res.json({ success: true, email });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // Analyze custom email on the fly (Sandbox)
  router.post('/emails/analyze', async (req, res) => {
    try {
      const { subject, sender, body, urls, attachments } = req.body;
      if (!subject && !body) {
        return res.status(400).json({ success: false, error: 'Subject or body is required for analysis' });
      }

      const scanResult = await emailService.analyzer.analyze({
        subject: subject || '',
        sender: sender || '',
        body: body || '',
        urls: urls || [],
        attachments: attachments || []
      });

      res.json({ success: true, scan: scanResult });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // Parse & Scan a real raw .EML / RFC 822 uploaded email
  router.post('/emails/upload-eml', async (req, res) => {
    try {
      const { emlRaw } = req.body;
      if (!emlRaw) {
        return res.status(400).json({ success: false, error: 'Raw EML content is required' });
      }

      const mlHost = new URL(emailService.analyzer.mlServiceUrl);
      const payload = JSON.stringify({ eml_raw: emlRaw });

      const parsedRes = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: mlHost.hostname,
          port: mlHost.port || 8001,
          path: '/parse-eml',
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload)
          },
          timeout: 5000
        }, (resp) => {
          let data = '';
          resp.on('data', chunk => data += chunk);
          resp.on('end', () => {
            try {
              resolve(JSON.parse(data));
            } catch (e) {
              reject(e);
            }
          });
        });
        req.on('error', reject);
        req.write(payload);
        req.end();
      });

      if (!parsedRes.success || !parsedRes.email) {
        return res.status(400).json({ success: false, error: 'Failed to parse EML headers' });
      }

      const processed = await emailService.processIncomingEmail({
        ...parsedRes.email,
        isRealEmail: true
      });

      res.json({ success: true, email: processed });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // Test Real IMAP Credentials
  router.post('/imap/test', async (req, res) => {
    try {
      const { host, port, username, password, useTls } = req.body;
      const mlHost = new URL(emailService.analyzer.mlServiceUrl);
      const payload = JSON.stringify({
        host: host || 'imap.gmail.com',
        port: port || 993,
        username,
        password,
        use_ssl: useTls !== false
      });

      const result = await new Promise((resolve, reject) => {
        const r = http.request({
          hostname: mlHost.hostname,
          port: mlHost.port || 8001,
          path: '/imap/test',
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload)
          },
          timeout: 10000
        }, (resp) => {
          let data = '';
          resp.on('data', chunk => data += chunk);
          resp.on('end', () => {
            try {
              resolve(JSON.parse(data));
            } catch (e) {
              reject(e);
            }
          });
        });
        r.on('error', reject);
        r.write(payload);
        r.end();
      });

      res.json(result);
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // Sync Real Emails from User's Inbox immediately
  router.post('/imap/sync-now', async (req, res) => {
    try {
      const { limit } = req.body;
      const result = await emailService.syncRealEmails(limit || 10);
      res.json({ success: true, ...result });
    } catch (err) {
      res.status(400).json({ success: false, error: err.message });
    }
  });

  // Get ML Model Performance Metrics
  router.get('/model/metrics', async (req, res) => {
    try {
      const mlHost = new URL(emailService.analyzer.mlServiceUrl);
      const metrics = await new Promise((resolve, reject) => {
        http.get(`${emailService.analyzer.mlServiceUrl}/model/metrics`, (resp) => {
          let data = '';
          resp.on('data', chunk => data += chunk);
          resp.on('end', () => {
            try {
              resolve(JSON.parse(data));
            } catch (e) {
              reject(e);
            }
          });
        }).on('error', reject);
      });
      res.json({ success: true, metrics });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // Trigger On-Demand Model Retraining
  router.post('/model/retrain', async (req, res) => {
    try {
      const mlHost = new URL(emailService.analyzer.mlServiceUrl);
      const retrainResult = await new Promise((resolve, reject) => {
        const r = http.request({
          hostname: mlHost.hostname,
          port: mlHost.port || 8001,
          path: '/model/retrain',
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          timeout: 60000
        }, (resp) => {
          let data = '';
          resp.on('data', chunk => data += chunk);
          resp.on('end', () => {
            try {
              resolve(JSON.parse(data));
            } catch (e) {
              reject(e);
            }
          });
        });
        r.on('error', reject);
        r.end();
      });
      res.json(retrainResult);
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // Simulate an incoming email
  router.post('/emails/simulate-incoming', async (req, res) => {
    try {
      const emailData = req.body;
      const processed = await emailService.processIncomingEmail(emailData);
      res.json({ success: true, email: processed });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // Toggle quarantine for an email
  router.post('/emails/:id/quarantine', (req, res) => {
    try {
      const email = emailService.toggleQuarantine(req.params.id);
      if (!email) {
        return res.status(404).json({ success: false, error: 'Email not found' });
      }
      res.json({ success: true, email });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // Defang links in an email
  router.post('/emails/:id/defang', (req, res) => {
    try {
      const email = emailService.defangEmailLinks(req.params.id);
      if (!email) {
        return res.status(404).json({ success: false, error: 'Email not found' });
      }
      res.json({ success: true, email });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // SOC Telemetry & Threat Analytics
  router.get('/analytics', (req, res) => {
    try {
      const analytics = emailService.getAnalytics();
      res.json({ success: true, analytics });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // Personal Email Sync Configuration
  router.get('/settings/email-sync', (req, res) => {
    res.json({ success: true, config: emailService.syncConfig });
  });

  router.post('/settings/email-sync', (req, res) => {
    try {
      const updated = emailService.updateSyncConfig(req.body);
      res.json({ success: true, message: 'Email synchronization settings updated', config: updated });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // Dedicated URL Security Scanner
  router.post('/scanner/url', async (req, res) => {
    try {
      const { url } = req.body;
      if (!url) return res.status(400).json({ success: false, error: 'URL is required' });

      const scanResult = await emailService.analyzer.analyze({
        subject: 'URL Scan',
        sender: 'scanner@internal',
        body: `URL scan target: ${url}`,
        urls: [url]
      });

      res.json({ success: true, scan: scanResult });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  return router;
};
