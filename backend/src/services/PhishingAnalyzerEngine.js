/**
 * FishGuard AI - Phishing & Cyber Threat Analyzer Engine
 * Industry-grade multi-vector analysis: Domain, NLP/Content, URLs, Attachments, and ML Inference.
 */

const http = require('http');

// Known high-value target brands and their legitimate domains
const BRAND_DOMAINS = {
  'paypal': ['paypal.com', 'paypal-corp.com'],
  'google': ['google.com', 'gmail.com', 'googlemail.com', 'accounts.google.com'],
  'microsoft': ['microsoft.com', 'office.com', 'live.com', 'outlook.com', 'azure.com'],
  'apple': ['apple.com', 'icloud.com'],
  'amazon': ['amazon.com', 'amazon.co.uk', 'aws.amazon.com'],
  'netflix': ['netflix.com'],
  'chase': ['chase.com', 'jpmorganchase.com'],
  'wellsfargo': ['wellsfargo.com'],
  'bankofamerica': ['bankofamerica.com', 'bofa.com'],
  'dhl': ['dhl.com', 'dhl-express.com'],
  'fedex': ['fedex.com'],
  'docusign': ['docusign.com', 'docusign.net'],
  'dropbox': ['dropbox.com'],
  'linkedin': ['linkedin.com'],
  'stripe': ['stripe.com'],
  'facebook': ['facebook.com', 'meta.com', 'instagram.com'],
  'coinbase': ['coinbase.com']
};

// High-risk Top Level Domains frequently abused in phishing campaigns
const SUSPICIOUS_TLDS = [
  '.xyz', '.top', '.icu', '.buzz', '.club', '.work', '.click',
  '.rest', '.country', '.tk', '.ml', '.ga', '.cf', '.gq', '.info', '.biz'
];

// Dangerous file extensions
const DANGEROUS_EXTENSIONS = [
  '.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.iso', '.hta', '.pif', '.wsf'
];
const MACRO_EXTENSIONS = ['.docm', '.xlsm', '.pptm'];

// Levenshtein distance implementation for typosquatting detection
function levenshteinDistance(s1, s2) {
  const m = s1.length;
  const n = s2.length;
  const dp = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (s1[i - 1] === s2[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1];
      } else {
        dp[i][j] = 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
      }
    }
  }
  return dp[m][n];
}

class PhishingAnalyzerEngine {
  constructor(mlServiceUrl = process.env.ML_SERVICE_URL || 'http://127.0.0.1:8001') {
    this.mlServiceUrl = mlServiceUrl;
  }

  /**
   * Main analysis pipeline
   * @param {Object} email - { sender, subject, body, urls, attachments, rawHeaders }
   * @returns {Promise<Object>} Full diagnostic report with score, indicators, and precautions
   */
  async analyze(email) {
    const indicators = [];
    let senderRisk = 0;
    let contentRisk = 0;
    let urlRisk = 0;
    let attachmentRisk = 0;

    const senderEmail = (email.sender || '').toLowerCase().trim();
    const subject = email.subject || '';
    const body = email.body || '';
    const urls = email.urls || this.extractUrls(body);
    const attachments = email.attachments || [];

    // 1. SENDER & DOMAIN ANALYSIS
    const domainMatch = senderEmail.match(/@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
    const senderDomain = domainMatch ? domainMatch[1] : '';

    if (senderDomain) {
      // 1.1 Suspicious TLD check
      const matchedTld = SUSPICIOUS_TLDS.find(tld => senderDomain.endsWith(tld));
      if (matchedTld) {
        senderRisk += 30;
        indicators.push({
          id: 'suspicious-tld',
          category: 'Domain & Sender',
          severity: 'HIGH',
          title: `Suspicious Top-Level Domain (${matchedTld})`,
          explanation: `The sender domain '${senderDomain}' uses a TLD commonly linked to disposable phishing infrastructures and low-reputation registrars.`,
          evidence: senderDomain
        });
      }

      // 1.2 Brand Spoofing & Typosquatting
      for (const [brand, legitDomains] of Object.entries(BRAND_DOMAINS)) {
        const brandInSender = senderEmail.includes(brand);
        const isLegit = legitDomains.some(ld => senderDomain === ld || senderDomain.endsWith('.' + ld));

        if (brandInSender && !isLegit) {
          senderRisk += 45;
          indicators.push({
            id: 'brand-impersonation',
            category: 'Domain & Sender',
            severity: 'CRITICAL',
            title: `Impersonation of Trusted Brand (${brand.toUpperCase()})`,
            explanation: `The sender claims to be '${brand.toUpperCase()}', but the actual sender domain is '${senderDomain}', which is NOT an official domain for ${brand}.`,
            evidence: `Sender: ${senderEmail} (Claiming: ${brand})`
          });
          break;
        }

        // Typosquatting / Homoglyph distance on domain root
        const domainParts = senderDomain.split('.');
        const domainRoot = domainParts[domainParts.length - 2] || '';
        const dist = levenshteinDistance(domainRoot, brand);

        if (dist === 1 && domainRoot !== brand) {
          senderRisk += 40;
          indicators.push({
            id: 'typosquatting-detected',
            category: 'Domain & Sender',
            severity: 'CRITICAL',
            title: `Typosquatting Detected: Looks like '${brand}'`,
            explanation: `The domain '${senderDomain}' differs by only 1 character from legitimate brand '${brand}'. Attackers use this to trick victims into thinking it's authentic.`,
            evidence: `${domainRoot} vs ${brand} (Levenshtein distance: 1)`
          });
        }
      }

      // 1.3 Free webmail spoofing enterprise service
      const freeProviders = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com'];
      if (freeProviders.includes(senderDomain)) {
        const lowerSubject = subject.toLowerCase();
        const businessTerms = ['invoice', 'wire transfer', 'payroll', 'paypal support', 'billing department', 'bank alert'];
        if (businessTerms.some(term => lowerSubject.includes(term))) {
          senderRisk += 25;
          indicators.push({
            id: 'freemail-business-spoof',
            category: 'Domain & Sender',
            severity: 'MEDIUM',
            title: 'Commercial / Banking Communication from Free Webmail',
            explanation: `Official billing or financial notifications rarely originate from public free email services like ${senderDomain}.`,
            evidence: `Sender: ${senderEmail}`
          });
        }
      }
    } else {
      senderRisk += 15;
      indicators.push({
        id: 'malformed-sender',
        category: 'Domain & Sender',
        severity: 'MEDIUM',
        title: 'Malformed or Missing Sender Address',
        explanation: 'Email lacks a RFC-compliant sender domain.',
        evidence: senderEmail || 'Empty'
      });
    }

    // 2. URL & HYPERLINK ANALYSIS
    if (urls.length > 0) {
      for (const urlStr of urls) {
        try {
          const parsed = new URL(urlStr);

          // 2.1 Direct IP address in URL
          if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(parsed.hostname)) {
            urlRisk += 40;
            indicators.push({
              id: 'ip-in-url',
              category: 'Malicious Links',
              severity: 'CRITICAL',
              title: 'Direct IP Address Used as Hostname',
              explanation: `The link '${urlStr}' routes directly to a raw IP address instead of a registered domain name, a hallmark of credential harvesting servers.`,
              evidence: parsed.hostname
            });
          }

          // 2.2 Suspicious keywords in URL path or query
          const sensitiveKeywords = ['login', 'signin', 'verify', 'update-password', 'account-restore', 'billing', 'wallet', 'crypto', 'session'];
          const matchedKw = sensitiveKeywords.filter(k => parsed.pathname.includes(k) || parsed.search.includes(k));
          if (matchedKw.length > 0) {
            urlRisk += 20;
            indicators.push({
              id: 'credential-harvesting-url',
              category: 'Malicious Links',
              severity: 'HIGH',
              title: 'Credential Harvesting Path in URL',
              explanation: `The link targets sensitive authentication paths: ${matchedKw.join(', ')}.`,
              evidence: urlStr
            });
          }

          // 2.3 URL Shortener detection
          const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 'cutt.ly'];
          if (shorteners.includes(parsed.hostname)) {
            urlRisk += 20;
            indicators.push({
              id: 'url-shortener-mask',
              category: 'Malicious Links',
              severity: 'MEDIUM',
              title: 'URL Shortener Used to Mask True Destination',
              explanation: `Link uses shortener '${parsed.hostname}' which conceals the final landing page destination.`,
              evidence: urlStr
            });
          }

          // 2.4 Suspicious TLD in link
          const linkTld = SUSPICIOUS_TLDS.find(tld => parsed.hostname.endsWith(tld));
          if (linkTld) {
            urlRisk += 25;
            indicators.push({
              id: 'suspicious-link-tld',
              category: 'Malicious Links',
              severity: 'HIGH',
              title: `Link Points to Risky TLD (${linkTld})`,
              explanation: `Embedded link '${urlStr}' directs to high-risk TLD '${linkTld}'.`,
              evidence: parsed.hostname
            });
          }
        } catch (e) {
          // invalid url format
        }
      }
    }

    // 3. CONTENT & NLP HEURISTICS
    const fullText = `${subject} ${body}`.toLowerCase();

    // 3.1 Urgency & Pressure triggers
    const urgencyKeywords = [
      'immediate action required', 'urgent', 'within 24 hours', 'within 12 hours',
      'account suspended', 'permanently closed', 'final notice', 'action required',
      'will be terminated', 'restricted immediately'
    ];
    const foundUrgency = urgencyKeywords.filter(k => fullText.includes(k));
    if (foundUrgency.length > 0) {
      contentRisk += Math.min(35, foundUrgency.length * 15);
      indicators.push({
        id: 'urgency-pressure',
        category: 'Social Engineering',
        severity: 'HIGH',
        title: 'Coercive Urgency Tactics Detected',
        explanation: `Attackers manipulate urgency to force quick panic reactions before victims can verify legitimacy. Found: '${foundUrgency.join("', '")}'.`,
        evidence: foundUrgency.join(', ')
      });
    }

    // 3.2 Fear & Coercion / Threat
    const fearKeywords = ['unauthorized transaction', 'arrest', 'legal action', 'breach detected', 'lawsuit', 'compromised'];
    const foundFear = fearKeywords.filter(k => fullText.includes(k));
    if (foundFear.length > 0) {
      contentRisk += 25;
      indicators.push({
        id: 'fear-coercion',
        category: 'Social Engineering',
        severity: 'HIGH',
        title: 'Intimidation & Security Panic Triggers',
        explanation: 'Email utilizes intimidating security language to provoke panic response.',
        evidence: foundFear.join(', ')
      });
    }

    // 3.3 Credential Harvesting / Sensitive Data Extraction
    const credKeywords = ['password', 'confirm identity', 'social security', 'credit card', 'enter pin', 'seed phrase', 'unlock wallet'];
    const foundCreds = credKeywords.filter(k => fullText.includes(k));
    if (foundCreds.length > 0) {
      contentRisk += 30;
      indicators.push({
        id: 'credential-harvesting-request',
        category: 'Credential Harvesting',
        severity: 'CRITICAL',
        title: 'Solicitation of Sensitive Credentials / PII',
        explanation: 'Legitimate institutions never request sensitive credentials or PINs over unsolicited emails.',
        evidence: foundCreds.join(', ')
      });
    }

    // 3.4 Impersonal / Generic Greetings
    const genericGreetings = ['dear customer', 'dear client', 'dear user', 'valued member', 'dear member'];
    if (genericGreetings.some(g => fullText.includes(g))) {
      contentRisk += 10;
      indicators.push({
        id: 'generic-greeting',
        category: 'Social Engineering',
        severity: 'LOW',
        title: 'Generic Unpersonalized Salutation',
        explanation: 'Legitimate organizations typically address users by their registered full name.',
        evidence: 'Detected generic salutation'
      });
    }

    // 4. ATTACHMENT RISK
    if (attachments && attachments.length > 0) {
      attachments.forEach(att => {
        const name = (att.filename || att.name || '').toLowerCase();
        
        // Dangerous executable / script
        if (DANGEROUS_EXTENSIONS.some(ext => name.endsWith(ext))) {
          attachmentRisk += 50;
          indicators.push({
            id: 'executable-attachment',
            category: 'Malicious Attachment',
            severity: 'CRITICAL',
            title: `Dangerous Executable Attachment (${name})`,
            explanation: `File '${name}' contains an executable script format commonly used for malware, ransomware, or keyloggers.`,
            evidence: name
          });
        }

        // Macro-enabled document
        if (MACRO_EXTENSIONS.some(ext => name.endsWith(ext))) {
          attachmentRisk += 35;
          indicators.push({
            id: 'macro-attachment',
            category: 'Malicious Attachment',
            severity: 'HIGH',
            title: `Macro-Enabled Document (${name})`,
            explanation: `File '${name}' can execute automated Visual Basic macros that compromise system security upon opening.`,
            evidence: name
          });
        }

        // Double extension disguise (e.g. invoice.pdf.exe)
        if (/\.[a-z0-9]+\.(exe|scr|vbs|bat|js)$/i.test(name)) {
          attachmentRisk += 50;
          indicators.push({
            id: 'double-extension-deception',
            category: 'Malicious Attachment',
            severity: 'CRITICAL',
            title: 'Deceptive Double Extension Detected',
            explanation: `File '${name}' masquerades as a benign file while hiding an executable payload.`,
            evidence: name
          });
        }
      });
    }

    // 5. CALL MACHINE LEARNING MICROSERVICE (FastAPI)
    let mlPrediction = null;
    try {
      mlPrediction = await this.callMlService({
        subject,
        sender: senderEmail,
        body,
        urls
      });
    } catch (err) {
      // ML microservice offline; fallback gracefully to heuristics
      console.log(`[FishGuard] ML service unavailable (${err.message}). Using local rule engine.`);
    }

    // 6. COMPOSITE RISK CALCULATION
    let rawHeuristicScore = (senderRisk * 0.35) + (urlRisk * 0.30) + (contentRisk * 0.25) + (attachmentRisk * 0.35);
    rawHeuristicScore = Math.min(100, Math.round(rawHeuristicScore));

    let finalScore = rawHeuristicScore;
    let mlContribution = null;

    if (mlPrediction && mlPrediction.phishing_probability !== undefined) {
      const mlScore = Math.round(mlPrediction.phishing_probability * 100);
      mlContribution = {
        probability: mlPrediction.phishing_probability,
        confidence: mlPrediction.confidence,
        risk_level: mlPrediction.risk_level,
        status: mlPrediction.status
      };

      // Ensemble blend: 60% ML prediction + 40% Heuristic indicators
      finalScore = Math.round((mlScore * 0.60) + (rawHeuristicScore * 0.40));
    }

    // Cap at 0 - 100
    finalScore = Math.max(0, Math.min(100, finalScore));

    // Determine verdict
    let verdict = 'SAFE';
    let verdictColor = '#10b981'; // green
    if (finalScore >= 70) {
      verdict = 'PHISHING';
      verdictColor = '#ef4444'; // red
    } else if (finalScore >= 35) {
      verdict = 'SUSPICIOUS';
      verdictColor = '#f59e0b'; // amber
    }

    // Generate Tailored Actionable Precautions
    const precautions = this.generatePrecautions(verdict, indicators, urls);

    // Defanged link preview
    const defangedUrls = urls.map(u => this.defangUrl(u));

    return {
      riskScore: finalScore,
      verdict,
      verdictColor,
      confidence: mlContribution ? mlContribution.confidence : 0.88,
      breakdown: {
        senderRisk: Math.min(100, senderRisk),
        urlRisk: Math.min(100, urlRisk),
        contentRisk: Math.min(100, contentRisk),
        attachmentRisk: Math.min(100, attachmentRisk)
      },
      indicators,
      totalIndicators: indicators.length,
      mlEngine: mlContribution,
      precautions,
      defangedUrls,
      analyzedAt: new Date().toISOString()
    };
  }

  /**
   * Generates step-by-step safety precautions based on detected threat vectors
   */
  generatePrecautions(verdict, indicators, urls) {
    const list = [];

    if (verdict === 'PHISHING') {
      list.push('DO NOT click any embedded links or buttons in this email under any circumstances.');
      list.push('DO NOT enter usernames, passwords, credit card numbers, or MFA/OTP codes.');
      list.push('DO NOT open or download any email attachments.');
      list.push('Quarantine this email or mark it as Phishing in your email provider.');
      list.push('If you already clicked a link or entered credentials, change your password immediately on the genuine website and enable Multi-Factor Authentication (MFA).');
    } else if (verdict === 'SUSPICIOUS') {
      list.push('Proceed with caution: sender authenticity or link destinations could not be fully verified.');
      list.push('Verify the sender identity through an alternative, trusted channel (e.g., phone call or official portal).');
      list.push('Inspect URLs carefully before clicking. Hover over links to confirm the destination matches expected domain.');
    } else {
      list.push('Email appears benign based on domain reputation and content signatures.');
      list.push('Always practice basic cyber hygiene: never share passwords via email.');
    }

    return list;
  }

  /**
   * Defang URL for safe rendering without risk of accidental click
   */
  defangUrl(url) {
    return url
      .replace(/^https:\/\//i, 'hxxps://')
      .replace(/^http:\/\//i, 'hxxp://')
      .replace(/\./g, '[.]');
  }

  /**
   * Extract URLs from email text body
   */
  extractUrls(text) {
    if (!text) return [];
    const urlRegex = /https?:\/\/[^\s"'<>()[\]]+/gi;
    const matches = text.match(urlRegex) || [];
    return [...new Set(matches)];
  }

  /**
   * Helper to invoke the Python FastAPI ML microservice via HTTP
   */
  callMlService(payload) {
    return new Promise((resolve, reject) => {
      const data = JSON.stringify(payload);
      const url = new URL('/predict', this.mlServiceUrl);

      const req = http.request({
        hostname: url.hostname,
        port: url.port || 8001,
        path: url.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(data)
        },
        timeout: 2500
      }, (res) => {
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            try {
              resolve(JSON.parse(body));
            } catch (e) {
              reject(e);
            }
          } else {
            reject(new Error(`ML service returned status ${res.statusCode}: ${body}`));
          }
        });
      });

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('ML service request timed out'));
      });

      req.write(data);
      req.end();
    });
  }
}

module.exports = PhishingAnalyzerEngine;
