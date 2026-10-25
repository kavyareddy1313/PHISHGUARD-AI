# 🛡️ FishGuard AI - Enterprise Phishing Detection & Prevention System

> **Next-Generation Cyber Threat Defense System Powered by Machine Learning, Heuristic NLP, and Real-Time SOC Telemetry.**

---

## 📌 Executive Summary

Every day, individuals and corporate employees receive thousands of emails across Gmail, Outlook, and corporate inboxes. Attackers utilize sophisticated techniques—**subtle domain typosquatting, deceptive sender display names, credential-harvesting links, urgent extortion, and disguised executable attachments**—to breach accounts, steal sensitive credentials, and deploy ransomware.

**FishGuard AI** is an industry-grade, end-to-end cybersecurity solution that monitors incoming emails, decomposes threat signals across four distinct vectors in real-time, outputs an explainable **Risk Score (0–100)**, and automatically neutralizes/quarantines malicious payloads before users fall victim.

---

## 🏗️ System Architecture

```
                       ┌──────────────────────────────────────────────┐
                       │          User Personal Inbox / IMAP          │
                       │    (Gmail / Outlook / Corporate Exchange)    │
                       └──────────────────────┬───────────────────────┘
                                              │ (Polling / Webhook)
                                              ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                 FISHGUARD BACKEND API                                  │
│                                 (Node.js / Express / Socket.IO)                        │
│                                                                                        │
│  ┌───────────────────────┐   ┌────────────────────────┐   ┌─────────────────────────┐  │
│  │ Domain & Spoof Engine │   │   URL Deep Inspector   │   │ Content & NLP Heuristics│  │
│  │ • Typosquatting / IDN │   │ • IP Hostname Check    │   │ • Coercive Urgency      │  │
│  │ • Homoglyphs          │   │ • Anchor Mismatch      │   │ • Credential Extraction │  │
│  │ • Suspicious TLDs     │   │ • Path Threat Entropy  │   │ • Financial Panic       │  │
│  └───────────┬───────────┘   └───────────┬────────────┘   └────────────┬────────────┘  │
│              │                           │                             │               │
│              └───────────────────────────┼─────────────────────────────┘               │
│                                          │                                             │
│                                          ▼                                             │
│                           ┌───────────────────────────────┐                            │
│                           │   Python ML Inference Engine  │                            │
│                           │   (FastAPI / Scikit-Learn)    │                            │
│                           │   • TF-IDF Vectorization      │                            │
│                           │   • Structural Indicators     │                            │
│                           └──────────────┬────────────────┘                            │
│                                          │                                             │
│                                          ▼                                             │
│                           ┌───────────────────────────────┐                            │
│                           │  Composite Risk Scoring & XAI │                            │
│                           │  (0 - 100 Risk Score)         │                            │
│                           └──────────────┬────────────────┘                            │
└──────────────────────────────────────────┼─────────────────────────────────────────────┘
                                           │ WebSocket Real-Time Stream & REST
                                           ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              FISHGUARD SOC DASHBOARD                                   │
│                            (React 18 / Vite / Lucide)                                  │
│                                                                                        │
│  • Live Email Threat Feed           • Explainable AI (XAI) Diagnostic Breakdown        │
│  • Circular Risk Gauges             • Automated Link Defanging (hxxp://)               │
│  • Automated Quarantine Isolation   • Sandbox Analyzer & Incident JSON Exporter        │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## ⚡ Core Detection Vectors

### 1. 🌐 Domain & Sender Spoofing Detection
- **Brand Impersonation**: Compares display names claiming to be trusted entities (PayPal, Microsoft, Google, Apple, Amazon, Chase, Wells Fargo, etc.) against the authenticated sender domain.
- **Typosquatting & Levenshtein Analysis**: Detects lookalike domains (e.g. `paypa1.com`, `micros0ft.com`, `g00gle.com`).
- **Homoglyph & Punycode (IDN) Attacks**: Flags foreign Unicode substitutions masquerading as Latin characters.
- **Risky TLD Screening**: Flags high-risk Top-Level Domains (`.xyz`, `.top`, `.icu`, `.buzz`, `.club`, `.work`, `.click`, `.rest`, `.country`).
- **Free Webmail Discrepancy**: Alerts when official banking/corporate communication originates from public free accounts (`@gmail.com`, `@yahoo.com`).

### 2. 🔗 Hyperlink & URL Deep Inspection
- **Direct IP Hostnames**: Identifies URLs containing raw IP addresses (`http://192.168.1.105/login`), common in credential harvesters.
- **Anchor Text Mismatch**: Detects when visible link text (e.g. `https://accounts.google.com`) routes to an unrelated malicious domain.
- **Credential Harvesting Paths**: Inspects URL paths for `/login`, `/verify`, `/account-restore`, `/banking`, `/wallet`.
- **URL Shortener Masking**: Detects `bit.ly`, `tinyurl.com`, `t.co` used to mask destination targets.
- **Automated Defanging**: Converts dangerous URLs into neutralized formats (`hxxps://target[.]xyz`) to prevent accidental clicks.

### 3. 🧠 Content & NLP Threat Heuristics
- **Coercive Urgency**: Identifies artificial panic words ("within 24 hours", "immediate action required", "account permanently suspended").
- **Intimidation & Extortion**: Detects legal threats, unauthorized breach claims, and arrest notices.
- **Credential Solicitation**: Flags attempts to harvest passwords, PINs, SSNs, credit card details, or crypto seed phrases.
- **Generic Salutations**: Identifies impersonal greetings ("Dear Valued Customer") typical of mass phishing campaigns.

### 4. 📎 Malicious Attachment Risk Evaluation
- **High-Hazard Executables**: Automatically flags `.exe`, `.scr`, `.bat`, `.cmd`, `.vbs`, `.js`, `.iso`, `.hta`.
- **Macro-Enabled Documents**: Detects `.docm`, `.xlsm`, `.pptm` capable of running malicious VBA scripts.
- **Double Extension Deception**: Unmasks disguised files such as `Invoice_2026.pdf.exe`.

---

## 🧮 Composite Risk Scoring & Explainable AI (XAI)

| Score Range | Threat Classification | Action Taken |
| :--- | :--- | :--- |
| **0 – 34** | 🟢 **SAFE / BENIGN** | Authenticated sender; no malicious links; normal business language. |
| **35 – 69** | 🟡 **SUSPICIOUS / WARNING** | Potential domain discrepancy or aggressive tone; cautious verification advised. |
| **70 – 100** | 🔴 **CRITICAL PHISHING** | Auto-quarantined; links neutralized; warning banner displayed. |

---

## 🚀 Quickstart Guide

### Option 1: One-Command Local Startup (Native)
Run all 3 services (ML Engine, Backend, and Frontend) simultaneously:

```bash
cd FishGuard-AI
./start.sh
```

- **Frontend Dashboard:** [http://localhost:3000](http://localhost:3000)
- **Backend API:** [http://localhost:5001/api/emails](http://localhost:5001/api/emails)
- **ML Engine Health:** [http://localhost:8001/health](http://localhost:8001/health)

---

### Option 2: Docker Compose (Full Stack Containerized)
Orchestrates Python ML Engine, Node.js Backend, React Nginx Frontend, and PostgreSQL Database:

```bash
cd FishGuard-AI
docker-compose up --build
```

---

## ☸️ Production Kubernetes Deployment

Deploy into any standard Kubernetes cluster (Minikube, EKS, GKE, AKS):

```bash
# 1. Apply namespace and secrets
kubectl apply -f k8s/00-namespace.yaml
kubectl apply -f k8s/01-configmap-secrets.yaml

# 2. Deploy PostgreSQL database
kubectl apply -f k8s/02-postgres.yaml

# 3. Deploy ML Microservice
kubectl apply -f k8s/03-ml-engine.yaml

# 4. Deploy Node.js Backend API
kubectl apply -f k8s/04-backend.yaml

# 5. Deploy Frontend and Ingress
kubectl apply -f k8s/05-frontend.yaml
kubectl apply -f k8s/06-ingress.yaml

# 6. Apply Autoscalers (HPA)
kubectl apply -f k8s/07-hpa.yaml
```

Verify running pods:
```bash
kubectl get pods -n fishguard
```

---

## 🔄 GitHub Actions CI/CD Pipeline

The `.github/workflows/ci-cd.yml` workflow enforces production release standards:
1. **Linting & Model Validation**: Executes Python training and scikit-learn pipeline verification.
2. **Backend & Frontend Tests**: Validates Node.js analyzer engine and compiles the React production bundle.
3. **Cybersecurity Vulnerability Audit**: Runs **Trivy** vulnerability scanner for dependencies and CVEs.
4. **Docker Multi-Arch Build & GHCR Push**: Builds and pushes Docker images to GitHub Container Registry.
5. **Kubeconform Validation**: Lints and verifies all Kubernetes YAML manifests against standard schemas.

---

## 📡 REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/emails` | List all scanned emails with search & verdict filter |
| `GET` | `/api/emails/:id` | Fetch full email report with Explainable AI indicators |
| `POST` | `/api/emails/analyze` | Real-time sandbox analysis of custom subject & body |
| `POST` | `/api/emails/simulate-incoming` | Simulate incoming phishing attack with live WebSocket push |
| `POST` | `/api/emails/:id/quarantine` | Toggle isolation vault status for an email |
| `POST` | `/api/emails/:id/defang` | Neutralize embedded links in email body |
| `GET` | `/api/analytics` | Retrieve SOC telemetry metrics and threat categories |
| `POST` | `/api/scanner/url` | Dedicated deep hyperlink threat inspector |
| `POST` | `/api/settings/email-sync` | Configure personal IMAP/Gmail credentials & auto-quarantine |

---

## 🛡️ License
Enterprise Cybersecurity License. Designed for Security Operations Centers (SOC) and personal email protection.
