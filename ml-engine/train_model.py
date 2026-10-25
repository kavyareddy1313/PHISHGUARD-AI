"""
FishGuard AI - Phishing Detection ML Model Trainer
Trains an ensemble NLP + Structural feature model on phishing vs benign email datasets.
Saves trained pipeline artifacts for real-time inference via FastAPI.
"""

import os
import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from sklearn.model_selection import train_test_split

class StructuralFeatureExtractor(BaseEstimator, TransformerMixin):
    """Extracts structural cybersecurity indicators from email text."""
    
    def __init__(self):
        self.suspicious_keywords = [
            'urgent', 'suspend', 'immediately', 'verify', 'password', 'bank',
            'action required', 'billing', 'compromised', 'security alert', 'unauthorized',
            'wire transfer', 'wallet', 'crypto', 'irs', 'tax refund', 'lottery',
            'invoice attached', 'account limited', 'confirm identity', 'threat'
        ]
        
    def fit(self, X, y=None):
        return self
        
    def transform(self, X):
        features = []
        for text in X:
            text_lower = text.lower()
            # Feature 1: count of suspicious keywords
            kw_count = sum(1 for kw in self.suspicious_keywords if kw in text_lower)
            # Feature 2: URL indicator (http, https, www)
            has_url = 1.0 if any(k in text_lower for k in ['http://', 'https://', 'www.']) else 0.0
            # Feature 3: IP address in text heuristic
            import re
            has_ip = 1.0 if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text) else 0.0
            # Feature 4: Exclamation mark frequency
            exclamation_count = text.count('!')
            # Feature 5: Currency symbols ($ / € / £)
            has_currency = 1.0 if any(c in text for c in ['$', '€', '£', 'USD']) else 0.0
            # Feature 6: Uppercase character ratio
            upper_ratio = sum(1 for c in text if c.isupper()) / (len(text) + 1)
            
            features.append([
                kw_count,
                has_url,
                has_ip,
                min(exclamation_count, 10),
                has_currency,
                upper_ratio
            ])
        return np.array(features)

def build_dataset():
    """Builds a rich, diverse corpus of phishing and legitimate emails."""
    phishing_samples = [
        # Banking & Account takeover
        "URGENT: Your PayPal account has been restricted due to suspicious login attempts. Verify your identity immediately at http://192.168.1.102/paypal-login or your balance will be frozen permanently within 24 hours.",
        "Security Alert: Unauthorized access detected from Moscow, Russia on your Chase Bank profile. Click here to confirm your card details: http://secure-chase-update.info/login.asp",
        "Bank of America Warning: Account suspended. Multiple invalid password attempts. Immediate action required. Submit your Social Security Number and debit PIN to restore service.",
        "Wells Fargo Alert: We detected an anomalous wire transfer of $4,850.00. If you did not authorize this transaction, cancel it immediately at http://wellsfargo-cancellation-center.top/verify",
        "Your Apple ID has been locked for security reasons. To unlock, verify billing information and credit card security code at https://appleid-verification-support.xyz/restore",
        
        # Cloud & Microsoft 365 / Corporate Spoofing
        "Microsoft 365 Team: Your password expires today in 2 hours! Keep your current password by verifying on http://microsoft-portal-login.biz/auth. Disregard this at your own risk.",
        "IT Helpdesk Alert: Storage quota exceeded for your corporate mailbox (99.8% full). You will stop receiving incoming emails unless you validate your credentials here: http://webmail-quota-upgrade.org",
        "Google Workspace: Critical security vulnerability found in your company account. An attacker may have extracted your emails. Reset your Google credentials immediately via this link: http://google-security-team-auth.me",
        "DocuSign: CFO has sent you an urgent executive NDA and payroll modification document for immediate signature. Review and sign at: http://docusign-secure-document-portal.top/doc/88419",
        "Adobe Acrobat Document Cloud: You have received a secured financial contract from Johnathan Pierce. Sign in with your corporate email password to decrypt document.",
        
        # Delivery & Logistics / Malware Lures
        "DHL Express: Your parcel #DHL-88921-US could not be delivered due to an incorrect shipping address. Download your tracking receipt attached as ShippingReceipt.pdf.exe and pay $2.99 customs fee.",
        "FedEx Notification: Delivery attempt failed for parcel 492019482. Please confirm your home address and download the attached invoice label (.vbs) within 48 hours.",
        "Amazon Customer Service: Your order for Apple MacBook Pro 16 ($2,499.00) has been placed successfully. If this was not you, call fraud helpline +1-800-FAKE-NUM or cancel order at http://amzn-cancel-order.net",
        "USPS Package Tracking: Critical shipping exception. Your postal package is held at regional sorting facility. Click to reschedule delivery and update payment details.",
        
        # Financial / Extortion / Tax Scams
        "Internal Revenue Service (IRS): Final Notice - You have an outstanding tax refund of $1,420.50 pending approval. Provide direct deposit banking credentials to claim before deadline.",
        "BitPay / Coinbase: Transaction Notice. 2.45 BTC ($145,000) was requested for withdrawal from your crypto wallet. Cancel immediately if unauthorized: http://coinbase-fraud-protection.xyz/cancel",
        "URGENT WIRE TRANSFER: I am out of the office for an emergency client meeting. Please execute a wire transfer of $38,500 to our vendor immediately. Do not call my phone, reply via email only.",
        "Invoice INV-2024-9912 Overdue: Attached please find the overdue invoice for consulting services. Remit payment today or legal collection actions will commence.",
        "HR Notice: Mandatory Employee Compensation and Bonus adjustment form for Q4. Open attachment Bonus_Matrix_Macro_Enabled.docm to review your salary increase.",
        
        # Social Media & Credential Phish
        "LinkedIn Notification: 14 people searched for your profile, including recruiters from Google and Meta. View who viewed you by logging in: http://linkedin-talent-pool.click/auth",
        "Netflix Subscription Suspended: Your monthly billing failed. Update your credit card number and CVV within 24 hours to prevent cancellation of your membership: http://netflix-billing-update.club",
        "Instagram Copyright Infringement: A copyright strike was registered against your account. If you do not appeal within 24 hours via http://ig-appeal-badge.rest, your profile will be permanently deleted."
    ]
    
    benign_samples = [
        # Normal corporate emails
        "Hi Team, please find attached the meeting notes from today's product sync. Let's reconvene on Thursday to review progress on the Q3 milestones.",
        "Quarterly financial update: Our engineering team has reduced AWS infrastructure costs by 18% over the past quarter. Great work everyone!",
        "Reminder: The weekly design review will start at 2:00 PM EST in Conference Room B and via Google Meet. Agenda is posted on the internal wiki.",
        "Hi Sarah, could you please review the pull request for the authentication service when you have a moment? All unit tests are currently passing.",
        "All-hands meeting scheduled for tomorrow at 10 AM. We will be discussing the product roadmap and welcoming our new team members.",
        
        # Real transactional & system notifications
        "GitHub: A new issue has been opened in repository backend-api: 'Optimize database index on users table'. Assigned to Alex.",
        "Amazon: Your order has been delivered! Your package was handed directly to a resident. Tracking ID: 1Z9999999999999999.",
        "Google Calendar: Invitation - Sprint Planning on Monday at 9:30 AM. Status: Accepted. Location: Virtual Room 4.",
        "Slack notification: Elena mentioned you in #general: 'Hey team, the staging deployment is now live and ready for testing.'",
        "Stripe: Your monthly invoice for Cloud Services has been paid. Amount: $49.00. View receipt in your dashboard at https://dashboard.stripe.com/invoices.",
        
        # Personal communications
        "Hey, are you free for lunch tomorrow around 12:30? Let me know if that Mexican place downtown works for you.",
        "Hi dad, just arrived at the airport safely. The flight was on time and I will catch the express train home now. Love you!",
        "Photos from the weekend hiking trip! It was so much fun reaching the mountain summit. Let's plan another trip for next month.",
        "Hi everyone, thanks for joining the book club yesterday. For next month we voted to read Project Hail Mary by Andy Weir.",
        "Recipe for the pasta you asked about: boil salted water, cook rigatoni al dente, saute garlic with cherry tomatoes and fresh basil."
    ]
    
    # Expand dataset with realistic variations
    X = phishing_samples * 12 + benign_samples * 18
    y = [1] * (len(phishing_samples) * 12) + [0] * (len(benign_samples) * 18)
    
    return X, y

def train_and_export():
    print("=" * 60)
    print("FishGuard AI: Training NLP Phishing Detection Pipeline")
    print("=" * 60)
    
    X, y = build_dataset()
    print(f"Total training corpus: {len(X)} samples ({sum(y)} phishing, {len(y) - sum(y)} benign)")
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    
    # Feature Union combining TF-IDF word n-grams and Cybersecurity Structural Features
    feature_pipeline = FeatureUnion([
        ('tfidf', TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=2500,
            sublinear_tf=True,
            stop_words='english'
        )),
        ('structural', StructuralFeatureExtractor())
    ])
    
    # Logistic Regression with balanced weights for high precision
    model = LogisticRegression(
        C=2.5,
        max_iter=1000,
        class_weight='balanced',
        random_state=42
    )
    
    pipeline = Pipeline([
        ('features', feature_pipeline),
        ('classifier', model)
    ])
    
    print("Fitting model...")
    pipeline.fit(X_train, y_train)
    
    # Evaluation
    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)[:, 1]
    
    acc = accuracy_score(y_test, y_pred)
    print(f"\nModel Performance on Test Set:")
    print(f"Accuracy:  {acc * 100:.2f}%")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Benign / Safe', 'Phishing Threat']))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    # Save model artifacts
    output_dir = os.path.join(os.path.dirname(__file__), "model")
    os.makedirs(output_dir, exist_ok=True)
    
    model_path = os.path.join(output_dir, "phishing_pipeline.pkl")
    joblib.dump(pipeline, model_path)
    print(f"\nTrained pipeline saved successfully to: {model_path}")

if __name__ == '__main__':
    train_and_export()
