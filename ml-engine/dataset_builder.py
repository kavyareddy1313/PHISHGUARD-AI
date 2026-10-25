"""
FishGuard AI - Large-Scale Cyber Phishing Corpus Generator
Builds a multi-thousand sample training and evaluation corpus of real-world phishing
threats and legitimate communications with realistic headers, lexical signals, and metadata.
"""

import os
import json
import random

def generate_corpus(total_samples=2400):
    phishing_templates = [
        # 1. Banking & Account Takeover
        {
            "category": "Banking Phish",
            "senders": [
                "alert@chase-security-update.xyz", "support@wellsfargo-verify.top",
                "fraud-prevention@bofa-portal.club", "security@citi-alert-wire.info",
                "service@paypal-account-center.rest", "billing@barclays-auth.work"
            ],
            "subjects": [
                "URGENT: Unauthorized wire transfer of ${amt} initiated from your profile",
                "SECURITY ALERT: Your online banking access is restricted immediately",
                "Final Notice: Verify debit card and PIN within 24 hours to avoid suspension",
                "Suspicious login detected from {city}, {country}. Confirm identity",
                "Important notice regarding your checking account balance hold"
            ],
            "bodies": [
                "Dear Customer,\n\nWe recorded multiple unsuccessful login attempts to your bank account from an unauthorized device located in {city}, {country}. For your protection, your ability to make wire transfers and debit payments has been suspended.\n\nTo restore full account functionality, verify your debit card number, expiration date, and ATM PIN at our secure banking center:\n\n{url}\n\nFailure to verify within 24 hours will result in permanent account termination and forfeiture of funds.\n\nFraud Department",
                "Attention Account Holder,\n\nA pending wire transfer in the amount of ${amt} was requested on your profile. If you did not authorize this transaction, click below immediately to cancel the charge and secure your funds:\n\n{url}\n\nSecurity Operations Center"
            ],
            "urls": ["http://{ip}/banking/login.php", "http://secure-{brand}-login.xyz/auth", "http://update-account-{brand}.top/verify"],
            "has_attachment": False
        },
        # 2. Microsoft 365 & Google Workspace Credential Harvesting
        {
            "category": "Cloud Credential Harvest",
            "senders": [
                "admin@microsoft365-pass-recovery.info", "it-support@workspace-google-auth.xyz",
                "helpdesk@company-internal-webmail.biz", "no-reply@sharepoint-docu-sign.top"
            ],
            "subjects": [
                "CRITICAL: Your Microsoft 365 password expires in {hours} hours",
                "IT Helpdesk: Mailbox storage quota exceeded ({pct}% full)",
                "Action Required: Re-authenticate your Google Workspace credentials",
                "Office 365: 7 unread incoming messages have been quarantined"
            ],
            "bodies": [
                "To All Employees,\n\nYour corporate email password will expire in {hours} hours. If you wish to keep your current password and maintain active access to Outlook Web App and OneDrive, you must confirm your credentials on our active directory gateway:\n\n{url}\n\nAny accounts not verified before 6:00 PM today will be disabled by system administrators.\n\nIT Support Services",
                "Mailbox Storage Warning:\n\nYour email account has reached {pct}% of its maximum allotted storage capacity. You will be unable to send or receive emails until you upgrade your mailbox quota.\n\nClick here to validate your corporate account credentials and increase quota: {url}\n\nInternal IT Infrastructure Team"
            ],
            "urls": ["http://{ip}/owa/auth.html", "http://login.microsoft-security-gateway.biz/token", "http://webmail-storage-update.org/login"],
            "has_attachment": False
        },
        # 3. Delivery / Courier Malware Droppers
        {
            "category": "Malware Dropper",
            "senders": [
                "tracking@dhl-express-logistics.xyz", "delivery-notice@fedex-shipment.top",
                "notification@usps-postal-tracking.club", "parcel@ups-shipping-exception.info"
            ],
            "subjects": [
                "DHL Delivery Exception: Parcel #DHL-{num} held at sorting facility",
                "FedEx Alert: Unable to deliver parcel due to incorrect recipient address",
                "USPS Tracking: Customs import fee of $2.75 required for release",
                "UPS Courier: Delivery attempt failed for shipment {num}"
            ],
            "bodies": [
                "Dear Recipient,\n\nYour international package #DHL-{num} could not be delivered to the registered address. A minor customs handling clearance fee of $2.75 remains unpaid.\n\nPlease open the attached shipping document ShippingReceipt_{num}.pdf.exe and complete the delivery confirmation form.\n\nAlternatively, confirm your address at: {url}\n\nCustomer Support Team",
                "Notice of Delivery Failure:\n\nOur courier driver attempted delivery of package {num} but no signature was available. Please print the attached delivery dispatch note Delivery_Label_Invoice.vbs to collect your package at the nearest depot."
            ],
            "urls": ["http://{brand}-parcel-tracking.xyz/auth", "http://{ip}/shipping/tracking.php"],
            "has_attachment": True,
            "attachments": ["ShippingReceipt_{num}.pdf.exe", "Delivery_Label_Invoice.vbs", "Customs_Declaration.docm"]
        },
        # 4. BEC & Executive Impersonation / CEO Fraud
        {
            "category": "CEO Fraud / BEC",
            "senders": [
                "ceo.executive.urgent@gmail.com", "chief.executive@company-corp-management.xyz",
                "board.directors@private-csuite.top"
            ],
            "subjects": [
                "URGENT REQUEST - Are you at your desk right now?",
                "Confidential: Wire Transfer payment required for acquisition",
                "Quick favor needed before board meeting - reply promptly",
                "Executive compensation matrix approval - immediate"
            ],
            "bodies": [
                "Hi,\n\nI am currently in an all-day confidential acquisition meeting and cannot take voice calls. We have an overdue invoice from our strategic legal consultant that must be settled today.\n\nPlease execute an international wire transfer of $48,250.00 immediately to the attached account coordinates. Do not call my cell phone as I am speaking on stage. Send confirmation receipt once done.\n\nRegards,\nChief Executive Officer",
                "Are you at your desk?\n\nI need you to purchase 15 Apple Store gift cards ($100 each) for client appreciation incentives. Scratch the backs and email me photos of the codes right away. I will reimburse you by tomorrow morning.\n\nSent from my iPhone"
            ],
            "urls": [],
            "has_attachment": False
        },
        # 5. Crypto & Financial Extortion
        {
            "category": "Extortion & Crypto",
            "senders": [
                "security@coinbase-wallet-protect.xyz", "alert@binance-withdrawal-auth.top",
                "support@metamask-seed-verification.club"
            ],
            "subjects": [
                "URGENT: 2.85 BTC withdrawal initiated from your account",
                "MetaMask Security: Your decentralized vault will be deactivated",
                "Coinbase: Compromised wallet detected. Move funds to safety"
            ],
            "bodies": [
                "Security Notice:\n\nA withdrawal of 2.85 BTC ($168,200 USD) was initiated to external address 1BoatSLRHtKNngkd59EU79bt5j86bcksb5. If this was not authorized by you, cancel the transaction immediately by verifying your 12-word recovery seed phrase at: {url}\n\nCoinbase Fraud Team",
                "Your crypto wallet has not completed the mandatory KYC compliance upgrade. Failure to confirm your private key at {url} within 12 hours will permanently lock your digital assets."
            ],
            "urls": ["http://coinbase-fraud-cancel.xyz/verify", "http://{ip}/metamask-restore/index.html"],
            "has_attachment": False
        }
    ]

    benign_templates = [
        # 1. Engineering & Developer Workflows
        {
            "category": "Dev Notification",
            "senders": [
                "notifications@github.com", "updates@gitlab.com",
                "jira-notifications@atlassian.net", "builds@circleci.com"
            ],
            "subjects": [
                "[GitHub] Pull Request #{num} approved: 'Add distributed caching layer'",
                "[GitLab] Pipeline passed for branch feature/auth-v2 in 3m 42s",
                "Jira: Issue PROJ-{num} moved to 'In Review' by Alex",
                "AWS CloudWatch Alarm: CPU utilization returned to normal state"
            ],
            "bodies": [
                "Hi developer,\n\nPull request #{num} has been reviewed by your teammates and all 28 automated integration tests have passed. You are free to merge this branch into main at https://github.com/company/repo/pull/{num}.\n\nBest regards,\nThe GitHub Team",
                "Hello,\n\nThe continuous integration pipeline #CI-{num} has successfully built the Docker images and executed all unit tests with 94.2% test coverage. Staging environment has been deployed."
            ],
            "urls": ["https://github.com/company/repo/pull/{num}", "https://atlassian.net/browse/PROJ-{num}"],
            "has_attachment": False
        },
        # 2. Corporate Internal Communications
        {
            "category": "Internal Corporate",
            "senders": [
                "hr@company.com", "calendar-notification@google.com",
                "all-hands@company.com", "facilities@company.com"
            ],
            "subjects": [
                "Invitation: Weekly Product Design Sync on Thursday at 2:00 PM",
                "All-Hands Meeting Agenda & Guest Speaker Announcement",
                "Holiday Schedule: Office closure dates for upcoming Thanksgiving week",
                "Reminder: Annual health and wellness benefits enrollment window"
            ],
            "bodies": [
                "Hi Team,\n\nPlease find attached the agenda for our upcoming sprint retrospective. We will discuss velocity improvements and review user feedback from the latest release.\n\nMeeting link: https://meet.google.com/abc-defg-hij\n\nThanks,\nProduct Operations",
                "Dear Colleagues,\n\nOur quarterly all-hands meeting will take place tomorrow at 10:00 AM EST in Auditorium A and streamed via Google Meet. Please review the attached slide deck prior to the session."
            ],
            "urls": ["https://meet.google.com/abc-defg-hij", "https://intranet.company.com/events"],
            "has_attachment": False
        },
        # 3. Legitimate Transactional Receipts & Bills
        {
            "category": "Legitimate Receipts",
            "senders": [
                "billing@aws.amazon.com", "invoices@stripe.com",
                "receipts@uber.com", "order-update@amazon.com"
            ],
            "subjects": [
                "Your Amazon.com order #{num} has shipped",
                "Stripe Receipt: Payment of $49.00 for SaaS Subscription",
                "Your trip with Uber on Saturday morning - Receipt",
                "AWS Monthly Invoice #AWS-2026-{num} is ready"
            ],
            "bodies": [
                "Hello,\n\nThank you for shopping with us. Your item has shipped via UPS and is estimated to arrive on Wednesday. You can track your shipment directly in your account dashboard at https://www.amazon.com/orders.\n\nAmazon Customer Service",
                "Your monthly receipt for Cloud Services is attached as a PDF. Payment was automatically charged to your Visa ending in 4242. View invoice online at https://dashboard.stripe.com/receipts."
            ],
            "urls": ["https://www.amazon.com/orders", "https://dashboard.stripe.com/receipts"],
            "has_attachment": True,
            "attachments": ["Invoice_Sept2026.pdf", "Uber_Trip_Receipt.pdf"]
        },
        # 4. Personal & Casual Conversations
        {
            "category": "Personal Messages",
            "senders": [
                "sarah.miller@gmail.com", "david.tech@outlook.com",
                "family.updates@yahoo.com", "alumni.board@university.edu"
            ],
            "subjects": [
                "Weekend brunch plans - what time works for you?",
                "Photos from our hiking trip in the national park",
                "Book recommendations: finished reading Hail Mary!",
                "Catching up next week over coffee"
            ],
            "bodies": [
                "Hey! Hope your week is going well. We were thinking of trying that new Italian bistro downtown on Saturday around 1:00 PM. Let me know if you can make it!",
                "Hi everyone, here are the photos from our camping weekend. It was great seeing everyone. Looking forward to our next trip!"
            ],
            "urls": [],
            "has_attachment": False
        }
    ]

    cities = ["New York", "Bucharest", "Moscow", "Lagos", "London", "São Paulo", "Shenzhen", "Berlin"]
    countries = ["United States", "Romania", "Russia", "Nigeria", "United Kingdom", "Brazil", "China", "Germany"]
    brands = ["paypal", "chase", "microsoft", "google", "apple", "wellsfargo", "dhl", "fedex"]

    records = []
    
    # Half phishing, half benign
    target_each = total_samples // 2
    
    # Generate Phishing samples
    for i in range(target_each):
        tmpl = random.choice(phishing_templates)
        sender = random.choice(tmpl["senders"])
        subject_t = random.choice(tmpl["subjects"])
        body_t = random.choice(tmpl["bodies"])
        
        num = random.randint(10000, 99999)
        amt = f"{random.randint(450, 8900):,}.{random.randint(10, 99)}"
        hours = random.choice([2, 4, 12, 24])
        pct = random.randint(96, 99)
        city = random.choice(cities)
        country = random.choice(countries)
        brand = random.choice(brands)
        ip = f"{random.randint(11, 210)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        
        url = ""
        if tmpl["urls"]:
            url = random.choice(tmpl["urls"]).format(ip=ip, brand=brand, num=num)
            
        subject = subject_t.format(amt=amt, city=city, country=country, hours=hours, pct=pct, num=num)
        body = body_t.format(amt=amt, city=city, country=country, hours=hours, pct=pct, num=num, url=url)
        
        att = []
        if tmpl.get("has_attachment") and "attachments" in tmpl:
            att = [random.choice(tmpl["attachments"]).format(num=num)]
            
        records.append({
            "id": f"phish-{i:05d}",
            "sender": sender,
            "subject": subject,
            "body": body,
            "urls": [url] if url else [],
            "attachments": att,
            "category": tmpl["category"],
            "label": 1 # Phishing
        })

    # Generate Benign samples
    for i in range(target_each):
        tmpl = random.choice(benign_templates)
        sender = random.choice(tmpl["senders"])
        subject_t = random.choice(tmpl["subjects"])
        body_t = random.choice(tmpl["bodies"])
        
        num = random.randint(100, 9999)
        url = ""
        if tmpl["urls"]:
            url = random.choice(tmpl["urls"]).format(num=num)
            
        subject = subject_t.format(num=num)
        body = body_t.format(num=num, url=url)
        
        att = []
        if tmpl.get("has_attachment") and "attachments" in tmpl:
            att = [random.choice(tmpl["attachments"])]
            
        records.append({
            "id": f"benign-{i:05d}",
            "sender": sender,
            "subject": subject,
            "body": body,
            "urls": [url] if url else [],
            "attachments": att,
            "category": tmpl["category"],
            "label": 0 # Benign
        })

    random.shuffle(records)
    
    out_path = os.path.join(os.path.dirname(__file__), "dataset", "cyber_phishing_corpus.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)
        
    print(f"Generated {len(records)} realistic cybersecurity training samples into: {out_path}")
    return records

if __name__ == '__main__':
    generate_corpus(2500)
