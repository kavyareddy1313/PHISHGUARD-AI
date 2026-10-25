/**
 * Curated benchmark dataset of real-world phishing attacks and benign corporate communications
 */

module.exports = [
  {
    id: 'em-101',
    sender: 'security-alert@paypal-verification-center.top',
    senderName: 'PayPal Security Department',
    recipient: 'user@personal-inbox.com',
    subject: 'URGENT: Your PayPal Account Has Been Suspended - Verify Identity Immediately',
    body: `Dear Valued Customer,\n\nWe recently detected multiple unauthorized login attempts to your PayPal account from an unrecognized IP address in Bucharest, Romania. For your security, your account privileges, card transactions, and balance transfers have been suspended temporarily.\n\nImmediate action is required within 24 hours to prevent permanent account closure. Please verify your identity and confirm your debit card and Social Security Number at our secured portal below:\n\nhttp://192.168.1.105/paypal-auth/verify\n\nIf you do not confirm within 24 hours, all existing funds will be forfeited.\n\nSincerely,\nPayPal Fraud Prevention Team`,
    urls: ['http://192.168.1.105/paypal-auth/verify'],
    attachments: [],
    receivedAt: new Date(Date.now() - 1000 * 60 * 15).toISOString(),
    isRead: false,
    isQuarantined: true
  },
  {
    id: 'em-102',
    sender: 'tracking-update@dhl-express-logistics.xyz',
    senderName: 'DHL International Express',
    recipient: 'user@personal-inbox.com',
    subject: 'Delivery Failed: Parcel #DHL-994821 requires customs payment receipt',
    body: `Hello Customer,\n\nYour courier shipment #DHL-994821 is currently held at our central sorting facility due to unpaid import duty fees ($2.50 USD).\n\nPlease download your official clearance receipt attached as ShippingReceipt_DHL.pdf.exe and complete the payment verification before 5:00 PM today, otherwise the package will be returned to the origin sender.\n\nTrack parcel live at: http://dhl-express-tracking-portal.club/auth\n\nDHL Worldwide Courier Services`,
    urls: ['http://dhl-express-tracking-portal.club/auth'],
    attachments: [
      { name: 'ShippingReceipt_DHL.pdf.exe', size: '248 KB', type: 'application/octet-stream' }
    ],
    receivedAt: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
    isRead: false,
    isQuarantined: true
  },
  {
    id: 'em-103',
    sender: 'it-support@microsoft365-password-portal.biz',
    senderName: 'Microsoft 365 Admin Center',
    recipient: 'user@personal-inbox.com',
    subject: 'CRITICAL ALERT: Your Microsoft 365 password expires in 2 hours',
    body: `Notice to All Users,\n\nYour corporate Microsoft 365 Office account password is scheduled to expire in 2 hours. Failure to update will result in termination of Outlook web access and SharePoint document access.\n\nTo retain your current password and avoid disruption, click below to validate your credentials:\n\nhttp://login-microsoft365-verify.info/auth/login.html\n\nOffice 365 Security Team`,
    urls: ['http://login-microsoft365-verify.info/auth/login.html'],
    attachments: [],
    receivedAt: new Date(Date.now() - 1000 * 60 * 90).toISOString(),
    isRead: true,
    isQuarantined: false
  },
  {
    id: 'em-104',
    sender: 'notifications@github.com',
    senderName: 'GitHub Notifications',
    recipient: 'user@personal-inbox.com',
    subject: '[GitHub] Pull request #42 merged into main: "Add high-speed caching for API responses"',
    body: `Hi developer,\n\nYour pull request #42 ("Add high-speed caching for API responses") has been successfully reviewed and merged by maintainer alex-cloud.\n\nAll CI checks passed (14/14 tests passing). You can view the full commit log and deployment status at https://github.com/organization/repo/pull/42.\n\nBest regards,\nThe GitHub Team`,
    urls: ['https://github.com/organization/repo/pull/42'],
    attachments: [],
    receivedAt: new Date(Date.now() - 1000 * 60 * 180).toISOString(),
    isRead: true,
    isQuarantined: false
  },
  {
    id: 'em-105',
    sender: 'billing@aws.amazon.com',
    senderName: 'Amazon Web Services',
    recipient: 'user@personal-inbox.com',
    subject: 'Amazon Web Services Invoice #AWS-2026-9901 Available',
    body: `Dear AWS Customer,\n\nYour monthly billing statement for AWS services covering account 9821-4412-0092 is now available. Your payment of $34.20 USD was processed successfully via your card on file ending in 4012.\n\nYou can review your detailed usage breakdown in the AWS Billing and Cost Management console at https://aws.amazon.com/console.\n\nThank you for choosing Amazon Web Services.`,
    urls: ['https://aws.amazon.com/console'],
    attachments: [
      { name: 'AWS_Invoice_Sept2026.pdf', size: '112 KB', type: 'application/pdf' }
    ],
    receivedAt: new Date(Date.now() - 1000 * 60 * 320).toISOString(),
    isRead: true,
    isQuarantined: false
  },
  {
    id: 'em-106',
    sender: 'refund-dept@irs-tax-gov-portal.rest',
    senderName: 'Internal Revenue Service (IRS)',
    recipient: 'user@personal-inbox.com',
    subject: 'Tax Refund Notification: Unclaimed rebate balance of $1,420.50 pending',
    body: `Attention Taxpayer,\n\nOur automated audit revealed an unclaimed federal tax refund of $1,420.50 for fiscal year 2025. Due to strict IRS regulations, direct deposits must be claimed within 48 hours.\n\nTo initiate the wire transfer to your personal bank account, please submit your direct deposit details, full name, SSN, and date of birth at: http://irs-tax-refund-wire.rest/claim\n\nDepartment of the Treasury\nInternal Revenue Service`,
    urls: ['http://irs-tax-refund-wire.rest/claim'],
    attachments: [],
    receivedAt: new Date(Date.now() - 1000 * 60 * 450).toISOString(),
    isRead: false,
    isQuarantined: true
  }
];
