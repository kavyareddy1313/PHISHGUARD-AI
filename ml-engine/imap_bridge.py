"""
FishGuard AI - Native IMAP Bridge & RFC 822 Email Parser
Connects directly to real Gmail, Outlook, Yahoo, or Custom IMAP servers via SSL/TLS.
Fetches, decodes, and parses real incoming emails for real-time AI security inspection.
"""

import imaplib
import email
from email.header import decode_header
import re
import ssl
from typing import List, Dict, Any, Optional

def clean_header(header_val: Optional[str]) -> str:
    """Decodes MIME encoded-word syntax (RFC 2047) into readable unicode."""
    if not header_val:
        return ""
    try:
        decoded_parts = decode_header(header_val)
        result = []
        for part, encoding in decoded_parts:
            if isinstance(part, bytes):
                encoding = encoding or 'utf-8'
                try:
                    result.append(part.decode(encoding, errors='replace'))
                except Exception:
                    result.append(part.decode('latin-1', errors='replace'))
            else:
                result.append(str(part))
        return "".join(result).strip()
    except Exception:
        return str(header_val)

def extract_urls_from_text(text: str) -> List[str]:
    """Extracts all HTTP/HTTPS links from email body text."""
    if not text:
        return []
    url_pattern = r'https?://[^\s"\'<>()[\]]+'
    found = re.findall(url_pattern, text)
    # Deduplicate while preserving order
    return list(dict.fromkeys(found))

def parse_mime_message(msg: email.message.Message, msg_id: str = "") -> Dict[str, Any]:
    """Parses a Python email.message.Message object into a structured threat payload."""
    subject = clean_header(msg.get("Subject", "(No Subject)"))
    sender = clean_header(msg.get("From", "Unknown Sender"))
    to_addr = clean_header(msg.get("To", ""))
    date_str = clean_header(msg.get("Date", ""))
    auth_results = clean_header(msg.get("Authentication-Results", ""))
    
    # Extract plain text body and HTML
    body_text = ""
    body_html = ""
    attachments = []
    
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))
            filename = part.get_filename()
            
            # Check for attachments
            if "attachment" in content_disposition or filename:
                fname = clean_header(filename or "unnamed_attachment")
                payload = part.get_payload(decode=True)
                size_kb = f"{round(len(payload) / 1024, 1)} KB" if payload else "0 KB"
                attachments.append({
                    "name": fname,
                    "size": size_kb,
                    "contentType": content_type
                })
                continue
                
            # Extract textual parts
            if content_type == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        body_text += payload.decode(charset, errors="replace") + "\n"
                    except Exception:
                        body_text += payload.decode("latin-1", errors="replace") + "\n"
            elif content_type == "text/html":
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        body_html += payload.decode(charset, errors="replace")
                    except Exception:
                        body_html += payload.decode("latin-1", errors="replace")
    else:
        # Non-multipart message
        content_type = msg.get_content_type()
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            try:
                text_content = payload.decode(charset, errors="replace")
            except Exception:
                text_content = payload.decode("latin-1", errors="replace")
                
            if content_type == "text/html":
                body_html = text_content
            else:
                body_text = text_content

    # If body_text is empty but HTML exists, strip simple tags for text analysis
    if not body_text.strip() and body_html:
        # Simple HTML tag stripper
        stripped = re.sub(r'<script[^>]*>.*?</script>', '', body_html, flags=re.DOTALL)
        stripped = re.sub(r'<style[^>]*>.*?</style>', '', stripped, flags=re.DOTALL)
        stripped = re.sub(r'<[^>]+>', ' ', stripped)
        body_text = re.sub(r'\s+', ' ', stripped).strip()

    # Extract all embedded URLs
    combined_for_urls = f"{body_text} {body_html}"
    urls = extract_urls_from_text(combined_for_urls)

    return {
        "id": msg_id or f"real-em-{abs(hash(subject + sender + date_str)) % 1000000}",
        "sender": sender,
        "senderName": sender.split("<")[0].replace('"', '').strip() if "<" in sender else sender,
        "recipient": to_addr,
        "subject": subject,
        "body": body_text.strip(),
        "urls": urls,
        "attachments": attachments,
        "receivedAt": date_str,
        "rawAuthResults": auth_results,
        "isRealEmail": True
    }

class ImapClient:
    """Manages real-time connections to user email inboxes."""

    def __init__(self, host: str, port: int, username: str, password: str, use_ssl: bool = True):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.use_ssl = use_ssl

    def connect(self) -> imaplib.IMAP4:
        """Establishes SSL or TLS connection to the IMAP server."""
        if self.use_ssl:
            ssl_context = ssl.create_default_context()
            client = imaplib.IMAP4_SSL(self.host, self.port, ssl_context=ssl_context)
        else:
            client = imaplib.IMAP4(self.host, self.port)

        client.login(self.username, self.password)
        return client

    def test_connection(self) -> Dict[str, Any]:
        """Validates connection and credentials."""
        try:
            client = self.connect()
            status, folders = client.list()
            client.select("INBOX", readonly=True)
            status, total_count = client.search(None, "ALL")
            total_msgs = len(total_count[0].split()) if total_count and total_count[0] else 0
            client.logout()
            return {
                "success": True,
                "message": f"Successfully connected to {self.host}! Total emails in INBOX: {total_msgs}",
                "inboxCount": total_msgs
            }
        except imaplib.IMAP4.error as e:
            err_msg = str(e)
            if "AUTHENTICATIONFAILED" in err_msg or "Invalid credentials" in err_msg:
                return {
                    "success": False,
                    "error": "Authentication failed. For Gmail, ensure you are using a 16-character Google App Password (myaccount.google.com/apppasswords), NOT your normal password."
                }
            return {"success": False, "error": f"IMAP error: {err_msg}"}
        except Exception as e:
            return {"success": False, "error": f"Connection error: {str(e)}"}

    def fetch_recent_emails(self, folder: str = "INBOX", limit: int = 10) -> List[Dict[str, Any]]:
        """Fetches the latest N real emails from the selected folder."""
        client = None
        try:
            client = self.connect()
            client.select(folder, readonly=True)
            
            # Fetch message IDs
            status, data = client.search(None, "ALL")
            if status != "OK" or not data or not data[0]:
                return []
                
            msg_ids = data[0].split()
            # Get latest 'limit' messages (reverse order)
            recent_ids = msg_ids[-limit:] if len(msg_ids) > limit else msg_ids
            recent_ids.reverse() # Newest first
            
            parsed_emails = []
            for mid in recent_ids:
                status, msg_data = client.fetch(mid, "(RFC822)")
                if status == "OK" and msg_data and msg_data[0]:
                    raw_email_bytes = msg_data[0][1]
                    email_obj = email.message_from_bytes(raw_email_bytes)
                    parsed = parse_mime_message(email_obj, msg_id=f"real-{mid.decode()}")
                    parsed_emails.append(parsed)
                    
            return parsed_emails
        finally:
            if client:
                try:
                    client.close()
                    client.logout()
                except Exception:
                    pass
