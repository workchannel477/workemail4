"""
Email utility functions
"""

import re
import dns.resolver
import socket
import time
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

logger = logging.getLogger(__name__)

class EmailValidator:
    """Email validation and verification utilities"""
    
    EMAIL_REGEX = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    @staticmethod
    def is_valid_format(email: str) -> bool:
        """Check if email format is valid"""
        return bool(re.match(EmailValidator.EMAIL_REGEX, email))
    
    @staticmethod
    def verify_domain(email: str) -> bool:
        """Verify email domain has MX records"""
        try:
            domain = email.split('@')[1]
            mx_records = dns.resolver.resolve(domain, 'MX')
            return len(mx_records) > 0
        except:
            return False
    
    @staticmethod
    def validate_emails(emails: List[str]) -> Dict[str, Any]:
        """Validate list of emails"""
        valid = []
        invalid = []
        
        for email in emails:
            if EmailValidator.is_valid_format(email) and EmailValidator.verify_domain(email):
                valid.append(email)
            else:
                invalid.append(email)
        
        return {
            "valid": valid,
            "invalid": invalid,
            "valid_count": len(valid),
            "invalid_count": len(invalid)
        }


class EmailTemplate:
    """Email template management"""
    
    def __init__(self):
        self.templates = {}
    
    def load_template(self, name: str, subject: str, text_body: str = "", 
                     html_body: str = "") -> None:
        """Load an email template"""
        self.templates[name] = {
            "subject": subject,
            "text_body": text_body,
            "html_body": html_body
        }
    
    def render_template(self, name: str, variables: Dict[str, str]) -> Dict[str, str]:
        """Render template with variables"""
        if name not in self.templates:
            raise ValueError(f"Template '{name}' not found")
        
        template = self.templates[name]
        rendered = {}
        
        for key, value in template.items():
            if value:
                for var_name, var_value in variables.items():
                    placeholder = f"{{{var_name}}}"
                    value = value.replace(placeholder, str(var_value))
                rendered[key] = value
        
        return rendered


class RateLimiter:
    """Rate limiting for email sending"""
    
    def __init__(self, max_per_minute: int = 30):
        self.max_per_minute = max_per_minute
        self.sent_times = []
        self.lock = threading.Lock()
    
    def can_send(self) -> bool:
        """Check if sending is allowed under rate limit"""
        with self.lock:
            now = time.time()
            # Remove timestamps older than 1 minute
            self.sent_times = [t for t in self.sent_times if now - t < 60]
            
            if len(self.sent_times) >= self.max_per_minute:
                return False
            
            self.sent_times.append(now)
            return True
    
    def wait_if_needed(self) -> None:
        """Wait if rate limit is reached"""
        while not self.can_send():
            time.sleep(1)


def chunk_list(lst: List[Any], chunk_size: int) -> List[List[Any]]:
    """Split list into chunks"""
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]


def create_email_report(results: List[Dict[str, Any]]) -> str:
    """Create human-readable email sending report"""
    total_sent = sum(r.get("sent_count", 0) for r in results if r.get("success"))
    total_failed = sum(1 for r in results if not r.get("success"))
    
    report = [
        "=" * 50,
        "EMAIL SENDING REPORT",
        "=" * 50,
        f"Total batches: {len(results)}",
        f"Successfully sent: {total_sent} emails",
        f"Failed batches: {total_failed}",
        ""
    ]
    
    for i, result in enumerate(results, 1):
        if result.get("success"):
            report.append(f"Batch {i}: ✓ Success - {result.get('sent_count', 0)} emails")
        else:
            report.append(f"Batch {i}: ✗ Failed - {result.get('error', 'Unknown error')}")
    
    report.append("=" * 50)
    return "\n".join(report)