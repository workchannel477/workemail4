from __future__ import annotations

import argparse
import json
import smtplib
import sys
import socket
import ssl
import time
import logging
from dataclasses import dataclass, field
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid
from getpass import getpass
from pathlib import Path
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse
import socks
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
import schedule
import threading

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

DEFAULT_SMTP_HOST = "smtp.gmail.com"
DEFAULT_SMTP_PORT = 587
DEFAULT_TIMEOUT = 30

@dataclass
class ProxyConfig:
    """Proxy configuration"""
    host: Optional[str] = None
    port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None
    proxy_type: str = "http"  # http, socks4, socks5
    enabled: bool = False
    
    @classmethod
    def from_string(cls, proxy_string: Optional[str]) -> "ProxyConfig":
        """Create proxy config from string (e.g., http://user:pass@host:port)"""
        if not proxy_string:
            return cls(enabled=False)
        
        try:
            parsed = urlparse(proxy_string)
            auth = parsed.netloc.split('@')
            
            if len(auth) == 2:
                user_pass = auth[0].split(':')
                username = user_pass[0] if user_pass[0] else None
                password = user_pass[1] if len(user_pass) > 1 else None
                netloc = auth[1]
            else:
                username = password = None
                netloc = parsed.netloc
            
            host = parsed.hostname
            port = parsed.port
            
            # Default ports based on scheme
            if not port:
                if parsed.scheme.startswith('socks'):
                    port = 1080
                else:
                    port = 8080
            
            proxy_type = parsed.scheme if parsed.scheme else "http"
            
            return cls(
                host=host,
                port=port,
                username=username,
                password=password,
                proxy_type=proxy_type,
                enabled=True
            )
        except Exception as e:
            logger.warning(f"Failed to parse proxy string: {e}")
            return cls(enabled=False)

@dataclass
class EmailPayload:
    username: str
    password: str
    recipients: List[str]
    subject: str
    text_body: str = ""
    html_body: str = ""
    smtp_host: str = DEFAULT_SMTP_HOST
    smtp_port: int = DEFAULT_SMTP_PORT
    use_tls: bool = True
    timeout: int = DEFAULT_TIMEOUT
    proxy: Optional[str] = None
    batch_size: int = 50  # Number of recipients per connection
    delay_between_batches: int = 2  # Seconds between batches
    max_retries: int = 3


class SMTPConnectionPool:
    """Manages SMTP connections with reuse"""
    
    def __init__(self):
        self.connections = {}
        self.lock = threading.Lock()
    
    def get_connection(self, host: str, port: int, username: str, password: str, 
                      proxy_config: Optional[ProxyConfig] = None) -> smtplib.SMTP:
        """Get or create SMTP connection"""
        key = f"{host}:{port}:{username}"
        
        with self.lock:
            if key in self.connections:
                conn = self.connections[key]
                try:
                    # Test if connection is still alive
                    conn.noop()
                    return conn
                except:
                    del self.connections[key]
            
            # Create new connection
            conn = self._create_connection(host, port, proxy_config)
            conn.login(username, password)
            self.connections[key] = conn
            return conn
    
    def _create_connection(self, host: str, port: int, 
                          proxy_config: Optional[ProxyConfig]) -> smtplib.SMTP:
        """Create SMTP connection with optional proxy"""
        if proxy_config and proxy_config.enabled:
            return self._create_proxied_connection(host, port, proxy_config)
        
        # Direct connection
        connection = smtplib.SMTP(host, port, timeout=DEFAULT_TIMEOUT)
        connection.ehlo()
        if port == 587 or port == 465:
            connection.starttls()
            connection.ehlo()
        return connection
    
    def _create_proxied_connection(self, host: str, port: int, 
                                  proxy_config: ProxyConfig) -> smtplib.SMTP:
        """Create SMTP connection through proxy"""
        # Set proxy using PySocks
        if proxy_config.proxy_type == "socks4":
            socks_type = socks.SOCKS4
        elif proxy_config.proxy_type == "socks5":
            socks_type = socks.SOCKS5
        else:
            socks_type = socks.HTTP
        
        # Set up proxy
        socks.set_default_proxy(
            socks_type,
            proxy_config.host,
            proxy_config.port,
            username=proxy_config.username,
            password=proxy_config.password
        )
        socket.socket = socks.socksocket
        
        # Create connection
        connection = smtplib.SMTP(host, port, timeout=DEFAULT_TIMEOUT)
        connection.ehlo()
        if port == 587 or port == 465:
            connection.starttls()
            connection.ehlo()
        
        # Reset to default socket
        socks.set_default_proxy()
        socket.socket = socks._orgsocket
        
        return connection
    
    def cleanup(self):
        """Close all connections"""
        with self.lock:
            for conn in self.connections.values():
                try:
                    conn.quit()
                except:
                    pass
            self.connections.clear()


class EmailSender:
    """Enhanced email sender with IP rotation and rate limiting"""
    
    def __init__(self, connection_pool: Optional[SMTPConnectionPool] = None):
        self.connection_pool = connection_pool or SMTPConnectionPool()
        self.sent_count = 0
        self.failed_count = 0
        self.last_sent_time = 0
        self.rate_limit_delay = 1  # Minimum seconds between emails
    
    def send_with_retry(self, payload: EmailPayload) -> Dict[str, Any]:
        """Send email with retry logic"""
        proxy_config = ProxyConfig.from_string(payload.proxy)
        
        @retry(
            stop=stop_after_attempt(payload.max_retries),
            wait=wait_exponential(multiplier=1, min=4, max=10),
            retry=retry_if_exception_type((smtplib.SMTPException, socket.error, TimeoutError))
        )
        def _send():
            return self._send_single(payload, proxy_config)
        
        try:
            return _send()
        except Exception as e:
            logger.error(f"Failed to send email after {payload.max_retries} attempts: {e}")
            self.failed_count += 1
            return {
                "success": False,
                "error": str(e),
                "recipients": payload.recipients
            }
    
    def _send_single(self, payload: EmailPayload, 
                    proxy_config: ProxyConfig) -> Dict[str, Any]:
        """Send a single email"""
        # Rate limiting
        current_time = time.time()
        if current_time - self.last_sent_time < self.rate_limit_delay:
            sleep_time = self.rate_limit_delay - (current_time - self.last_sent_time)
            time.sleep(sleep_time)
        
        try:
            # Get connection from pool
            connection = self.connection_pool.get_connection(
                payload.smtp_host,
                payload.smtp_port,
                payload.username,
                payload.password,
                proxy_config
            )
            
            # Create message
            message = self._build_message(payload)
            
            # Send to all recipients
            connection.sendmail(
                payload.username,
                payload.recipients,
                message.as_string()
            )
            
            self.sent_count += len(payload.recipients)
            self.last_sent_time = time.time()
            
            logger.info(f"Successfully sent email to {len(payload.recipients)} recipients")
            
            return {
                "success": True,
                "sent_count": len(payload.recipients),
                "recipients": payload.recipients
            }
            
        except smtplib.SMTPException as e:
            logger.error(f"SMTP error: {e}")
            raise
        except socket.error as e:
            logger.error(f"Socket error: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            raise
    
    def send_batch(self, payload: EmailPayload) -> List[Dict[str, Any]]:
        """Send emails in batches to avoid rate limits"""
        results = []
        total_recipients = len(payload.recipients)
        
        for i in range(0, total_recipients, payload.batch_size):
            batch = payload.recipients[i:i + payload.batch_size]
            batch_payload = EmailPayload(
                username=payload.username,
                password=payload.password,
                recipients=batch,
                subject=payload.subject,
                text_body=payload.text_body,
                html_body=payload.html_body,
                smtp_host=payload.smtp_host,
                smtp_port=payload.smtp_port,
                proxy=payload.proxy,
                batch_size=payload.batch_size,
                delay_between_batches=payload.delay_between_batches,
                max_retries=payload.max_retries
            )
            
            result = self.send_with_retry(batch_payload)
            results.append(result)
            
            # Delay between batches
            if i + payload.batch_size < total_recipients:
                time.sleep(payload.delay_between_batches)
        
        return results
    
    def _build_message(self, payload: EmailPayload) -> MIMEMultipart:
        """Build MIME message with proper headers"""
        message = MIMEMultipart("alternative")
        
        # Basic headers
        message["Subject"] = payload.subject
        message["From"] = payload.username
        message["To"] = ", ".join(payload.recipients)
        message["Date"] = formatdate(localtime=True)
        message["Message-ID"] = make_msgid()
        
        # Add text body
        if payload.text_body:
            text_part = MIMEText(payload.text_body, "plain", "utf-8")
            message.attach(text_part)
        
        # Add HTML body
        if payload.html_body:
            html_part = MIMEText(payload.html_body, "html", "utf-8")
            message.attach(html_part)
        
        # If no body provided, create empty text part
        if not payload.text_body and not payload.html_body:
            text_part = MIMEText("", "plain", "utf-8")
            message.attach(text_part)
        
        return message
    
    def get_stats(self) -> Dict[str, Any]:
        """Get sending statistics"""
        return {
            "sent_count": self.sent_count,
            "failed_count": self.failed_count,
            "success_rate": (self.sent_count / (self.sent_count + self.failed_count)) * 100 
                           if (self.sent_count + self.failed_count) > 0 else 0
        }
    
    def cleanup(self):
        """Cleanup resources"""
        self.connection_pool.cleanup()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Enhanced Email Sender with IP Rotation")
    parser.add_argument("--payload", help="Path to a JSON payload file.")
    parser.add_argument("--username", help="SMTP username (usually the email address).")
    parser.add_argument("--password", help="SMTP password or app password.")
    parser.add_argument("--recipients", help="Comma or newline separated recipient list.")
    parser.add_argument("--subject", help="Email subject.")
    parser.add_argument("--text", help="Plain-text body.")
    parser.add_argument("--html", help="HTML body.")
    parser.add_argument("--smtp-host", default=DEFAULT_SMTP_HOST, 
                       help="SMTP host (default: smtp.gmail.com).")
    parser.add_argument("--smtp-port", type=int, default=DEFAULT_SMTP_PORT, 
                       help="SMTP port (default: 587).")
    parser.add_argument("--proxy", help="Proxy string (e.g., http://user:pass@host:port)")
    parser.add_argument("--batch-size", type=int, default=50,
                       help="Number of recipients per batch (default: 50)")
    parser.add_argument("--delay", type=int, default=2,
                       help="Delay between batches in seconds (default: 2)")
    parser.add_argument("--retries", type=int, default=3,
                       help="Maximum retry attempts (default: 3)")
    parser.add_argument("--no-tls", action="store_true",
                       help="Disable TLS (not recommended)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                       help="Connection timeout in seconds (default: 30)")
    parser.add_argument("--log-level", default="INFO",
                       choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                       help="Set logging level")
    return parser.parse_args()


def load_payload_from_file(path: Path) -> EmailPayload:
    """Load email payload from JSON file"""
    if not path.exists():
        raise FileNotFoundError(f"Payload file {path} does not exist")
    
    with path.open("r", encoding="utf-8") as handle:
        raw = json.load(handle)
    
    recipients = normalize_recipients(raw.get("recipients"))
    
    return EmailPayload(
        username=raw.get("username", "").strip(),
        password=raw.get("password", "").strip(),
        recipients=recipients,
        subject=raw.get("subject", "").strip(),
        text_body=raw.get("textBody", raw.get("text", "")),
        html_body=raw.get("htmlBody", raw.get("html", "")),
        smtp_host=raw.get("smtpHost", DEFAULT_SMTP_HOST),
        smtp_port=int(raw.get("smtpPort", DEFAULT_SMTP_PORT)),
        proxy=raw.get("proxy"),
        batch_size=int(raw.get("batchSize", 50)),
        delay_between_batches=int(raw.get("delayBetweenBatches", 2)),
        max_retries=int(raw.get("maxRetries", 3)),
        use_tls=bool(raw.get("useTls", True)),
        timeout=int(raw.get("timeout", DEFAULT_TIMEOUT))
    )


def normalize_recipients(recipients: Optional[object]) -> List[str]:
    """Normalize recipient list from various formats"""
    if recipients is None:
        return []
    
    if isinstance(recipients, str):
        # Handle multiple formats: comma, semicolon, newline separated
        lines = recipients.replace(';', ',').split('\n')
        all_recipients = []
        for line in lines:
            all_recipients.extend([r.strip() for r in line.split(',') if r.strip()])
        return list(set(all_recipients))  # Remove duplicates
    
    if isinstance(recipients, list):
        cleaned = []
        for value in recipients:
            if isinstance(value, str) and value.strip():
                cleaned.append(value.strip())
        return list(set(cleaned))  # Remove duplicates
    
    return []


def build_payload_from_args(args: argparse.Namespace) -> EmailPayload:
    """Build payload from command line arguments"""
    recipients = normalize_recipients(args.recipients)
    
    # Interactive prompts for missing required fields
    if not args.username:
        args.username = input("SMTP username (email): ").strip()
    if not args.password:
        args.password = getpass("SMTP password or app password: ").strip()
    if not recipients:
        prompt = input("Recipients (comma separated): ").strip()
        recipients = normalize_recipients(prompt)
    if not args.subject:
        args.subject = input("Subject: ").strip()
    if not args.text and not args.html:
        args.text = input("Plain-text body (leave blank to skip): ").strip()
        args.html = input("HTML body (leave blank to skip): ").strip()
    
    return EmailPayload(
        username=args.username,
        password=args.password,
        recipients=recipients,
        subject=args.subject,
        text_body=args.text or "",
        html_body=args.html or "",
        smtp_host=args.smtp_host,
        smtp_port=args.smtp_port,
        proxy=args.proxy,
        batch_size=args.batch_size,
        delay_between_batches=args.delay,
        max_retries=args.retries,
        use_tls=not args.no_tls,
        timeout=args.timeout
    )


def main() -> None:
    """Main function with enhanced error handling and logging"""
    args = parse_args()
    
    # Set logging level
    logging.getLogger().setLevel(getattr(logging, args.log_level))
    
    sender = EmailSender()
    
    try:
        if args.payload:
            payload = load_payload_from_file(Path(args.payload))
        else:
            payload = build_payload_from_args(args)
        
        logger.info(f"Starting email send to {len(payload.recipients)} recipients")
        logger.info(f"Using SMTP: {payload.smtp_host}:{payload.smtp_port}")
        if payload.proxy:
            logger.info(f"Using proxy: {payload.proxy}")
        
        # Send emails
        if len(payload.recipients) > payload.batch_size:
            results = sender.send_batch(payload)
        else:
            results = [sender.send_with_retry(payload)]
        
        # Log results
        total_sent = sum(r.get("sent_count", 0) for r in results if r.get("success"))
        total_failed = len(payload.recipients) - total_sent
        
        if total_failed > 0:
            failed_emails = []
            for result in results:
                if not result.get("success"):
                    failed_emails.extend(result.get("recipients", []))
            
            logger.warning(f"Failed to send to {total_failed} recipients: {failed_emails}")
        
        stats = sender.get_stats()
        logger.info(f"Completed: {stats['sent_count']} sent, {stats['failed_count']} failed")
        logger.info(f"Success rate: {stats['success_rate']:.2f}%")
        
        # Output results as JSON for automation
        output = {
            "success": total_failed == 0,
            "stats": stats,
            "total_recipients": len(payload.recipients),
            "sent": total_sent,
            "failed": total_failed,
            "results": results
        }
        
        print(json.dumps(output, indent=2))
        
        if total_failed > 0:
            sys.exit(1)
            
    except KeyboardInterrupt:
        logger.info("Interrupted by user. Cleaning up...")
        sender.cleanup()
        print("Operation cancelled by user.")
        sys.exit(130)
        
    except FileNotFoundError as e:
        logger.error(f"Payload file error: {e}")
        sys.exit(1)
        
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in payload file: {e}")
        sys.exit(1)
        
    except Exception as exc:
        logger.error(f"Failed to send email: {exc}", exc_info=True)
        sys.exit(1)
        
    finally:
        sender.cleanup()


if __name__ == "__main__":
    main()