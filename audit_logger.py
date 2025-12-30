"""Security audit logging for the LLM Guardrail Proxy."""
import os
from datetime import datetime
from typing import Optional
from config import settings


class AuditLogger:
    """Handles security audit logging to file."""
    
    def __init__(self, log_file_path: Optional[str] = None):
        """Initialize the audit logger.
        
        Args:
            log_file_path: Path to the log file. Defaults to settings.log_file_path.
        """
        self.log_file_path = log_file_path or settings.log_file_path
        self._ensure_log_file()
    
    def _ensure_log_file(self):
        """Ensure the log file exists."""
        if not os.path.exists(self.log_file_path):
            # Create the file with header
            with open(self.log_file_path, 'w') as f:
                f.write("Timestamp | IP Address | Attack Type | Payload | Status\n")
                f.write("-" * 100 + "\n")
    
    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        return datetime.now().isoformat()
    
    def log_security_event(
        self,
        ip_address: str,
        attack_type: str,
        payload: str,
        status: str,
    ):
        """Log a security event.
        
        Args:
            ip_address: Client IP address
            attack_type: Type of attack detected (e.g., "PII_DETECTED", "INJECTION_DETECTED", "SAFE_REQUEST")
            payload: The user input that triggered the event
            status: Status of the request (e.g., "BLOCKED", "ALLOWED")
        """
        timestamp = self._get_timestamp()
        
        # Truncate payload if too long (for readability)
        truncated_payload = payload[:200] + "..." if len(payload) > 200 else payload
        
        # Escape newlines in payload for single-line log format
        sanitized_payload = truncated_payload.replace("\n", "\\n").replace("\r", "\\r")
        
        log_entry = f"{timestamp} | {ip_address} | {attack_type} | {sanitized_payload} | {status}\n"
        
        with open(self.log_file_path, 'a') as f:
            f.write(log_entry)
    
    def log_pii_detection(self, ip_address: str, payload: str):
        """Log a PII detection event."""
        self.log_security_event(
            ip_address=ip_address,
            attack_type="PII_DETECTED",
            payload=payload,
            status="BLOCKED"
        )
    
    def log_injection_detection(self, ip_address: str, payload: str):
        """Log a prompt injection detection event."""
        self.log_security_event(
            ip_address=ip_address,
            attack_type="INJECTION_DETECTED",
            payload=payload,
            status="BLOCKED"
        )
    
    def log_safe_request(self, ip_address: str, payload: str):
        """Log a safe request that was allowed."""
        self.log_security_event(
            ip_address=ip_address,
            attack_type="SAFE_REQUEST",
            payload=payload,
            status="ALLOWED"
        )


# Global logger instance
audit_logger = AuditLogger()

