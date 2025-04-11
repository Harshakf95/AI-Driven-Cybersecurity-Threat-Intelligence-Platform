import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
from typing import Dict, List

class NotificationService:
    def __init__(self):
        # Email configuration
        self.smtp_host = os.getenv('SMTP_HOST', 'smtp.gmail.com')
        self.smtp_port = int(os.getenv('SMTP_PORT', 587))
        self.smtp_username = os.getenv('SMTP_USERNAME')
        self.smtp_password = os.getenv('SMTP_PASSWORD')
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            filename='notification_service.log'
        )
        self.logger = logging.getLogger(__name__)

    def send_email_alert(self, 
                          recipient: str, 
                          subject: str, 
                          threat_details: Dict) -> bool:
        """
        Send email alert for detected threats
        """
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.smtp_username
            msg['To'] = recipient
            msg['Subject'] = subject

            # Construct email body
            body = f"""
            Threat Alert Detected:
            
            Severity: {threat_details.get('severity', 'Unknown')}
            Type: {threat_details.get('type', 'Unknown')}
            Hash: {threat_details.get('hash', 'N/A')}
            Timestamp: {threat_details.get('timestamp', 'N/A')}
            
            Additional Details:
            {threat_details.get('description', 'No additional information')}
            """
            
            msg.attach(MIMEText(body, 'plain'))

            # Send email
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_username, self.smtp_password)
                server.send_message(msg)
            
            self.logger.info(f"Email alert sent to {recipient}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to send email alert: {e}")
            return False

    def send_sms_alert(self, phone_number: str, message: str) -> bool:
        """
        Send SMS alert using a third-party SMS service
        Placeholder for future implementation
        """
        try:
            # TODO: Integrate with SMS gateway (Twilio, etc.)
            self.logger.info(f"SMS alert attempted to {phone_number}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to send SMS alert: {e}")
            return False

    def log_threat(self, threat_details: Dict) -> None:
        """
        Log threat details to a log file
        """
        log_message = (
            f"THREAT DETECTED: "
            f"Severity={threat_details.get('severity', 'Unknown')} "
            f"Type={threat_details.get('type', 'Unknown')} "
            f"Hash={threat_details.get('hash', 'N/A')}"
        )
        self.logger.warning(log_message)

    def notify_multiple(self, 
                        threats: List[Dict], 
                        notification_methods: List[str] = ['email', 'log']) -> None:
        """
        Notify through multiple channels for a list of threats
        """
        for threat in threats:
            if 'email' in notification_methods:
                self.send_email_alert(
                    recipient=os.getenv('ADMIN_EMAIL', 'admin@example.com'),
                    subject=f"Threat Alert: {threat.get('type', 'Unknown')}",
                    threat_details=threat
                )
            
            if 'log' in notification_methods:
                self.log_threat(threat)
            
            if 'sms' in notification_methods:
                self.send_sms_alert(
                    phone_number=os.getenv('ADMIN_PHONE', '+1234567890'),
                    message=f"Threat Detected: {threat.get('type', 'Unknown')}"
                )

def main():
    # Example usage
    notification_service = NotificationService()
    
    sample_threat = {
        'severity': 'high',
        'type': 'Malware',
        'hash': 'abc123',
        'timestamp': '2025-04-10T12:00:00',
        'description': 'Potential ransomware detected'
    }
    
    notification_service.notify_multiple([sample_threat])

if __name__ == '__main__':
    main()