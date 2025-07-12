"""
Notification system for LogSentinel
Handles email and Slack notifications for suspicious log entries
"""

import smtplib
import json
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Dict, List, Optional
import os


class EmailConfig:
    """Email configuration helper"""
    def __init__(self, config_dict: Dict):
        self.enabled = config_dict.get("enabled", False)
        self.smtp_server = config_dict.get("smtp_server", "")
        self.smtp_port = config_dict.get("smtp_port", 587)
        self.username = config_dict.get("username", "")
        self.password = config_dict.get("password", "")
        self.from_email = config_dict.get("from_email", "")
        self.to_emails = config_dict.get("to_emails", [])
        self.use_tls = config_dict.get("use_tls", True)
    
    def to_dict(self):
        return {
            "enabled": self.enabled,
            "smtp_server": self.smtp_server,
            "smtp_port": self.smtp_port,
            "username": self.username,
            "password": self.password,
            "from_email": self.from_email,
            "to_emails": self.to_emails,
            "use_tls": self.use_tls
        }


class SlackConfig:
    """Slack configuration helper"""
    def __init__(self, config_dict: Dict):
        self.enabled = config_dict.get("enabled", False)
        self.webhook_url = config_dict.get("webhook_url", "")
        self.channel = config_dict.get("channel", "#security-alerts")
        self.username = config_dict.get("username", "LogSentinel")
    
    def to_dict(self):
        return {
            "enabled": self.enabled,
            "webhook_url": self.webhook_url,
            "channel": self.channel,
            "username": self.username
        }


class AlertConfig:
    """Alert settings configuration helper"""
    def __init__(self, config_dict: Dict):
        self.min_severity = config_dict.get("min_severity", "medium")
        self.batch_alerts = config_dict.get("batch_alerts", False)
        self.batch_timeout = config_dict.get("batch_timeout", 300)
        self.max_alerts_per_hour = config_dict.get("max_alerts_per_hour", 50)
    
    def to_dict(self):
        return {
            "min_severity": self.min_severity,
            "batch_alerts": self.batch_alerts,
            "batch_timeout": self.batch_timeout,
            "max_alerts_per_hour": self.max_alerts_per_hour
        }


class NotificationConfig:
    """Configuration class for notification settings"""
    
    def __init__(self, config_file: str = "notification_config.json"):
        self.config_file = config_file
        self.config = self.load_config()
        
        # Create easy access properties
        self.email = EmailConfig(self.config["email"])
        self.slack = SlackConfig(self.config["slack"])
        self.alert_settings = AlertConfig(self.config["alert_settings"])
    
    @classmethod
    def load_from_file(cls, config_file: str):
        """Class method to load configuration from file"""
        return cls(config_file)
    
    def save_to_file(self, config_file: str = None):
        """Save configuration to file"""
        file_path = config_file or self.config_file
        try:
            config_dict = {
                "email": self.email.to_dict(),
                "slack": self.slack.to_dict(), 
                "alert_settings": self.alert_settings.to_dict()
            }
            with open(file_path, 'w') as f:
                json.dump(config_dict, f, indent=4)
            # Also update self.config for backward compatibility
            self.config = config_dict
            return True
        except Exception as e:
            print(f"Error saving config: {e}")
            return False
    
    def load_config(self) -> Dict:
        """Load configuration from JSON file"""
        default_config = {
            "email": {
                "enabled": False,
                "smtp_server": "",
                "smtp_port": 587,
                "username": "",
                "password": "",
                "from_email": "",
                "to_emails": [],
                "use_tls": True
            },
            "slack": {
                "enabled": False,
                "webhook_url": "",
                "channel": "#security-alerts",
                "username": "LogSentinel"
            },
            "alert_settings": {
                "min_severity": "medium",
                "batch_alerts": False,
                "batch_timeout": 300,
                "max_alerts_per_hour": 50
            }
        }
        
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                # Merge with defaults to ensure all keys exist
                for key in default_config:
                    if key not in config:
                        config[key] = default_config[key]
                return config
            except Exception as e:
                print(f"Error loading config: {e}")
                return default_config
        else:
            # Create default config file
            self.save_config(default_config)
            return default_config
    
    def save_config(self, config: Dict = None) -> bool:
        """Save configuration to JSON file"""
        try:
            config_to_save = config or self.config
            with open(self.config_file, 'w') as f:
                json.dump(config_to_save, f, indent=4)
            if config:
                self.config = config
            return True
        except Exception as e:
            print(f"Error saving config: {e}")
            return False
    
    def update_email_config(self, smtp_server: str, smtp_port: int, username: str, 
                           password: str, from_email: str, to_emails: List[str]) -> bool:
        """Update email configuration"""
        self.config["email"].update({
            "smtp_server": smtp_server,
            "smtp_port": smtp_port,
            "username": username,
            "password": password,
            "from_email": from_email,
            "to_emails": to_emails,
            "enabled": True
        })
        return self.save_config()
    
    def update_slack_config(self, webhook_url: str, channel: str = "#security-alerts") -> bool:
        """Update Slack configuration"""
        self.config["slack"].update({
            "webhook_url": webhook_url,
            "channel": channel,
            "enabled": True
        })
        return self.save_config()


class EmailNotifier:
    """Email notification handler"""
    
    def __init__(self, config: NotificationConfig):
        self.config = config
    
    def send_alert(self, log_entry: str, threat_level: str = "medium", 
                   additional_info: Dict = None) -> bool:
        """Send email alert for suspicious activity"""
        if not self.config.email.enabled:
            return False
        
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.config.email.from_email
            msg['To'] = ", ".join(self.config.email.to_emails)
            msg['Subject'] = f"🚨 LogSentinel Security Alert - {threat_level.upper()} Severity"
            
            # Create email body
            body = self._create_email_body(log_entry, threat_level, additional_info)
            msg.attach(MIMEText(body, 'html'))
            
            # Send email
            server = smtplib.SMTP(
                self.config.config["email"]["smtp_server"],
                self.config.config["email"]["smtp_port"]
            )
            
            if self.config.config["email"]["use_tls"]:
                server.starttls()
            
            server.login(
                self.config.config["email"]["username"],
                self.config.config["email"]["password"]
            )
            
            server.send_message(msg)
            server.quit()
            
            print(f"✅ Email alert sent successfully to {len(self.config.config['email']['to_emails'])} recipients")
            return True
            
        except Exception as e:
            print(f"❌ Error sending email alert: {e}")
            return False
    
    def _create_email_body(self, log_entry: str, threat_level: str, 
                          additional_info: Dict = None) -> str:
        """Create HTML email body"""
        severity_colors = {
            "low": "#ffc107",
            "medium": "#fd7e14", 
            "high": "#dc3545",
            "critical": "#6f42c1"
        }
        
        severity_icons = {
            "low": "⚠️",
            "medium": "🔶",
            "high": "🚨",
            "critical": "💀"
        }
        
        color = severity_colors.get(threat_level, "#fd7e14")
        icon = severity_icons.get(threat_level, "🔶")
        
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        html_body = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f8f9fa; }}
                .container {{ max-width: 600px; margin: 0 auto; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; text-align: center; }}
                .content {{ padding: 30px; }}
                .alert-box {{ background: {color}; color: white; padding: 15px; border-radius: 8px; margin: 20px 0; }}
                .log-entry {{ background: #f8f9fa; border-left: 4px solid {color}; padding: 15px; margin: 20px 0; font-family: monospace; word-break: break-all; }}
                .footer {{ background: #f8f9fa; padding: 20px; text-align: center; color: #6c757d; font-size: 12px; }}
                .btn {{ display: inline-block; background: #667eea; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin: 10px 5px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🛡️ LogSentinel Security Alert</h1>
                    <p>Suspicious activity detected in your system logs</p>
                </div>
                
                <div class="content">
                    <div class="alert-box">
                        <h3>{icon} {threat_level.upper()} Severity Alert</h3>
                        <p><strong>Detection Time:</strong> {current_time}</p>
                    </div>
                    
                    <h3>🔍 Log Entry Details:</h3>
                    <div class="log-entry">
                        {log_entry}
                    </div>
                    
                    <h3>📋 Additional Information:</h3>
                    <ul>
                        <li><strong>Threat Level:</strong> {threat_level.title()}</li>
                        <li><strong>Source:</strong> LogSentinel Real-time Monitor</li>
                        <li><strong>Detection Method:</strong> Pattern Matching</li>
        """
        
        if additional_info:
            for key, value in additional_info.items():
                html_body += f'<li><strong>{key.title()}:</strong> {value}</li>'
        
        html_body += """
                    </ul>
                    
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="http://127.0.0.1:5000" class="btn">🔗 View Dashboard</a>
                        <a href="http://127.0.0.1:5000/monitoring/status" class="btn">📊 Monitoring Status</a>
                    </div>
                </div>
                
                <div class="footer">
                    <p>This alert was generated by LogSentinel Security Monitoring System</p>
                    <p>If you believe this is a false positive, please review your detection rules</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html_body
    
    def test_connection(self) -> bool:
        """Test email configuration"""
        if not self.config.config["email"]["enabled"]:
            return False
        
        try:
            server = smtplib.SMTP(
                self.config.config["email"]["smtp_server"],
                self.config.config["email"]["smtp_port"]
            )
            
            if self.config.config["email"]["use_tls"]:
                server.starttls()
            
            server.login(
                self.config.config["email"]["username"],
                self.config.config["email"]["password"]
            )
            
            server.quit()
            return True
            
        except Exception as e:
            print(f"Email connection test failed: {e}")
            return False


class SlackNotifier:
    """Slack notification handler"""
    
    def __init__(self, config: NotificationConfig):
        self.config = config
    
    def send_alert(self, log_entry: str, threat_level: str = "medium", 
                   additional_info: Dict = None) -> bool:
        """Send Slack alert for suspicious activity"""
        if not self.config.config["slack"]["enabled"]:
            return False
        
        try:
            # Create Slack message
            message = self._create_slack_message(log_entry, threat_level, additional_info)
            
            # Send to Slack
            response = requests.post(
                self.config.config["slack"]["webhook_url"],
                json=message,
                timeout=10
            )
            
            if response.status_code == 200:
                print("✅ Slack alert sent successfully")
                return True
            else:
                print(f"❌ Slack alert failed: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Error sending Slack alert: {e}")
            return False
    
    def _create_slack_message(self, log_entry: str, threat_level: str, 
                             additional_info: Dict = None) -> Dict:
        """Create Slack message payload"""
        severity_colors = {
            "low": "#ffc107",
            "medium": "#fd7e14",
            "high": "#dc3545", 
            "critical": "#6f42c1"
        }
        
        severity_emojis = {
            "low": ":warning:",
            "medium": ":large_orange_diamond:",
            "high": ":rotating_light:",
            "critical": ":skull_and_crossbones:"
        }
        
        color = severity_colors.get(threat_level, "#fd7e14")
        emoji = severity_emojis.get(threat_level, ":large_orange_diamond:")
        
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        message = {
            "username": self.config.config["slack"]["username"],
            "channel": self.config.config["slack"]["channel"],
            "text": f"{emoji} *LogSentinel Security Alert* - {threat_level.upper()} Severity",
            "attachments": [
                {
                    "color": color,
                    "fields": [
                        {
                            "title": "🔍 Suspicious Log Entry",
                            "value": f"```{log_entry}```",
                            "short": False
                        },
                        {
                            "title": "⏰ Detection Time", 
                            "value": current_time,
                            "short": True
                        },
                        {
                            "title": "🎯 Threat Level",
                            "value": threat_level.title(),
                            "short": True
                        }
                    ],
                    "actions": [
                        {
                            "type": "button",
                            "text": "🔗 View Dashboard",
                            "url": "http://127.0.0.1:5000"
                        },
                        {
                            "type": "button", 
                            "text": "📊 Monitor Status",
                            "url": "http://127.0.0.1:5000/monitoring/status"
                        }
                    ],
                    "footer": "LogSentinel Security Monitor",
                    "footer_icon": "https://img.icons8.com/color/48/000000/security-checked.png",
                    "ts": int(datetime.now().timestamp())
                }
            ]
        }
        
        if additional_info:
            info_text = "\n".join([f"*{k.title()}:* {v}" for k, v in additional_info.items()])
            message["attachments"][0]["fields"].append({
                "title": "📋 Additional Information",
                "value": info_text,
                "short": False
            })
        
        return message
    
    def test_connection(self) -> bool:
        """Test Slack webhook"""
        if not self.config.config["slack"]["enabled"]:
            return False
        
        try:
            test_message = {
                "text": "🧪 LogSentinel Test Message",
                "username": self.config.config["slack"]["username"],
                "channel": self.config.config["slack"]["channel"]
            }
            
            response = requests.post(
                self.config.config["slack"]["webhook_url"],
                json=test_message,
                timeout=10
            )
            
            return response.status_code == 200
            
        except Exception as e:
            print(f"Slack connection test failed: {e}")
            return False


class NotificationManager:
    """Main notification manager that handles all notification types"""
    
    def __init__(self, config=None):
        if isinstance(config, NotificationConfig):
            self.config = config
        elif isinstance(config, str):
            self.config = NotificationConfig(config)
        else:
            self.config = NotificationConfig()
        
        self.email_notifier = EmailNotifier(self.config)
        self.slack_notifier = SlackNotifier(self.config)
        self.alert_count = 0
        self.last_alert_time = None
    
    def send_alert(self, log_entry: str, threat_level: str = "medium", 
                   additional_info: Dict = None, source: str = "real-time") -> Dict:
        """Send alert through all enabled notification channels"""
        results = {
            "email": False,
            "slack": False,
            "timestamp": datetime.now().isoformat()
        }
        
        # Rate limiting check
        if not self._should_send_alert():
            print("⏳ Alert rate limit reached, skipping notification")
            return results
        
        # Enhance additional info
        if additional_info is None:
            additional_info = {}
        
        additional_info.update({
            "source": source,
            "alert_id": f"LS-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{self.alert_count:03d}"
        })
        
        # Send email notification
        if self.config.email.enabled:
            results["email"] = self.email_notifier.send_alert(
                log_entry, threat_level, additional_info
            )
        
        # Send Slack notification  
        if self.config.slack.enabled:
            results["slack"] = self.slack_notifier.send_alert(
                log_entry, threat_level, additional_info
            )
        
        # Update counters
        self.alert_count += 1
        self.last_alert_time = datetime.now()
        
        return results
    
    def _should_send_alert(self) -> bool:
        """Check if we should send alert based on rate limiting"""
        max_alerts = self.config.alert_settings.max_alerts_per_hour
        
        # Simple rate limiting - reset counter every hour
        if self.last_alert_time:
            time_diff = (datetime.now() - self.last_alert_time).total_seconds()
            if time_diff > 3600:  # Reset after 1 hour
                self.alert_count = 0
        
        return self.alert_count < max_alerts
    
    def test_all_connections(self) -> Dict:
        """Test all notification channels"""
        return {
            "email": self.email_notifier.test_connection(),
            "slack": self.slack_notifier.test_connection()
        }
    
    def get_config(self) -> Dict:
        """Get current configuration"""
        return self.config.config
    
    def update_config(self, new_config: Dict) -> bool:
        """Update configuration"""
        return self.config.save_config(new_config)
    
    def send_security_alert(self, log_entry: str, threat_level: str = "medium", 
                           additional_info: Dict = None) -> Dict:
        """Convenience method for sending security alerts"""
        return self.send_alert(log_entry, threat_level, additional_info)
    
    def send_test_email(self) -> bool:
        """Send a test email"""
        return self.email_notifier.test_connection()
    
    def send_test_slack(self) -> bool:
        """Send a test Slack message"""
        return self.slack_notifier.test_connection()


# Global notification manager instance
_notification_manager = None

def get_notification_manager() -> NotificationManager:
    """Get the global notification manager instance"""
    global _notification_manager
    if _notification_manager is None:
        _notification_manager = NotificationManager()
    return _notification_manager

def send_security_alert(log_entry: str, threat_level: str = "medium", 
                       additional_info: Dict = None) -> Dict:
    """Convenience function to send security alert"""
    manager = get_notification_manager()
    return manager.send_alert(log_entry, threat_level, additional_info)

if __name__ == "__main__":
    # Test the notification system
    manager = NotificationManager()
    
    # Test alert
    test_log = "Jun 18 01:22:13 myhost sshd[1993]: Failed password for invalid user admin from 192.168.0.101 port 53742 ssh2"
    
    print("🧪 Testing notification system...")
    results = manager.send_alert(
        test_log, 
        "high", 
        {"ip_address": "192.168.0.101", "attack_type": "Brute Force"}
    )
    
    print(f"📧 Email sent: {results['email']}")
    print(f"💬 Slack sent: {results['slack']}")
