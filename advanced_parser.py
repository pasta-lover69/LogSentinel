"""
Enhanced Security Parser with Advanced Pattern Matching
Focuses on sophisticated malicious login detection and attack patterns
"""

import re
import time
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Set, Tuple
from collections import defaultdict, deque
from dataclasses import dataclass
from regex_engine import (
    AdvancedPatternMatcher, SecurityPattern, ThreatLevel, 
    PatternCategory, RegexTimeoutError, MaliciousPatternError
)

@dataclass
class LoginAttempt:
    """Represents a login attempt for analysis"""
    timestamp: datetime
    username: str
    ip_address: str
    success: bool
    service: str
    user_agent: Optional[str] = None
    source_port: Optional[int] = None

@dataclass
class ThreatIndicator:
    """Represents a detected threat with context"""
    threat_type: str
    severity: ThreatLevel
    description: str
    evidence: List[str]
    affected_assets: List[str]
    attack_timeline: List[datetime]
    confidence_score: float
    mitigation_advice: str

class BehavioralAnalyzer:
    """
    Analyzes patterns of behavior to detect sophisticated attacks
    """
    
    def __init__(self, time_window_minutes: int = 60):
        self.time_window = timedelta(minutes=time_window_minutes)
        self.login_attempts: deque = deque()
        self.failed_attempts_by_ip: defaultdict = defaultdict(list)
        self.failed_attempts_by_user: defaultdict = defaultdict(list)
        self.successful_logins: defaultdict = defaultdict(list)
        self.suspicious_ips: Set[str] = set()
        
    def add_login_attempt(self, attempt: LoginAttempt):
        """Add login attempt for behavioral analysis"""
        self.login_attempts.append(attempt)
        
        # Clean old attempts outside time window
        cutoff_time = attempt.timestamp - self.time_window
        while self.login_attempts and self.login_attempts[0].timestamp < cutoff_time:
            old_attempt = self.login_attempts.popleft()
            self._remove_from_tracking(old_attempt)
        
        # Track by IP and user
        if not attempt.success:
            self.failed_attempts_by_ip[attempt.ip_address].append(attempt)
            self.failed_attempts_by_user[attempt.username].append(attempt)
        else:
            self.successful_logins[attempt.ip_address].append(attempt)
    
    def _remove_from_tracking(self, attempt: LoginAttempt):
        """Remove old attempt from tracking dictionaries"""
        if attempt.ip_address in self.failed_attempts_by_ip:
            self.failed_attempts_by_ip[attempt.ip_address] = [
                a for a in self.failed_attempts_by_ip[attempt.ip_address] 
                if a.timestamp >= attempt.timestamp - self.time_window
            ]
        
        if attempt.username in self.failed_attempts_by_user:
            self.failed_attempts_by_user[attempt.username] = [
                a for a in self.failed_attempts_by_user[attempt.username]
                if a.timestamp >= attempt.timestamp - self.time_window
            ]
    
    def detect_brute_force(self, threshold: int = 5) -> List[ThreatIndicator]:
        """Detect brute force attacks"""
        threats = []
        
        for ip, attempts in self.failed_attempts_by_ip.items():
            if len(attempts) >= threshold:
                unique_users = set(a.username for a in attempts)
                timeline = [a.timestamp for a in attempts]
                
                # Calculate attack velocity
                time_span = (max(timeline) - min(timeline)).total_seconds()
                velocity = len(attempts) / max(time_span, 1)
                
                confidence = min(0.9, 0.3 + (len(attempts) / 20) + (velocity / 10))
                
                threat = ThreatIndicator(
                    threat_type="Brute Force Attack",
                    severity=ThreatLevel.HIGH if len(attempts) > 10 else ThreatLevel.MEDIUM,
                    description=f"Brute force attack from {ip}: {len(attempts)} failed attempts on {len(unique_users)} accounts",
                    evidence=[f"Failed login: {a.username}@{a.timestamp}" for a in attempts[-5:]],
                    affected_assets=[ip] + list(unique_users),
                    attack_timeline=timeline,
                    confidence_score=confidence,
                    mitigation_advice=f"Block IP {ip}, review accounts: {', '.join(unique_users)}"
                )
                threats.append(threat)
                self.suspicious_ips.add(ip)
        
        return threats
    
    def detect_credential_stuffing(self) -> List[ThreatIndicator]:
        """Detect credential stuffing attacks"""
        threats = []
        
        for ip, attempts in self.failed_attempts_by_ip.items():
            if len(attempts) >= 3:
                unique_users = set(a.username for a in attempts)
                user_ratio = len(unique_users) / len(attempts)
                
                # High user variety suggests credential stuffing
                if user_ratio > 0.7 and len(unique_users) >= 5:
                    timeline = [a.timestamp for a in attempts]
                    confidence = min(0.85, 0.4 + user_ratio * 0.4 + (len(unique_users) / 50))
                    
                    threat = ThreatIndicator(
                        threat_type="Credential Stuffing",
                        severity=ThreatLevel.HIGH,
                        description=f"Credential stuffing from {ip}: {len(attempts)} attempts on {len(unique_users)} different accounts",
                        evidence=[f"Account targeted: {user}" for user in list(unique_users)[:10]],
                        affected_assets=[ip] + list(unique_users),
                        attack_timeline=timeline,
                        confidence_score=confidence,
                        mitigation_advice=f"Block IP {ip}, implement rate limiting, check for compromised credentials"
                    )
                    threats.append(threat)
        
        return threats
    
    def detect_account_enumeration(self) -> List[ThreatIndicator]:
        """Detect account enumeration attempts"""
        threats = []
        
        for ip, attempts in self.failed_attempts_by_ip.items():
            if len(attempts) >= 10:
                usernames = [a.username for a in attempts]
                
                # Look for systematic username patterns
                sequential_patterns = self._detect_sequential_usernames(usernames)
                dictionary_patterns = self._detect_dictionary_usernames(usernames)
                
                if sequential_patterns or dictionary_patterns:
                    confidence = 0.6 + (len(sequential_patterns) * 0.1) + (len(dictionary_patterns) * 0.1)
                    
                    threat = ThreatIndicator(
                        threat_type="Account Enumeration",
                        severity=ThreatLevel.MEDIUM,
                        description=f"Account enumeration from {ip}: systematic username testing detected",
                        evidence=sequential_patterns + dictionary_patterns,
                        affected_assets=[ip],
                        attack_timeline=[a.timestamp for a in attempts],
                        confidence_score=min(confidence, 0.9),
                        mitigation_advice=f"Block IP {ip}, implement CAPTCHA, monitor for valid account discovery"
                    )
                    threats.append(threat)
        
        return threats
    
    def _detect_sequential_usernames(self, usernames: List[str]) -> List[str]:
        """Detect sequential username patterns"""
        patterns = []
        
        # Check for numbered sequences (user1, user2, user3)
        numbered_base = {}
        for username in usernames:
            match = re.match(r'([a-zA-Z]+)(\d+)$', username)
            if match:
                base, num = match.groups()
                if base not in numbered_base:
                    numbered_base[base] = []
                numbered_base[base].append(int(num))
        
        for base, numbers in numbered_base.items():
            if len(numbers) >= 3:
                numbers.sort()
                consecutive_count = 1
                for i in range(1, len(numbers)):
                    if numbers[i] == numbers[i-1] + 1:
                        consecutive_count += 1
                    else:
                        consecutive_count = 1
                    
                    if consecutive_count >= 3:
                        patterns.append(f"Sequential usernames: {base}[{numbers[i-2]}-{numbers[i]}]")
                        break
        
        return patterns
    
    def _detect_dictionary_usernames(self, usernames: List[str]) -> List[str]:
        """Detect dictionary-based username patterns"""
        patterns = []
        
        # Common username patterns
        common_prefixes = ['admin', 'user', 'test', 'guest', 'root', 'service']
        admin_keywords = ['admin', 'administrator', 'root', 'superuser', 'sa']
        
        for prefix in common_prefixes:
            prefix_count = sum(1 for u in usernames if u.lower().startswith(prefix))
            if prefix_count >= 3:
                patterns.append(f"Dictionary pattern: {prefix_count} usernames with '{prefix}' prefix")
        
        for keyword in admin_keywords:
            keyword_count = sum(1 for u in usernames if keyword in u.lower())
            if keyword_count >= 2:
                patterns.append(f"Admin account targeting: {keyword_count} attempts on '{keyword}' accounts")
        
        return patterns

class AdvancedSecurityParser:
    """
    Enhanced security parser with advanced pattern matching and behavioral analysis
    """
    
    def __init__(self):
        self.pattern_matcher = AdvancedPatternMatcher()
        self.behavioral_analyzer = BehavioralAnalyzer()
        self.detection_stats = {
            'total_logs_processed': 0,
            'threats_detected': 0,
            'patterns_matched': 0,
            'false_positives': 0,
            'high_severity_threats': 0
        }
        
        # Add enhanced login-specific patterns
        self._load_enhanced_login_patterns()
    
    def _load_enhanced_login_patterns(self):
        """Load enhanced patterns specifically for malicious login detection"""
        
        enhanced_patterns = [
            # Advanced SSH Attack Patterns
            SecurityPattern(
                name="SSH Dictionary Attack",
                pattern=r"authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+).*user=(?:admin|root|administrator|guest|test)",
                category=PatternCategory.BRUTE_FORCE,
                threat_level=ThreatLevel.HIGH,
                description="SSH dictionary attack targeting common accounts"
            ),
            
            SecurityPattern(
                name="SSH Rapid Fire",
                pattern=r"sshd.*Failed password.*from (\d+\.\d+\.\d+\.\d+)",
                category=PatternCategory.BRUTE_FORCE,
                threat_level=ThreatLevel.MEDIUM,
                description="Rapid SSH login failures indicating automated attack"
            ),
            
            # Web Application Login Attacks
            SecurityPattern(
                name="Web Login Brute Force",
                pattern=r"(POST|GET).*\/(?:login|signin|auth|wp-login).*(?:401|403|failed|invalid)",
                category=PatternCategory.BRUTE_FORCE,
                threat_level=ThreatLevel.MEDIUM,
                description="Web application login brute force attempt"
            ),
            
            SecurityPattern(
                name="WordPress Admin Attack",
                pattern=r"wp-login\.php.*(?:admin|administrator).*(?:401|403|failed)",
                category=PatternCategory.BRUTE_FORCE,
                threat_level=ThreatLevel.HIGH,
                description="WordPress admin panel brute force attack"
            ),
            
            # Database Login Attacks
            SecurityPattern(
                name="MySQL Brute Force",
                pattern=r"mysqld.*Access denied for user.*host.*password.*YES",
                category=PatternCategory.BRUTE_FORCE,
                threat_level=ThreatLevel.CRITICAL,
                description="MySQL database brute force attack"
            ),
            
            SecurityPattern(
                name="PostgreSQL Attack",
                pattern=r"postgres.*FATAL.*password authentication failed.*user",
                category=PatternCategory.BRUTE_FORCE,
                threat_level=ThreatLevel.CRITICAL,
                description="PostgreSQL database authentication attack"
            ),
            
            # FTP/SFTP Attacks
            SecurityPattern(
                name="FTP Brute Force",
                pattern=r"ftpd.*authentication failure.*user.*rhost=(\d+\.\d+\.\d+\.\d+)",
                category=PatternCategory.BRUTE_FORCE,
                threat_level=ThreatLevel.MEDIUM,
                description="FTP service brute force attack"
            ),
            
            # Email Server Attacks
            SecurityPattern(
                name="IMAP/POP3 Attack",
                pattern=r"(?:imapd|pop3d).*authentication failure.*user.*rhost=(\d+\.\d+\.\d+\.\d+)",
                category=PatternCategory.BRUTE_FORCE,
                threat_level=ThreatLevel.MEDIUM,
                description="Email server authentication attack"
            ),
            
            # VPN and Remote Access
            SecurityPattern(
                name="VPN Brute Force",
                pattern=r"(?:openvpn|pptp|l2tp).*authentication.*failed.*user.*(\d+\.\d+\.\d+\.\d+)",
                category=PatternCategory.BRUTE_FORCE,
                threat_level=ThreatLevel.HIGH,
                description="VPN service brute force attack"
            ),
            
            # Advanced Behavioral Patterns
            SecurityPattern(
                name="Distributed Attack",
                pattern=r"authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+).*user=(\w+)",
                category=PatternCategory.CREDENTIAL_STUFFING,
                threat_level=ThreatLevel.HIGH,
                description="Potential distributed credential stuffing attack"
            ),
            
            # Privilege Escalation
            SecurityPattern(
                name="Sudo Brute Force",
                pattern=r"sudo.*pam_unix.*authentication failure.*user=(\w+).*rhost=(\d+\.\d+\.\d+\.\d+)?",
                category=PatternCategory.PRIVILEGE_ESCALATION,
                threat_level=ThreatLevel.CRITICAL,
                description="Sudo privilege escalation brute force"
            ),
            
            # Service Account Attacks
            SecurityPattern(
                name="Service Account Attack",
                pattern=r"authentication failure.*user=(?:service|daemon|system|backup|apache|nginx|www-data)",
                category=PatternCategory.PRIVILEGE_ESCALATION,
                threat_level=ThreatLevel.HIGH,
                description="Attack targeting service accounts"
            )
        ]
        
        # Add all enhanced patterns
        for pattern in enhanced_patterns:
            self.pattern_matcher.add_custom_pattern(pattern)
    
    def parse_log_line(self, log_line: str) -> Dict[str, any]:
        """
        Parse a single log line with advanced pattern matching and behavioral analysis
        """
        result = {
            'suspicious': False,
            'threat_indicators': [],
            'behavioral_threats': [],
            'confidence_score': 0.0,
            'recommended_actions': []
        }
        
        try:
            # Pattern matching analysis
            pattern_matches = self.pattern_matcher.analyze_log_line(log_line)
            
            if pattern_matches:
                result['suspicious'] = True
                result['threat_indicators'] = pattern_matches
                result['confidence_score'] = max(m['threat_level'] for m in pattern_matches) / 4.0
                self.detection_stats['patterns_matched'] += len(pattern_matches)
                
                # Check for high severity threats
                if any(m['threat_level'] >= 3 for m in pattern_matches):
                    self.detection_stats['high_severity_threats'] += 1
            
            # Extract login attempt information for behavioral analysis
            login_attempt = self._extract_login_attempt(log_line)
            if login_attempt:
                self.behavioral_analyzer.add_login_attempt(login_attempt)
                
                # Run behavioral analysis
                behavioral_threats = []
                behavioral_threats.extend(self.behavioral_analyzer.detect_brute_force())
                behavioral_threats.extend(self.behavioral_analyzer.detect_credential_stuffing())
                behavioral_threats.extend(self.behavioral_analyzer.detect_account_enumeration())
                
                if behavioral_threats:
                    result['behavioral_threats'] = behavioral_threats
                    result['suspicious'] = True
                    
                    # Update confidence based on behavioral analysis
                    behavioral_confidence = max(t.confidence_score for t in behavioral_threats)
                    result['confidence_score'] = max(result['confidence_score'], behavioral_confidence)
                    
                    # Generate recommendations
                    result['recommended_actions'] = self._generate_recommendations(behavioral_threats)
            
            # Update statistics
            self.detection_stats['total_logs_processed'] += 1
            if result['suspicious']:
                self.detection_stats['threats_detected'] += 1
                
        except (RegexTimeoutError, MaliciousPatternError) as e:
            print(f"Security warning during parsing: {e}")
            result['error'] = str(e)
        
        return result
    
    def _extract_login_attempt(self, log_line: str) -> Optional[LoginAttempt]:
        """Extract login attempt information from log line"""
        
        # Common log patterns for login attempts
        patterns = [
            # SSH
            r"(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*sshd.*(?P<success>Failed|Accepted)\s+password for (?P<user>\w+) from (?P<ip>\d+\.\d+\.\d+\.\d+)",
            
            # General authentication
            r"(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*authentication (?P<success>failure|success).*user=(?P<user>\w+).*rhost=(?P<ip>\d+\.\d+\.\d+\.\d+)",
            
            # Web authentication
            r"(?P<ip>\d+\.\d+\.\d+\.\d+).*\[(?P<timestamp>[^\]]+)\].*(?:POST|GET).*\/(?:login|signin|auth).*(?P<success>401|200|403)"
        ]
        
        for pattern in patterns:
            match = re.search(pattern, log_line)
            if match:
                groups = match.groupdict()
                
                try:
                    # Parse timestamp (simplified)
                    timestamp = datetime.now()  # In real implementation, parse the actual timestamp
                    
                    # Determine success
                    success_indicators = groups.get('success', '')
                    success = success_indicators.lower() in ['accepted', 'success', '200']
                    
                    return LoginAttempt(
                        timestamp=timestamp,
                        username=groups.get('user', 'unknown'),
                        ip_address=groups.get('ip', 'unknown'),
                        success=success,
                        service='ssh',  # Could be enhanced to detect service type
                        user_agent=None,
                        source_port=None
                    )
                except Exception as e:
                    print(f"Error parsing login attempt: {e}")
                    continue
        
        return None
    
    def _generate_recommendations(self, threats: List[ThreatIndicator]) -> List[str]:
        """Generate security recommendations based on detected threats"""
        recommendations = set()
        
        for threat in threats:
            if threat.threat_type == "Brute Force Attack":
                recommendations.add("Implement account lockout policies")
                recommendations.add("Enable rate limiting on authentication endpoints")
                recommendations.add("Consider IP-based blocking for repeated failures")
                
            elif threat.threat_type == "Credential Stuffing":
                recommendations.add("Implement CAPTCHA for suspicious login patterns")
                recommendations.add("Enable multi-factor authentication")
                recommendations.add("Monitor for compromised credentials in breach databases")
                
            elif threat.threat_type == "Account Enumeration":
                recommendations.add("Implement generic error messages for login failures")
                recommendations.add("Add delays for authentication responses")
                recommendations.add("Monitor and alert on systematic username testing")
        
        return list(recommendations)
    
    def get_statistics(self) -> Dict[str, any]:
        """Get comprehensive parsing and detection statistics"""
        stats = self.detection_stats.copy()
        stats.update(self.pattern_matcher.get_statistics())
        
        # Calculate detection rate
        if stats['total_logs_processed'] > 0:
            stats['detection_rate'] = stats['threats_detected'] / stats['total_logs_processed']
        else:
            stats['detection_rate'] = 0.0
        
        return stats
    
    def export_threats(self, format: str = 'json') -> str:
        """Export detected threats in specified format"""
        # Implementation for threat export
        pass

# Legacy compatibility function
def parse_logs(log_file: str) -> List[str]:
    """
    Enhanced log parsing function with advanced pattern matching
    Maintains compatibility with existing code
    """
    parser = AdvancedSecurityParser()
    suspicious = []
    
    try:
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                
                result = parser.parse_log_line(line)
                if result['suspicious']:
                    # Format for compatibility with existing system
                    threat_info = {
                        'line': line,
                        'line_number': line_num,
                        'threats': result['threat_indicators'],
                        'behavioral_threats': result.get('behavioral_threats', []),
                        'confidence': result['confidence_score'],
                        'recommendations': result.get('recommended_actions', [])
                    }
                    suspicious.append(threat_info)
                    
    except FileNotFoundError:
        print(f"Error: Log file '{log_file}' not found")
    except Exception as e:
        print(f"Error parsing log file: {e}")
    
    return suspicious

def is_suspicious(line: str) -> bool:
    """
    Enhanced suspicious line detection
    Maintains compatibility with existing code
    """
    parser = AdvancedSecurityParser()
    result = parser.parse_log_line(line)
    return result['suspicious']

# Export functions for backward compatibility
__all__ = [
    'AdvancedSecurityParser',
    'BehavioralAnalyzer', 
    'ThreatIndicator',
    'LoginAttempt',
    'parse_logs',
    'is_suspicious'
]