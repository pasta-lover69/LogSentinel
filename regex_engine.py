"""
Secure Advanced Pattern Matching Engine for LogSentinel
Security Features:
- ReDoS protection with timeouts
- Pattern validation and sanitization
- Resource usage limits
- Malicious pattern detection
"""

import re
import time
import threading
import hashlib
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum

class ThreatLevel(Enum):
    """Threat severity levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class PatternCategory(Enum):
    """Categories of security patterns"""
    BRUTE_FORCE = "brute_force"
    CREDENTIAL_STUFFING = "credential_stuffing"
    ACCOUNT_ENUMERATION = "account_enumeration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SQL_INJECTION = "sql_injection"
    XSS_ATTEMPT = "xss_attempt"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    FAILED_LOGIN = "failed_login"
    SUSPICIOUS_IP = "suspicious_ip"

@dataclass
class SecurityPattern:
    """Secure pattern definition"""
    name: str
    pattern: str
    category: PatternCategory
    threat_level: ThreatLevel
    description: str
    enabled: bool = True
    case_sensitive: bool = False
    
class RegexTimeoutError(Exception):
    """Raised when regex execution times out"""
    pass

class MaliciousPatternError(Exception):
    """Raised when a potentially malicious pattern is detected"""
    pass

class SecureRegexEngine:
    """
    Security-hardened regex engine with ReDoS protection
    """
    
    # Security limits
    MAX_PATTERN_LENGTH = 1000
    MAX_EXECUTION_TIME = 5.0  # seconds
    MAX_COMPLEXITY_SCORE = 100
    MAX_CACHED_PATTERNS = 1000
    
    # Dangerous regex patterns that could cause ReDoS
    DANGEROUS_PATTERNS = [
        r'(a+)+',  # Catastrophic backtracking
        r'(a|a)*',  # Alternative repetition
        r'([a-zA-Z]+)*',  # Nested quantifiers
        r'(.*)*',  # Double star
        r'(a?){10,}',  # Optional with high repetition
    ]
    
    def __init__(self):
        self.compiled_patterns: Dict[str, re.Pattern] = {}
        self.pattern_cache: Dict[str, Any] = {}
        self.stats = {
            'patterns_compiled': 0,
            'patterns_executed': 0,
            'timeouts': 0,
            'security_blocks': 0
        }
    
    def validate_pattern(self, pattern: str) -> bool:
        """
        Validate regex pattern for security issues
        """
        if not pattern or len(pattern) > self.MAX_PATTERN_LENGTH:
            raise MaliciousPatternError("Pattern too long or empty")
        
        # Check for dangerous patterns
        for dangerous in self.DANGEROUS_PATTERNS:
            if re.search(dangerous, pattern):
                raise MaliciousPatternError(f"Potentially dangerous pattern detected: {dangerous}")
        
        # Calculate complexity score
        complexity = self._calculate_complexity(pattern)
        if complexity > self.MAX_COMPLEXITY_SCORE:
            raise MaliciousPatternError(f"Pattern complexity too high: {complexity}")
        
        return True
    
    def _calculate_complexity(self, pattern: str) -> int:
        """Calculate pattern complexity score"""
        score = 0
        score += pattern.count('*') * 5  # Kleene star
        score += pattern.count('+') * 4  # Plus quantifier
        score += pattern.count('?') * 2  # Optional
        score += pattern.count('|') * 3  # Alternation
        score += pattern.count('(') * 2  # Groups
        score += len(pattern) // 10      # Base complexity
        return score
    
    def compile_pattern(self, pattern: str, flags: int = 0) -> re.Pattern:
        """
        Safely compile regex pattern with security checks
        """
        # Create pattern hash for caching
        pattern_hash = hashlib.md5(f"{pattern}{flags}".encode()).hexdigest()
        
        if pattern_hash in self.compiled_patterns:
            return self.compiled_patterns[pattern_hash]
        
        # Validate pattern security
        self.validate_pattern(pattern)
        
        try:
            # Compile with timeout protection
            compiled = self._safe_compile(pattern, flags)
            
            # Cache the compiled pattern
            if len(self.compiled_patterns) < self.MAX_CACHED_PATTERNS:
                self.compiled_patterns[pattern_hash] = compiled
            
            self.stats['patterns_compiled'] += 1
            return compiled
            
        except re.error as e:
            raise MaliciousPatternError(f"Invalid regex pattern: {e}")
    
    def _safe_compile(self, pattern: str, flags: int) -> re.Pattern:
        """Compile pattern with timeout protection"""
        result = []
        exception = []
        
        def compile_thread():
            try:
                result.append(re.compile(pattern, flags))
            except Exception as e:
                exception.append(e)
        
        thread = threading.Thread(target=compile_thread)
        thread.daemon = True
        thread.start()
        thread.join(timeout=2.0)  # 2 second timeout for compilation
        
        if thread.is_alive():
            raise RegexTimeoutError("Pattern compilation timed out")
        
        if exception:
            raise exception[0]
        
        if not result:
            raise RegexTimeoutError("Pattern compilation failed")
        
        return result[0]
    
    def safe_match(self, pattern: re.Pattern, text: str) -> Optional[re.Match]:
        """
        Execute regex match with timeout protection
        """
        if not text:
            return None
        
        result = []
        exception = []
        
        def match_thread():
            try:
                result.append(pattern.search(text))
            except Exception as e:
                exception.append(e)
        
        thread = threading.Thread(target=match_thread)
        thread.daemon = True
        thread.start()
        thread.join(timeout=self.MAX_EXECUTION_TIME)
        
        if thread.is_alive():
            self.stats['timeouts'] += 1
            raise RegexTimeoutError("Pattern execution timed out")
        
        if exception:
            raise exception[0]
        
        self.stats['patterns_executed'] += 1
        return result[0] if result else None
    
    def get_stats(self) -> Dict[str, int]:
        """Get engine statistics"""
        return self.stats.copy()
    
    def clear_cache(self):
        """Clear pattern cache"""
        self.compiled_patterns.clear()
        self.pattern_cache.clear()

class AdvancedPatternMatcher:
    """
    Advanced pattern matching system with security-hardened regex engine
    """
    
    def __init__(self):
        self.engine = SecureRegexEngine()
        self.patterns: List[SecurityPattern] = []
        self.load_default_patterns()
    
    def load_default_patterns(self):
        """Load default security patterns"""
        self.patterns = [
            # Brute Force Attacks
            SecurityPattern(
                name="SSH Brute Force",
                pattern=r"Failed password for .* from (\d+\.\d+\.\d+\.\d+) port \d+ ssh",
                category=PatternCategory.BRUTE_FORCE,
                threat_level=ThreatLevel.HIGH,
                description="SSH brute force attack attempts"
            ),
            SecurityPattern(
                name="Multiple Failed Logins",
                pattern=r"authentication failure.*user=(\w+).*rhost=(\d+\.\d+\.\d+\.\d+)",
                category=PatternCategory.BRUTE_FORCE,
                threat_level=ThreatLevel.MEDIUM,
                description="Multiple authentication failures from same source"
            ),
            
            # Credential Stuffing
            SecurityPattern(
                name="Rapid Login Attempts",
                pattern=r"login attempt.*(\d+\.\d+\.\d+\.\d+).*(?=.*login attempt.*\1.*){3,}",
                category=PatternCategory.CREDENTIAL_STUFFING,
                threat_level=ThreatLevel.HIGH,
                description="Rapid login attempts indicating credential stuffing"
            ),
            
            # Account Enumeration
            SecurityPattern(
                name="Invalid User Enumeration",
                pattern=r"Invalid user (\w+) from (\d+\.\d+\.\d+\.\d+)",
                category=PatternCategory.ACCOUNT_ENUMERATION,
                threat_level=ThreatLevel.MEDIUM,
                description="Attempts to enumerate valid usernames"
            ),
            
            # Privilege Escalation
            SecurityPattern(
                name="Sudo Failures",
                pattern=r"sudo.*authentication failure.*user=(\w+)",
                category=PatternCategory.PRIVILEGE_ESCALATION,
                threat_level=ThreatLevel.HIGH,
                description="Failed privilege escalation attempts"
            ),
            
            # Web Application Attacks
            SecurityPattern(
                name="SQL Injection Attempt",
                pattern=r"(\bUNION\b|\bSELECT\b|\bINSERT\b|\bDROP\b|\bDELETE\b).*(\bFROM\b|\bWHERE\b)",
                category=PatternCategory.SQL_INJECTION,
                threat_level=ThreatLevel.CRITICAL,
                description="Potential SQL injection attempts",
                case_sensitive=False
            ),
            
            # Command Injection
            SecurityPattern(
                name="Command Injection",
                pattern=r"(;|\||\&|\$\(|\`).*(rm|cat|ls|ps|kill|wget|curl|nc|netcat)",
                category=PatternCategory.COMMAND_INJECTION,
                threat_level=ThreatLevel.CRITICAL,
                description="Command injection attempts"
            ),
            
            # Path Traversal
            SecurityPattern(
                name="Path Traversal",
                pattern=r"(\.\./){3,}|(\.\.\\/){3,}|(%2e%2e%2f){3,}",
                category=PatternCategory.PATH_TRAVERSAL,
                threat_level=ThreatLevel.HIGH,
                description="Directory traversal attempts",
                case_sensitive=False
            ),
            
            # XSS Attempts
            SecurityPattern(
                name="XSS Attempt",
                pattern=r"<script[^>]*>.*</script>|javascript:|onload=|onerror=",
                category=PatternCategory.XSS_ATTEMPT,
                threat_level=ThreatLevel.HIGH,
                description="Cross-site scripting attempts",
                case_sensitive=False
            ),
            
            # Suspicious IPs
            SecurityPattern(
                name="Tor Exit Node",
                pattern=r"(tor-exit|exit-node|proxy|vpn).*(\d+\.\d+\.\d+\.\d+)",
                category=PatternCategory.SUSPICIOUS_IP,
                threat_level=ThreatLevel.MEDIUM,
                description="Traffic from anonymization services",
                case_sensitive=False
            )
        ]
    
    def add_custom_pattern(self, pattern: SecurityPattern) -> bool:
        """
        Add custom security pattern with validation
        """
        try:
            # Validate the pattern
            self.engine.validate_pattern(pattern.pattern)
            
            # Compile to ensure it's valid
            flags = 0 if pattern.case_sensitive else re.IGNORECASE
            self.engine.compile_pattern(pattern.pattern, flags)
            
            # Add to patterns list
            self.patterns.append(pattern)
            return True
            
        except (MaliciousPatternError, RegexTimeoutError) as e:
            print(f"Security warning: Pattern rejected - {e}")
            return False
    
    def analyze_log_line(self, log_line: str) -> List[Dict[str, Any]]:
        """
        Analyze a log line against all security patterns
        """
        matches = []
        
        for pattern in self.patterns:
            if not pattern.enabled:
                continue
            
            try:
                flags = 0 if pattern.case_sensitive else re.IGNORECASE
                compiled_pattern = self.engine.compile_pattern(pattern.pattern, flags)
                match = self.engine.safe_match(compiled_pattern, log_line)
                
                if match:
                    matches.append({
                        'pattern_name': pattern.name,
                        'category': pattern.category.value,
                        'threat_level': pattern.threat_level.value,
                        'description': pattern.description,
                        'matched_text': match.group(0),
                        'groups': match.groups(),
                        'log_line': log_line,
                        'timestamp': time.time()
                    })
                    
            except (RegexTimeoutError, MaliciousPatternError) as e:
                print(f"Security warning: Pattern '{pattern.name}' blocked - {e}")
                continue
        
        return matches
    
    def get_patterns_by_category(self, category: PatternCategory) -> List[SecurityPattern]:
        """Get patterns by category"""
        return [p for p in self.patterns if p.category == category]
    
    def get_patterns_by_threat_level(self, min_level: ThreatLevel) -> List[SecurityPattern]:
        """Get patterns by minimum threat level"""
        return [p for p in self.patterns if p.threat_level.value >= min_level.value]
    
    def disable_pattern(self, pattern_name: str):
        """Disable a specific pattern"""
        for pattern in self.patterns:
            if pattern.name == pattern_name:
                pattern.enabled = False
                break
    
    def enable_pattern(self, pattern_name: str):
        """Enable a specific pattern"""
        for pattern in self.patterns:
            if pattern.name == pattern_name:
                pattern.enabled = True
                break
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics"""
        stats = self.engine.get_stats()
        stats.update({
            'total_patterns': len(self.patterns),
            'enabled_patterns': len([p for p in self.patterns if p.enabled]),
            'patterns_by_category': {
                cat.value: len(self.get_patterns_by_category(cat))
                for cat in PatternCategory
            },
            'patterns_by_threat_level': {
                f"level_{level.value}": len(self.get_patterns_by_threat_level(level))
                for level in ThreatLevel
            }
        })
        return stats

# Export main classes
__all__ = [
    'AdvancedPatternMatcher',
    'SecurityPattern',
    'ThreatLevel',
    'PatternCategory',
    'SecureRegexEngine',
    'RegexTimeoutError',
    'MaliciousPatternError'
]