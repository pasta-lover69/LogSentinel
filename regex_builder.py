"""
Secure Regex Builder Web Interface
Security Features:
- CSRF protection
- Input validation and sanitization
- Rate limiting
- XSS prevention
- SQL injection protection
"""

import json
import time
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from flask import session, request, abort
from functools import wraps
from regex_engine import (
    AdvancedPatternMatcher, SecurityPattern, ThreatLevel, 
    PatternCategory, RegexTimeoutError, MaliciousPatternError
)

class CSRFProtection:
    """CSRF protection for regex builder"""
    
    @staticmethod
    def generate_csrf_token() -> str:
        """Generate a secure CSRF token"""
        if 'csrf_token' not in session:
            session['csrf_token'] = secrets.token_hex(32)
        return session['csrf_token']
    
    @staticmethod
    def validate_csrf_token(token: str) -> bool:
        """Validate CSRF token"""
        return session.get('csrf_token') == token and token is not None

class RateLimiter:
    """Rate limiting for regex testing"""
    
    def __init__(self):
        self.requests = {}
        self.max_requests = 10  # Max requests per window
        self.time_window = 60   # Time window in seconds
    
    def is_allowed(self, client_ip: str) -> bool:
        """Check if request is allowed under rate limit"""
        now = time.time()
        
        # Clean old entries
        cutoff = now - self.time_window
        self.requests = {
            ip: times for ip, times in self.requests.items()
            if any(t > cutoff for t in times)
        }
        
        # Update current IP requests
        if client_ip not in self.requests:
            self.requests[client_ip] = []
        
        # Remove old requests for this IP
        self.requests[client_ip] = [
            t for t in self.requests[client_ip] if t > cutoff
        ]
        
        # Check if limit exceeded
        if len(self.requests[client_ip]) >= self.max_requests:
            return False
        
        # Add current request
        self.requests[client_ip].append(now)
        return True

class InputValidator:
    """Secure input validation for regex builder"""
    
    # Maximum lengths for security
    MAX_PATTERN_NAME = 100
    MAX_PATTERN_DESCRIPTION = 500
    MAX_PATTERN_LENGTH = 1000
    MAX_TEST_TEXT_LENGTH = 10000
    
    # Allowed characters for pattern names
    PATTERN_NAME_REGEX = r'^[a-zA-Z0-9_\-\s]{1,100}$'
    
    @classmethod
    def validate_pattern_name(cls, name: str) -> tuple[bool, str]:
        """Validate pattern name"""
        if not name:
            return False, "Pattern name is required"
        
        if len(name) > cls.MAX_PATTERN_NAME:
            return False, f"Pattern name too long (max {cls.MAX_PATTERN_NAME} characters)"
        
        import re
        if not re.match(cls.PATTERN_NAME_REGEX, name):
            return False, "Pattern name contains invalid characters"
        
        return True, ""
    
    @classmethod
    def validate_pattern_description(cls, description: str) -> tuple[bool, str]:
        """Validate pattern description"""
        if len(description) > cls.MAX_PATTERN_DESCRIPTION:
            return False, f"Description too long (max {cls.MAX_PATTERN_DESCRIPTION} characters)"
        
        # Basic XSS prevention
        dangerous_chars = ['<', '>', '"', "'", '&']
        if any(char in description for char in dangerous_chars):
            return False, "Description contains invalid characters"
        
        return True, ""
    
    @classmethod
    def validate_regex_pattern(cls, pattern: str) -> tuple[bool, str]:
        """Validate regex pattern"""
        if not pattern:
            return False, "Regex pattern is required"
        
        if len(pattern) > cls.MAX_PATTERN_LENGTH:
            return False, f"Pattern too long (max {cls.MAX_PATTERN_LENGTH} characters)"
        
        return True, ""
    
    @classmethod
    def validate_test_text(cls, text: str) -> tuple[bool, str]:
        """Validate test text"""
        if len(text) > cls.MAX_TEST_TEXT_LENGTH:
            return False, f"Test text too long (max {cls.MAX_TEST_TEXT_LENGTH} characters)"
        
        return True, ""
    
    @classmethod
    def sanitize_html(cls, text: str) -> str:
        """Sanitize HTML content"""
        import html
        return html.escape(text)

class SecureRegexBuilder:
    """Secure regex builder with comprehensive security features"""
    
    def __init__(self):
        self.pattern_matcher = AdvancedPatternMatcher()
        self.rate_limiter = RateLimiter()
        self.validator = InputValidator()
        self.audit_log = []
        
    def create_pattern(self, form_data: Dict[str, Any], client_ip: str) -> Dict[str, Any]:
        """
        Securely create a new regex pattern
        """
        result = {
            'success': False,
            'message': '',
            'pattern_id': None,
            'errors': {}
        }
        
        try:
            # Rate limiting check
            if not self.rate_limiter.is_allowed(client_ip):
                result['message'] = 'Rate limit exceeded. Please try again later.'
                self._log_security_event('rate_limit_exceeded', client_ip, form_data.get('name', 'unknown'))
                return result
            
            # CSRF validation
            csrf_token = form_data.get('csrf_token')
            if not CSRFProtection.validate_csrf_token(csrf_token):
                result['message'] = 'CSRF token validation failed'
                self._log_security_event('csrf_validation_failed', client_ip, form_data.get('name', 'unknown'))
                return result
            
            # Input validation
            validation_errors = self._validate_form_data(form_data)
            if validation_errors:
                result['errors'] = validation_errors
                result['message'] = 'Validation failed'
                return result
            
            # Create security pattern
            pattern = SecurityPattern(
                name=self.validator.sanitize_html(form_data['name']),
                pattern=form_data['pattern'],
                category=PatternCategory(form_data['category']),
                threat_level=ThreatLevel(int(form_data['threat_level'])),
                description=self.validator.sanitize_html(form_data['description']),
                case_sensitive=form_data.get('case_sensitive', False)
            )
            
            # Add pattern with security validation
            if self.pattern_matcher.add_custom_pattern(pattern):
                pattern_id = hashlib.md5(f"{pattern.name}{pattern.pattern}".encode()).hexdigest()
                result['success'] = True
                result['message'] = 'Pattern created successfully'
                result['pattern_id'] = pattern_id
                
                self._log_security_event('pattern_created', client_ip, pattern.name)
            else:
                result['message'] = 'Pattern failed security validation'
                self._log_security_event('pattern_rejected', client_ip, pattern.name)
            
        except (MaliciousPatternError, RegexTimeoutError) as e:
            result['message'] = f'Security validation failed: {str(e)}'
            self._log_security_event('security_validation_failed', client_ip, form_data.get('name', 'unknown'), str(e))
        except Exception as e:
            result['message'] = 'An error occurred while creating the pattern'
            self._log_security_event('pattern_creation_error', client_ip, form_data.get('name', 'unknown'), str(e))
        
        return result
    
    def test_pattern(self, form_data: Dict[str, Any], client_ip: str) -> Dict[str, Any]:
        """
        Securely test a regex pattern against sample text
        """
        result = {
            'success': False,
            'message': '',
            'matches': [],
            'execution_time': 0,
            'errors': {}
        }
        
        try:
            # Rate limiting check
            if not self.rate_limiter.is_allowed(client_ip):
                result['message'] = 'Rate limit exceeded. Please try again later.'
                return result
            
            # CSRF validation
            csrf_token = form_data.get('csrf_token')
            if not CSRFProtection.validate_csrf_token(csrf_token):
                result['message'] = 'CSRF token validation failed'
                return result
            
            # Input validation
            pattern = form_data.get('pattern', '')
            test_text = form_data.get('test_text', '')
            case_sensitive = form_data.get('case_sensitive', False)
            
            pattern_valid, pattern_error = self.validator.validate_regex_pattern(pattern)
            text_valid, text_error = self.validator.validate_test_text(test_text)
            
            if not pattern_valid:
                result['errors']['pattern'] = pattern_error
            if not text_valid:
                result['errors']['test_text'] = text_error
            
            if result['errors']:
                result['message'] = 'Validation failed'
                return result
            
            # Test pattern with security measures
            start_time = time.time()
            
            flags = 0 if case_sensitive else __import__('re').IGNORECASE
            compiled_pattern = self.pattern_matcher.engine.compile_pattern(pattern, flags)
            
            # Split large text into chunks to prevent memory exhaustion
            chunks = self._split_text_safely(test_text)
            all_matches = []
            
            for chunk_idx, chunk in enumerate(chunks):
                matches = self._find_matches_safely(compiled_pattern, chunk, chunk_idx * 1000)
                all_matches.extend(matches)
                
                # Limit total matches to prevent memory exhaustion
                if len(all_matches) > 100:
                    all_matches = all_matches[:100]
                    result['message'] = 'Results limited to first 100 matches for performance'
                    break
            
            execution_time = time.time() - start_time
            
            result['success'] = True
            result['matches'] = all_matches
            result['execution_time'] = round(execution_time * 1000, 2)  # Convert to milliseconds
            result['message'] = f'Found {len(all_matches)} matches in {result["execution_time"]}ms'
            
            self._log_security_event('pattern_tested', client_ip, f'pattern_length:{len(pattern)}')
            
        except (RegexTimeoutError, MaliciousPatternError) as e:
            result['message'] = f'Security validation failed: {str(e)}'
            self._log_security_event('pattern_test_blocked', client_ip, f'reason:{str(e)}')
        except Exception as e:
            result['message'] = 'An error occurred while testing the pattern'
            self._log_security_event('pattern_test_error', client_ip, str(e))
        
        return result
    
    def _validate_form_data(self, form_data: Dict[str, Any]) -> Dict[str, str]:
        """Validate all form data"""
        errors = {}
        
        # Validate pattern name
        name_valid, name_error = self.validator.validate_pattern_name(form_data.get('name', ''))
        if not name_valid:
            errors['name'] = name_error
        
        # Validate description
        desc_valid, desc_error = self.validator.validate_pattern_description(form_data.get('description', ''))
        if not desc_valid:
            errors['description'] = desc_error
        
        # Validate regex pattern
        pattern_valid, pattern_error = self.validator.validate_regex_pattern(form_data.get('pattern', ''))
        if not pattern_valid:
            errors['pattern'] = pattern_error
        
        # Validate category
        try:
            PatternCategory(form_data.get('category', ''))
        except ValueError:
            errors['category'] = 'Invalid category selected'
        
        # Validate threat level
        try:
            threat_level = int(form_data.get('threat_level', 0))
            if threat_level not in [1, 2, 3, 4]:
                errors['threat_level'] = 'Invalid threat level'
        except (ValueError, TypeError):
            errors['threat_level'] = 'Invalid threat level'
        
        return errors
    
    def _split_text_safely(self, text: str, chunk_size: int = 10000) -> List[str]:
        """Split large text into safe chunks"""
        if len(text) <= chunk_size:
            return [text]
        
        chunks = []
        for i in range(0, len(text), chunk_size):
            chunks.append(text[i:i + chunk_size])
        
        return chunks
    
    def _find_matches_safely(self, pattern, text: str, offset: int = 0) -> List[Dict[str, Any]]:
        """Find pattern matches with safety measures"""
        matches = []
        
        try:
            for match in pattern.finditer(text):
                match_info = {
                    'start': match.start() + offset,
                    'end': match.end() + offset,
                    'text': self.validator.sanitize_html(match.group(0)),
                    'groups': [self.validator.sanitize_html(g) if g else None for g in match.groups()]
                }
                matches.append(match_info)
                
                # Safety limit
                if len(matches) >= 50:
                    break
                    
        except Exception as e:
            self._log_security_event('match_finding_error', 'unknown', str(e))
        
        return matches
    
    def _log_security_event(self, event_type: str, client_ip: str, details: str, error: str = None):
        """Log security events for monitoring"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'client_ip': client_ip,
            'details': details,
            'error': error
        }
        
        self.audit_log.append(log_entry)
        
        # Keep only last 1000 entries to prevent memory issues
        if len(self.audit_log) > 1000:
            self.audit_log = self.audit_log[-1000:]
    
    def get_patterns(self) -> List[Dict[str, Any]]:
        """Get all patterns with sanitized output"""
        patterns = []
        
        for pattern in self.pattern_matcher.patterns:
            pattern_dict = {
                'name': self.validator.sanitize_html(pattern.name),
                'category': pattern.category.value,
                'threat_level': pattern.threat_level.value,
                'description': self.validator.sanitize_html(pattern.description),
                'enabled': pattern.enabled,
                'case_sensitive': pattern.case_sensitive
            }
            patterns.append(pattern_dict)
        
        return patterns
    
    def get_security_stats(self) -> Dict[str, Any]:
        """Get security statistics"""
        stats = self.pattern_matcher.get_statistics()
        
        # Add security-specific stats
        stats.update({
            'csrf_tokens_generated': len([e for e in self.audit_log if e['event_type'] == 'csrf_token_generated']),
            'rate_limit_hits': len([e for e in self.audit_log if e['event_type'] == 'rate_limit_exceeded']),
            'patterns_blocked': len([e for e in self.audit_log if e['event_type'] == 'pattern_rejected']),
            'validation_failures': len([e for e in self.audit_log if 'validation_failed' in e['event_type']]),
            'audit_log_entries': len(self.audit_log)
        })
        
        return stats

# Rate limiting decorator
def rate_limit(max_requests: int = 10, window: int = 60):
    """Decorator for rate limiting endpoints"""
    rate_limiter = RateLimiter()
    rate_limiter.max_requests = max_requests
    rate_limiter.time_window = window
    
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
            if not rate_limiter.is_allowed(client_ip):
                abort(429)  # Too Many Requests
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# CSRF protection decorator
def csrf_protect(f):
    """Decorator for CSRF protection"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            token = request.form.get('csrf_token') or request.json.get('csrf_token')
            if not CSRFProtection.validate_csrf_token(token):
                abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function

# Export main classes
__all__ = [
    'SecureRegexBuilder',
    'CSRFProtection',
    'RateLimiter',
    'InputValidator',
    'rate_limit',
    'csrf_protect'
]