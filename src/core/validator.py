"""
Core Input Validation Engine with Security Focus
Provides comprehensive validation for security threats and data integrity
"""

import re
import json
import yaml
from typing import Any, Dict, List, Union, Optional, Callable
from dataclasses import dataclass
from enum import Enum
import datetime
import decimal
import hashlib
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SecurityThreatLevel(Enum):
    """Security threat levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ValidationType(Enum):
    """Supported validation types"""
    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    EMAIL = "email"
    URL = "url"
    PHONE = "phone"
    DATE = "date"
    DATETIME = "datetime"
    IP_ADDRESS = "ip_address"
    UUID = "uuid"
    JSON = "json"
    SQL_SAFE = "sql_safe"
    XSS_SAFE = "xss_safe"
    COMMAND_SAFE = "command_safe"
    PATH_SAFE = "path_safe"
    CUSTOM = "custom"


@dataclass
class SecurityValidationResult:
    """Result of security validation"""
    is_safe: bool
    threat_level: SecurityThreatLevel
    detected_threats: List[str]
    confidence_score: float
    recommendations: List[str]


@dataclass
class ValidationResult:
    """Result of validation operation"""
    is_valid: bool
    errors: List[str]
    warnings: List[str]
    validated_data: Any
    metadata: Dict[str, Any]
    security_result: Optional[SecurityValidationResult] = None


class SecurityValidator:
    """Security-focused validation rules"""
    
    def __init__(self):
        # SQL Injection patterns
        self.sql_patterns = [
            r"(\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b)",
            r"(\b(and|or)\b\s+\d+\s*[=<>])",
            r"(--|#|/\*|\*/)",
            r"(\bxp_|sp_|fn_)",
            r"(\bwaitfor\b|\bdelay\b)",
            r"(\bchar\s*\(\s*\d+\s*\))",
            r"(\bcast\s*\(\s*\w+\s+as\s+\w+\s*\))",
        ]
        
        # XSS patterns
        self.xss_patterns = [
            r"(<script[^>]*>.*?</script>)",
            r"(javascript:)",
            r"(on\w+\s*=)",
            r"(<iframe[^>]*>)",
            r"(<object[^>]*>)",
            r"(<embed[^>]*>)",
            r"(<form[^>]*>)",
            r"(<input[^>]*>)",
            r"(<textarea[^>]*>)",
            r"(<select[^>]*>)",
            r"(<button[^>]*>)",
            r"(<link[^>]*>)",
            r"(<meta[^>]*>)",
            r"(<style[^>]*>)",
            r"(<base[^>]*>)",
            r"(<bgsound[^>]*>)",
            r"(<link[^>]*>)",
            r"(<xml[^>]*>)",
            r"(<xmp[^>]*>)",
            r"(<plaintext[^>]*>)",
            r"(<listing[^>]*>)",
        ]
        
        # Command injection patterns
        self.command_patterns = [
            r"(\b(cat|ls|dir|pwd|whoami|id|uname|ps|top|kill|rm|del|copy|move|mkdir|rmdir)\b)",
            r"(\b(bash|sh|cmd|powershell|python|perl|ruby|php|java|node)\b)",
            r"(\b(sudo|su|runas|impersonate)\b)",
            r"(\b(net|netstat|ipconfig|ifconfig|route|arp|ping|traceroute|telnet|ssh|ftp|scp)\b)",
            r"(\b(grep|find|sed|awk|sort|uniq|wc|head|tail|less|more)\b)",
            r"(\b(tar|zip|unzip|gzip|gunzip|bzip2|bunzip2)\b)",
            r"(\b(chmod|chown|chgrp|umask|ulimit)\b)",
            r"(\b(export|set|env|printenv|unset)\b)",
            r"(\b(echo|printf|sprintf|fprintf|vprintf|vfprintf)\b)",
            r"(\b(system|exec|popen|shell_exec|passthru|eval|assert)\b)",
        ]
        
        # Path traversal patterns
        self.path_patterns = [
            r"(\.\./|\.\.\\)",
            r"(/etc/|/var/|/usr/|/bin/|/sbin/|/tmp/|/home/|/root/)",
            r"(c:\\|d:\\|e:\\)",
            r"(/proc/|/sys/|/dev/|/mnt/|/media/)",
            r"(~|%USERPROFILE%|%HOMEPATH%|%APPDATA%)",
            r"(\.\.%2f|\.\.%5c|\.\.%2F|\.\.%5C)",
            r"(%2e%2e%2f|%2e%2e%5c|%2e%2e%2F|%2e%2e%5C)",
        ]
        
        # Compile patterns for efficiency
        self.compiled_sql = [re.compile(pattern, re.IGNORECASE) for pattern in self.sql_patterns]
        self.compiled_xss = [re.compile(pattern, re.IGNORECASE) for pattern in self.xss_patterns]
        self.compiled_command = [re.compile(pattern, re.IGNORECASE) for pattern in self.command_patterns]
        self.compiled_path = [re.compile(pattern, re.IGNORECASE) for pattern in self.path_patterns]
    
    def validate_sql_safety(self, value: str) -> SecurityValidationResult:
        """Validate SQL injection safety"""
        if not isinstance(value, str):
            return SecurityValidationResult(
                is_safe=False,
                threat_level=SecurityThreatLevel.HIGH,
                detected_threats=["Non-string input"],
                confidence_score=0.9,
                recommendations=["Ensure input is string type"]
            )
        
        detected_threats = []
        for pattern in self.compiled_sql:
            if pattern.search(value):
                detected_threats.append(f"SQL injection pattern: {pattern.pattern}")
        
        if detected_threats:
            return SecurityValidationResult(
                is_safe=False,
                threat_level=SecurityThreatLevel.CRITICAL,
                detected_threats=detected_threats,
                confidence_score=0.95,
                recommendations=[
                    "Sanitize input using parameterized queries",
                    "Use ORM frameworks",
                    "Implement input validation"
                ]
            )
        
        return SecurityValidationResult(
            is_safe=True,
            threat_level=SecurityThreatLevel.LOW,
            detected_threats=[],
            confidence_score=0.8,
            recommendations=["Continue monitoring for new patterns"]
        )
    
    def validate_xss_safety(self, value: str) -> SecurityValidationResult:
        """Validate XSS safety"""
        if not isinstance(value, str):
            return SecurityValidationResult(
                is_safe=False,
                threat_level=SecurityThreatLevel.HIGH,
                detected_threats=["Non-string input"],
                confidence_score=0.9,
                recommendations=["Ensure input is string type"]
            )
        
        detected_threats = []
        for pattern in self.compiled_xss:
            if pattern.search(value):
                detected_threats.append(f"XSS pattern: {pattern.pattern}")
        
        if detected_threats:
            return SecurityValidationResult(
                is_safe=False,
                threat_level=SecurityThreatLevel.HIGH,
                detected_threats=detected_threats,
                confidence_score=0.9,
                recommendations=[
                    "HTML encode output",
                    "Use Content Security Policy",
                    "Validate and sanitize input"
                ]
            )
        
        return SecurityValidationResult(
            is_safe=True,
            threat_level=SecurityThreatLevel.LOW,
            detected_threats=[],
            confidence_score=0.8,
            recommendations=["Continue monitoring for new patterns"]
        )
    
    def validate_command_safety(self, value: str) -> SecurityValidationResult:
        """Validate command injection safety"""
        if not isinstance(value, str):
            return SecurityValidationResult(
                is_safe=False,
                threat_level=SecurityThreatLevel.HIGH,
                detected_threats=["Non-string input"],
                confidence_score=0.9,
                recommendations=["Ensure input is string type"]
            )
        
        detected_threats = []
        for pattern in self.compiled_command:
            if pattern.search(value):
                detected_threats.append(f"Command injection pattern: {pattern.pattern}")
        
        if detected_threats:
            return SecurityValidationResult(
                is_safe=False,
                threat_level=SecurityThreatLevel.CRITICAL,
                detected_threats=detected_threats,
                confidence_score=0.95,
                recommendations=[
                    "Avoid shell execution",
                    "Use subprocess with shell=False",
                    "Validate and sanitize input"
                ]
            )
        
        return SecurityValidationResult(
            is_safe=True,
            threat_level=SecurityThreatLevel.LOW,
            detected_threats=[],
            confidence_score=0.8,
            recommendations=["Continue monitoring for new patterns"]
        )
    
    def validate_path_safety(self, value: str) -> SecurityValidationResult:
        """Validate path traversal safety"""
        if not isinstance(value, str):
            return SecurityValidationResult(
                is_safe=False,
                threat_level=SecurityThreatLevel.HIGH,
                detected_threats=["Non-string input"],
                confidence_score=0.9,
                recommendations=["Ensure input is string type"]
            )
        
        detected_threats = []
        for pattern in self.compiled_path:
            if pattern.search(value):
                detected_threats.append(f"Path traversal pattern: {pattern.pattern}")
        
        if detected_threats:
            return SecurityValidationResult(
                is_safe=False,
                threat_level=SecurityThreatLevel.HIGH,
                detected_threats=detected_threats,
                confidence_score=0.9,
                recommendations=[
                    "Use path normalization",
                    "Implement path validation",
                    "Restrict file access to safe directories"
                ]
            )
        
        return SecurityValidationResult(
            is_safe=True,
            threat_level=SecurityThreatLevel.LOW,
            detected_threats=[],
            confidence_score=0.8,
            recommendations=["Continue monitoring for new patterns"]
        )


class InputValidator:
    """Main input validation engine with security focus"""
    
    def __init__(self):
        self.security_validator = SecurityValidator()
        self.rules: Dict[str, Any] = {}
        self.custom_validators: Dict[str, Callable] = {}
        self.audit_logger = logging.getLogger("audit")
        self._register_default_rules()
    
    def _register_default_rules(self):
        """Register default validation rules"""
        self.rules = {
            "string": self._string_validator,
            "integer": self._integer_validator,
            "float": self._float_validator,
            "boolean": self._boolean_validator,
            "email": self._email_validator,
            "url": self._url_validator,
            "phone": self._phone_validator,
            "date": self._date_validator,
            "datetime": self._datetime_validator,
            "ip_address": self._ip_address_validator,
            "uuid": self._uuid_validator,
            "json": self._json_validator,
            "sql_safe": self._sql_safe_validator,
            "xss_safe": self._xss_safe_validator,
            "command_safe": self._command_safe_validator,
            "path_safe": self._path_safe_validator,
        }
    
    def _string_validator(self, value: Any, **kwargs) -> tuple[bool, str]:
        """String validation"""
        if not isinstance(value, str):
            return False, f"Expected string, got {type(value).__name__}"
        
        min_length = kwargs.get('min_length')
        max_length = kwargs.get('max_length')
        pattern = kwargs.get('pattern')
        allowed_values = kwargs.get('allowed_values')
        
        if min_length and len(value) < min_length:
            return False, f"String too short. Minimum length: {min_length}"
        
        if max_length and len(value) > max_length:
            return False, f"String too long. Maximum length: {max_length}"
        
        if pattern and not re.match(pattern, value):
            return False, f"String does not match pattern: {pattern}"
        
        if allowed_values and value not in allowed_values:
            return False, f"Value '{value}' not in allowed values: {allowed_values}"
        
        return True, ""
    
    def _integer_validator(self, value: Any, **kwargs) -> tuple[bool, str]:
        """Integer validation"""
        try:
            num_value = int(value)
        except (ValueError, TypeError):
            return False, f"Expected integer, got {type(value).__name__}"
        
        min_value = kwargs.get('min_value')
        max_value = kwargs.get('max_value')
        
        if min_value is not None and num_value < min_value:
            return False, f"Value too small. Minimum: {min_value}"
        
        if max_value is not None and num_value > max_value:
            return False, f"Value too large. Maximum: {max_value}"
        
        return True, ""
    
    def _float_validator(self, value: Any, **kwargs) -> tuple[bool, str]:
        """Float validation"""
        try:
            num_value = float(value)
        except (ValueError, TypeError):
            return False, f"Expected float, got {type(value).__name__}"
        
        min_value = kwargs.get('min_value')
        max_value = kwargs.get('max_value')
        
        if min_value is not None and num_value < min_value:
            return False, f"Value too small. Minimum: {min_value}"
        
        if max_value is not None and num_value > max_value:
            return False, f"Value too large. Maximum: {max_value}"
        
        return True, ""
    
    def _boolean_validator(self, value: Any) -> tuple[bool, str]:
        """Boolean validation"""
        if isinstance(value, bool):
            return True, ""
        if isinstance(value, str):
            if value.lower() in ['true', 'false', '1', '0', 'yes', 'no']:
                return True, ""
        if isinstance(value, (int, float)) and value in [0, 1]:
            return True, ""
        return False, "Expected boolean value"
    
    def _email_validator(self, value: Any) -> tuple[bool, str]:
        """Email validation"""
        if not isinstance(value, str):
            return False, f"Expected string, got {type(value).__name__}"
        
        email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        if not email_pattern.match(value):
            return False, "Invalid email format"
        
        return True, ""
    
    def _url_validator(self, value: Any) -> tuple[bool, str]:
        """URL validation"""
        if not isinstance(value, str):
            return False, f"Expected string, got {type(value).__name__}"
        
        url_pattern = re.compile(r'^[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/$.?#].[^\s]*$')
        if not url_pattern.match(value):
            return False, "Invalid URL format"
        
        return True, ""
    
    def _phone_validator(self, value: Any) -> tuple[bool, str]:
        """Phone validation"""
        if not isinstance(value, str):
            return False, f"Expected string, got {type(value).__name__}"
        
        phone_pattern = re.compile(r'^\+?[\d\s\-\(\)]+$')
        if not phone_pattern.match(value):
            return False, "Invalid phone format"
        
        return True, ""
    
    def _date_validator(self, value: Any) -> tuple[bool, str]:
        """Date validation"""
        if isinstance(value, datetime.date):
            return True, ""
        if isinstance(value, str):
            try:
                datetime.datetime.strptime(value, "%Y-%m-%d")
                return True, ""
            except ValueError:
                pass
        return False, "Expected valid date (YYYY-MM-DD format)"
    
    def _datetime_validator(self, value: Any) -> tuple[bool, str]:
        """Datetime validation"""
        if isinstance(value, datetime.datetime):
            return True, ""
        if isinstance(value, str):
            try:
                datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
                return True, ""
            except ValueError:
                pass
        return False, "Expected valid ISO datetime format"
    
    def _ip_address_validator(self, value: Any) -> tuple[bool, str]:
        """IP address validation"""
        if not isinstance(value, str):
            return False, "Expected string"
        
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        if not ip_pattern.match(value):
            return False, "Invalid IP address format"
        
        parts = value.split('.')
        for part in parts:
            if not 0 <= int(part) <= 255:
                return False, "IP address parts must be between 0 and 255"
        
        return True, ""
    
    def _uuid_validator(self, value: Any) -> tuple[bool, str]:
        """UUID validation"""
        if not isinstance(value, str):
            return False, "Expected string"
        
        uuid_pattern = re.compile(
            r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
            re.IGNORECASE
        )
        if not uuid_pattern.match(value):
            return False, "Invalid UUID format"
        
        return True, ""
    
    def _json_validator(self, value: Any) -> tuple[bool, str]:
        """JSON validation"""
        if isinstance(value, (dict, list)):
            return True, ""
        if isinstance(value, str):
            try:
                json.loads(value)
                return True, ""
            except json.JSONDecodeError:
                return False, "Invalid JSON format"
        return False, "Expected JSON object, array, or JSON string"
    
    def _sql_safe_validator(self, value: Any) -> tuple[bool, str]:
        """SQL injection safety validation"""
        if not isinstance(value, str):
            return False, f"Expected string, got {type(value).__name__}"
        
        security_result = self.security_validator.validate_sql_safety(value)
        if not security_result.is_safe:
            return False, f"SQL injection threat detected: {', '.join(security_result.detected_threats)}"
        
        return True, ""
    
    def _xss_safe_validator(self, value: Any) -> tuple[bool, str]:
        """XSS safety validation"""
        if not isinstance(value, str):
            return False, f"Expected string, got {type(value).__name__}"
        
        security_result = self.security_validator.validate_xss_safety(value)
        if not security_result.is_safe:
            return False, f"XSS threat detected: {', '.join(security_result.detected_threats)}"
        
        return True, ""
    
    def _command_safe_validator(self, value: Any) -> tuple[bool, str]:
        """Command injection safety validation"""
        if not isinstance(value, str):
            return False, f"Expected string, got {type(value).__name__}"
        
        security_result = self.security_validator.validate_command_safety(value)
        if not security_result.is_safe:
            return False, f"Command injection threat detected: {', '.join(security_result.detected_threats)}"
        
        return True, ""
    
    def _path_safe_validator(self, value: Any) -> tuple[bool, str]:
        """Path traversal safety validation"""
        if not isinstance(value, str):
            return False, f"Expected string, got {type(value).__name__}"
        
        security_result = self.security_validator.validate_path_safety(value)
        if not security_result.is_safe:
            return False, f"Path traversal threat detected: {', '.join(security_result.detected_threats)}"
        
        return True, ""
    
    def add_custom_rule(self, name: str, validator: Callable):
        """Add a custom validation rule"""
        self.custom_validators[name] = validator
    
    def validate_field(self, value: Any, field_type: str, **kwargs) -> ValidationResult:
        """Validate a single field with security validation"""
        errors = []
        warnings = []
        security_result = None
        
        # Get the appropriate validator
        if field_type in self.custom_validators:
            validator = self.custom_validators[field_type]
            is_valid, error_msg = validator(value, **kwargs)
        elif field_type in self.rules:
            validator = self.rules[field_type]
            is_valid, error_msg = validator(value, **kwargs)
        else:
            return ValidationResult(
                is_valid=False,
                errors=[f"Unknown field type: {field_type}"],
                warnings=[],
                validated_data=value,
                metadata={"field_type": field_type},
                security_result=None
            )
        
        if not is_valid:
            errors.append(error_msg)
        
        # Perform security validation for string inputs
        if isinstance(value, str) and field_type not in ['sql_safe', 'xss_safe', 'command_safe', 'path_safe']:
            if 'sql_safe' in kwargs and kwargs['sql_safe']:
                sql_result = self.security_validator.validate_sql_safety(value)
                if not sql_result.is_safe:
                    errors.append(f"SQL injection threat: {', '.join(sql_result.detected_threats)}")
                    security_result = sql_result
            
            if 'xss_safe' in kwargs and kwargs['xss_safe']:
                xss_result = self.security_validator.validate_xss_safety(value)
                if not xss_result.is_safe:
                    errors.append(f"XSS threat: {', '.join(xss_result.detected_threats)}")
                    security_result = security_result or xss_result
            
            if 'command_safe' in kwargs and kwargs['command_safe']:
                cmd_result = self.security_validator.validate_command_safety(value)
                if not cmd_result.is_safe:
                    errors.append(f"Command injection threat: {', '.join(cmd_result.detected_threats)}")
                    security_result = security_result or cmd_result
            
            if 'path_safe' in kwargs and kwargs['path_safe']:
                path_result = self.security_validator.validate_path_safety(value)
                if not path_result.is_safe:
                    errors.append(f"Path traversal threat: {', '.join(path_result.detected_threats)}")
                    security_result = security_result or path_result
        
        # Log validation results for audit
        self._log_validation_result(field_type, value, len(errors) == 0, errors)
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            validated_data=value,
            metadata={"field_type": field_type, **kwargs},
            security_result=security_result
        )
    
    def validate_schema(self, data: Dict[str, Any], schema: Dict[str, Any]) -> ValidationResult:
        """Validate data against a schema with security validation"""
        errors = []
        warnings = []
        validated_data = {}
        security_results = []
        
        for field_name, field_config in schema.items():
            if field_name not in data:
                if field_config.get("required", False):
                    errors.append(f"Required field '{field_name}' is missing")
                continue
            
            field_value = data[field_name]
            field_type = field_config.get("type", "string")
            
            # Validate the field - only pass validation-specific parameters
            validation_params = {}
            for k, v in field_config.items():
                if k not in ["type", "required", "sql_safe", "xss_safe", "command_safe", "path_safe"]:  # Filter out schema-specific and security params
                    validation_params[k] = v
            
            field_result = self.validate_field(
                field_value, 
                field_type, 
                **validation_params
            )
            
            if not field_result.is_valid:
                errors.extend([f"{field_name}: {error}" for error in field_result.errors])
            
            if field_result.warnings:
                warnings.extend([f"{field_name}: {warning}" for warning in field_result.warnings])
            
            if field_result.security_result:
                security_results.append(field_result.security_result)
            
            validated_data[field_name] = field_result.validated_data
        
        # Log schema validation results
        self._log_schema_validation_result(schema, len(errors) == 0, errors)
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            validated_data=validated_data,
            metadata={"schema": schema, "security_results": security_results}
        )
    
    def _log_validation_result(self, field_type: str, value: Any, is_valid: bool, errors: List[str]):
        """Log validation results for audit purposes"""
        log_data = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "field_type": field_type,
            "value_hash": hashlib.sha256(str(value).encode()).hexdigest()[:16],
            "is_valid": is_valid,
            "error_count": len(errors),
            "errors": errors
        }
        
        if is_valid:
            self.audit_logger.info(f"Validation passed: {field_type}")
        else:
            self.audit_logger.warning(f"Validation failed: {field_type} - {errors}")
    
    def _log_schema_validation_result(self, schema: Dict[str, Any], is_valid: bool, errors: List[str]):
        """Log schema validation results for audit purposes"""
        log_data = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "schema_fields": list(schema.keys()),
            "is_valid": is_valid,
            "error_count": len(errors),
            "errors": errors
        }
        
        if is_valid:
            self.audit_logger.info(f"Schema validation passed: {len(schema)} fields")
        else:
            self.audit_logger.warning(f"Schema validation failed: {len(errors)} errors") 