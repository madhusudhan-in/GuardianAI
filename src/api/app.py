"""
REST API for Input Validation with Security Features
Provides HTTP endpoints for validating input data with security validation
"""

from flask import Flask, request, jsonify, g
from flask_cors import CORS
import json
import logging
import datetime
import hashlib
from typing import Dict, Any
import os
from functools import wraps

# Add parent directory to path
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.validator import InputValidator, ValidationResult

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create audit logger
audit_logger = logging.getLogger("audit")
audit_handler = logging.FileHandler("audit.log")
audit_handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s'
))
audit_logger.addHandler(audit_handler)
audit_logger.setLevel(logging.INFO)

app = Flask(__name__)
CORS(app)  # Enable CORS for cross-origin requests

# Initialize the validator
validator = InputValidator()

# Security configuration
SECURITY_HEADERS = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'"
}

def add_security_headers(response):
    """Add security headers to response"""
    for header, value in SECURITY_HEADERS.items():
        response.headers[header] = value
    return response

def log_request_info():
    """Log request information for audit"""
    g.request_id = hashlib.md5(
        f"{request.remote_addr}{datetime.datetime.utcnow().isoformat()}".encode()
    ).hexdigest()[:8]
    
    audit_logger.info(f"Request {g.request_id}: {request.method} {request.path} from {request.remote_addr}")

def require_api_key(f):
    """Decorator to require API key authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key or api_key != os.getenv('API_KEY', 'default-key'):
            audit_logger.warning(f"Unauthorized access attempt from {request.remote_addr}")
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def before_request():
    """Log request information before processing"""
    log_request_info()

@app.after_request
def after_request(response):
    """Add security headers and log response"""
    response = add_security_headers(response)
    
    # Log response for audit
    audit_logger.info(f"Request {g.request_id}: {response.status_code}")
    
    return response

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "Input Validation API",
        "version": "1.0.0",
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "security_features": [
            "SQL injection detection",
            "XSS detection", 
            "Command injection detection",
            "Path traversal detection"
        ]
    })

@app.route('/validate/field', methods=['POST'])
@require_api_key
def validate_field():
    """Validate a single field with security validation"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        value = data.get('value')
        field_type = data.get('type', 'string')
        validation_params = data.get('params', {})
        
        # Security validation flags
        security_flags = {
            'sql_safe': data.get('sql_safe', False),
            'xss_safe': data.get('xss_safe', False),
            'command_safe': data.get('command_safe', False),
            'path_safe': data.get('path_safe', False)
        }
        
        if value is None:
            return jsonify({"error": "Field value is required"}), 400
        
        # Log validation request
        audit_logger.info(f"Field validation request: {field_type} with security flags: {security_flags}")
        
        result = validator.validate_field(value, field_type, **validation_params, **security_flags)
        
        # Log validation result
        if result.is_valid:
            audit_logger.info(f"Field validation passed: {field_type}")
        else:
            audit_logger.warning(f"Field validation failed: {field_type} - {result.errors}")
        
        response_data = {
            "is_valid": result.is_valid,
            "errors": result.errors,
            "warnings": result.warnings,
            "validated_data": result.validated_data,
            "metadata": result.metadata
        }
        
        if result.security_result:
            response_data["security_result"] = {
                "is_safe": result.security_result.is_safe,
                "threat_level": result.security_result.threat_level.value,
                "detected_threats": result.security_result.detected_threats,
                "confidence_score": result.security_result.confidence_score,
                "recommendations": result.security_result.recommendations
            }
        
        return jsonify(response_data)
    
    except Exception as e:
        logger.error(f"Error validating field: {str(e)}")
        audit_logger.error(f"Field validation error: {str(e)}")
        return jsonify({"error": f"Validation error: {str(e)}"}), 500

@app.route('/validate/schema', methods=['POST'])
@require_api_key
def validate_schema():
    """Validate data against a schema with security validation"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        input_data = data.get('data', {})
        schema = data.get('schema', {})
        
        if not input_data:
            return jsonify({"error": "Input data is required"}), 400
        
        if not schema:
            return jsonify({"error": "Schema is required"}), 400
        
        # Log schema validation request
        audit_logger.info(f"Schema validation request: {len(schema)} fields")
        
        result = validator.validate_schema(input_data, schema)
        
        # Log validation result
        if result.is_valid:
            audit_logger.info(f"Schema validation passed: {len(schema)} fields")
        else:
            audit_logger.warning(f"Schema validation failed: {len(result.errors)} errors")
        
        response_data = {
            "is_valid": result.is_valid,
            "errors": result.errors,
            "warnings": result.warnings,
            "validated_data": result.validated_data,
            "metadata": result.metadata
        }
        
        if result.metadata.get("security_results"):
            response_data["security_results"] = [
                {
                    "is_safe": sr.is_safe,
                    "threat_level": sr.threat_level.value,
                    "detected_threats": sr.detected_threats,
                    "confidence_score": sr.confidence_score,
                    "recommendations": sr.recommendations
                }
                for sr in result.metadata["security_results"]
            ]
        
        return jsonify(response_data)
    
    except Exception as e:
        logger.error(f"Error validating schema: {str(e)}")
        audit_logger.error(f"Schema validation error: {str(e)}")
        return jsonify({"error": f"Validation error: {str(e)}"}), 500

@app.route('/validate/security', methods=['POST'])
@require_api_key
def validate_security():
    """Comprehensive security validation endpoint"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        value = data.get('value')
        if value is None:
            return jsonify({"error": "Value is required"}), 400
        
        if not isinstance(value, str):
            return jsonify({"error": "Value must be a string for security validation"}), 400
        
        # Perform all security validations
        sql_result = validator.security_validator.validate_sql_safety(value)
        xss_result = validator.security_validator.validate_xss_safety(value)
        command_result = validator.security_validator.validate_command_safety(value)
        path_result = validator.security_validator.validate_path_safety(value)
        
        # Aggregate results
        all_safe = all([
            sql_result.is_safe,
            xss_result.is_safe,
            command_result.is_safe,
            path_result.is_safe
        ])
        
        # Determine overall threat level
        threat_levels = [
            sql_result.threat_level,
            xss_result.threat_level,
            command_result.threat_level,
            path_result.threat_level
        ]
        
        overall_threat_level = max(threat_levels, key=lambda x: list(SecurityThreatLevel).index(x))
        
        # Collect all detected threats
        all_threats = []
        if not sql_result.is_safe:
            all_threats.extend([f"SQL: {t}" for t in sql_result.detected_threats])
        if not xss_result.is_safe:
            all_threats.extend([f"XSS: {t}" for t in xss_result.detected_threats])
        if not command_result.is_safe:
            all_threats.extend([f"Command: {t}" for t in command_result.detected_threats])
        if not path_result.is_safe:
            all_threats.extend([f"Path: {t}" for t in path_result.detected_threats])
        
        # Log security validation
        if all_safe:
            audit_logger.info(f"Security validation passed for value")
        else:
            audit_logger.warning(f"Security validation failed: {all_threats}")
        
        return jsonify({
            "is_safe": all_safe,
            "overall_threat_level": overall_threat_level.value,
            "validation_results": {
                "sql_injection": {
                    "is_safe": sql_result.is_safe,
                    "threat_level": sql_result.threat_level.value,
                    "detected_threats": sql_result.detected_threats,
                    "confidence_score": sql_result.confidence_score,
                    "recommendations": sql_result.recommendations
                },
                "xss": {
                    "is_safe": xss_result.is_safe,
                    "threat_level": xss_result.threat_level.value,
                    "detected_threats": xss_result.detected_threats,
                    "confidence_score": xss_result.confidence_score,
                    "recommendations": xss_result.recommendations
                },
                "command_injection": {
                    "is_safe": command_result.is_safe,
                    "threat_level": command_result.threat_level.value,
                    "detected_threats": command_result.detected_threats,
                    "confidence_score": command_result.confidence_score,
                    "recommendations": command_result.recommendations
                },
                "path_traversal": {
                    "is_safe": path_result.is_safe,
                    "threat_level": path_result.threat_level.value,
                    "detected_threats": path_result.detected_threats,
                    "confidence_score": path_result.confidence_score,
                    "recommendations": path_result.recommendations
                }
            },
            "all_detected_threats": all_threats
        })
    
    except Exception as e:
        logger.error(f"Error in security validation: {str(e)}")
        audit_logger.error(f"Security validation error: {str(e)}")
        return jsonify({"error": f"Security validation error: {str(e)}"}), 500

@app.route('/rules', methods=['GET'])
def list_rules():
    """List available validation rules"""
    rules = list(validator.rules.keys())
    custom_rules = list(validator.custom_validators.keys())
    
    return jsonify({
        "builtin_rules": rules,
        "custom_rules": custom_rules,
        "total_rules": len(rules) + len(custom_rules),
        "security_rules": [
            "sql_safe", "xss_safe", "command_safe", "path_safe"
        ]
    })

@app.route('/rules/custom', methods=['POST'])
@require_api_key
def add_custom_rule():
    """Add a custom validation rule"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        rule_name = data.get('name')
        rule_code = data.get('code')
        
        if not rule_name or not rule_code:
            return jsonify({"error": "Rule name and code are required"}), 400
        
        # Note: In production, this should be properly sandboxed
        try:
            # Create a simple function from the code
            exec(f"def {rule_name}_validator(value):\n{rule_code}")
            custom_validator = locals()[f"{rule_name}_validator"]
            validator.add_custom_rule(rule_name, custom_validator)
            
            audit_logger.info(f"Custom rule added: {rule_name}")
            
            return jsonify({
                "message": f"Custom rule '{rule_name}' added successfully",
                "rule_name": rule_name
            })
        
        except Exception as e:
            return jsonify({"error": f"Invalid rule code: {str(e)}"}), 400
    
    except Exception as e:
        logger.error(f"Error adding custom rule: {str(e)}")
        audit_logger.error(f"Error adding custom rule: {str(e)}")
        return jsonify({"error": f"Error adding custom rule: {str(e)}"}), 500

@app.route('/audit/logs', methods=['GET'])
@require_api_key
def get_audit_logs():
    """Get recent audit logs (for monitoring purposes)"""
    try:
        # Read recent audit logs
        with open("audit.log", "r") as f:
            lines = f.readlines()
        
        # Return last 100 lines
        recent_logs = lines[-100:] if len(lines) > 100 else lines
        
        return jsonify({
            "total_logs": len(lines),
            "recent_logs": recent_logs,
            "timestamp": datetime.datetime.utcnow().isoformat()
        })
    
    except FileNotFoundError:
        return jsonify({"error": "Audit log file not found"}), 404
    except Exception as e:
        logger.error(f"Error reading audit logs: {str(e)}")
        return jsonify({"error": f"Error reading audit logs: {str(e)}"}), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    # Set default API key if not provided
    if not os.getenv('API_KEY'):
        os.environ['API_KEY'] = 'default-key'
        logger.warning("Using default API key. Set API_KEY environment variable in production.")
    
    app.run(debug=True, host='0.0.0.0', port=5000) 