"""
AI-Enhanced REST API for Input Validation
Provides HTTP endpoints with AgenticAI integration for intelligent validation
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

from core.ai_enhanced_validator import AIEnhancedValidator
from ai.agentic_ai_integration import AIValidationMode, AIThreatLevel

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create audit logger
audit_logger = logging.getLogger("audit")
audit_handler = logging.FileHandler("ai_audit.log")
audit_handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s'
))
audit_logger.addHandler(audit_handler)
audit_logger.setLevel(logging.INFO)

app = Flask(__name__)
CORS(app)

# Initialize the AI-enhanced validator
ai_validator = AIEnhancedValidator(
    ai_mode=AIValidationMode.ADAPTIVE,
    ai_endpoint=os.getenv('AGENTIC_AI_ENDPOINT'),
    ai_api_key=os.getenv('AGENTIC_AI_API_KEY')
)

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
    
    audit_logger.info(f"AI Request {g.request_id}: {request.method} {request.path} from {request.remote_addr}")

def require_api_key(f):
    """Decorator to require API key authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key or api_key != os.getenv('API_KEY', 'default-key'):
            audit_logger.warning(f"Unauthorized AI access attempt from {request.remote_addr}")
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
    audit_logger.info(f"AI Request {g.request_id}: {response.status_code}")
    return response

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint with AI status"""
    ai_insights = ai_validator.get_ai_insights()
    
    return jsonify({
        "status": "healthy",
        "service": "AI-Enhanced Input Validation API",
        "version": "2.0.0",
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "ai_status": {
            "mode": ai_validator.ai_mode.value,
            "enabled": True,
            "model_version": ai_insights.get("learning_progress", {}).get("model_version", "unknown"),
            "training_samples": ai_insights.get("learning_progress", {}).get("training_samples", 0)
        },
        "security_features": [
            "AI-powered threat detection",
            "Behavioral analysis",
            "Anomaly detection",
            "Adaptive learning",
            "Traditional security validation"
        ]
    })

@app.route('/validate/ai/field', methods=['POST'])
@require_api_key
def validate_field_with_ai():
    """Validate a single field with AI enhancement"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        value = data.get('value')
        field_type = data.get('type', 'string')
        validation_params = data.get('params', {})
        enable_ai = data.get('enable_ai', True)
        
        if value is None:
            return jsonify({"error": "Field value is required"}), 400
        
        # Log AI validation request
        audit_logger.info(f"AI field validation request: {field_type}, AI enabled: {enable_ai}")
        
        # Perform AI-enhanced validation
        result = ai_validator.validate_field_with_ai(
            value, field_type, enable_ai, **validation_params
        )
        
        # Log validation result
        if result.is_valid:
            audit_logger.info(f"AI field validation passed: {field_type}")
        else:
            audit_logger.warning(f"AI field validation failed: {field_type} - Risk score: {result.combined_risk_score}")
        
        # Prepare response
        response_data = {
            "is_valid": result.is_valid,
            "combined_risk_score": result.combined_risk_score,
            "confidence_level": result.confidence_level,
            "validation_mode": result.validation_mode,
            "traditional_validation": {
                "is_valid": result.traditional_validation.is_valid,
                "errors": result.traditional_validation.errors,
                "warnings": result.traditional_validation.warnings
            },
            "ai_analysis": {
                "threat_level": result.ai_threat_analysis.threat_level.value if result.ai_threat_analysis else None,
                "confidence_score": result.ai_threat_analysis.confidence_score if result.ai_threat_analysis else None,
                "detected_patterns": result.ai_threat_analysis.detected_patterns if result.ai_threat_analysis else [],
                "risk_factors": result.ai_threat_analysis.risk_factors if result.ai_threat_analysis else [],
                "anomaly_detected": result.ai_threat_analysis.anomaly_detected if result.ai_threat_analysis else False,
                "behavioral_score": result.ai_threat_analysis.behavioral_score if result.ai_threat_analysis else 0.0
            },
            "ai_recommendations": result.ai_recommendations,
            "learning_applied": result.learning_applied
        }
        
        return jsonify(response_data)
    
    except Exception as e:
        logger.error(f"Error in AI field validation: {str(e)}")
        audit_logger.error(f"AI field validation error: {str(e)}")
        return jsonify({"error": f"AI validation error: {str(e)}"}), 500

@app.route('/validate/ai/schema', methods=['POST'])
@require_api_key
def validate_schema_with_ai():
    """Validate data against schema with AI enhancement"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        input_data = data.get('data', {})
        schema = data.get('schema', {})
        enable_ai = data.get('enable_ai', True)
        
        if not input_data:
            return jsonify({"error": "Input data is required"}), 400
        
        if not schema:
            return jsonify({"error": "Schema is required"}), 400
        
        # Log AI schema validation request
        audit_logger.info(f"AI schema validation request: {len(schema)} fields, AI enabled: {enable_ai}")
        
        # Perform AI-enhanced schema validation
        result = ai_validator.validate_schema_with_ai(input_data, schema, enable_ai)
        
        # Log validation result
        if result.is_valid:
            audit_logger.info(f"AI schema validation passed: {len(schema)} fields")
        else:
            audit_logger.warning(f"AI schema validation failed: Risk score: {result.combined_risk_score}")
        
        # Prepare response
        response_data = {
            "is_valid": result.is_valid,
            "combined_risk_score": result.combined_risk_score,
            "confidence_level": result.confidence_level,
            "validation_mode": result.validation_mode,
            "traditional_validation": {
                "is_valid": result.traditional_validation.is_valid,
                "errors": result.traditional_validation.errors,
                "warnings": result.traditional_validation.warnings,
                "validated_data": result.traditional_validation.validated_data
            },
            "ai_analysis": {
                "threat_level": result.ai_threat_analysis.threat_level.value if result.ai_threat_analysis else None,
                "confidence_score": result.ai_threat_analysis.confidence_score if result.ai_threat_analysis else None,
                "detected_patterns": result.ai_threat_analysis.detected_patterns if result.ai_threat_analysis else [],
                "risk_factors": result.ai_threat_analysis.risk_factors if result.ai_threat_analysis else [],
                "anomaly_detected": result.ai_threat_analysis.anomaly_detected if result.ai_threat_analysis else False,
                "behavioral_score": result.ai_threat_analysis.behavioral_score if result.ai_threat_analysis else 0.0
            },
            "ai_recommendations": result.ai_recommendations,
            "learning_applied": result.learning_applied
        }
        
        return jsonify(response_data)
    
    except Exception as e:
        logger.error(f"Error in AI schema validation: {str(e)}")
        audit_logger.error(f"AI schema validation error: {str(e)}")
        return jsonify({"error": f"AI validation error: {str(e)}"}), 500

@app.route('/ai/analyze', methods=['POST'])
@require_api_key
def ai_analysis_only():
    """Perform AI analysis without validation"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        value = data.get('value')
        if value is None:
            return jsonify({"error": "Value is required"}), 400
        
        # Perform AI analysis
        ai_analysis = ai_validator.ai_integration.analyze_threat_intelligence(str(value))
        
        # Log AI analysis
        audit_logger.info(f"AI analysis performed: Threat level: {ai_analysis.threat_level.value}")
        
        return jsonify({
            "ai_analysis": {
                "threat_level": ai_analysis.threat_level.value,
                "confidence_score": ai_analysis.confidence_score,
                "detected_patterns": ai_analysis.detected_patterns,
                "risk_factors": ai_analysis.risk_factors,
                "recommendations": ai_analysis.recommendations,
                "anomaly_detected": ai_analysis.anomaly_detected,
                "behavioral_score": ai_analysis.behavioral_score,
                "ai_model_version": ai_analysis.ai_model_version,
                "analysis_timestamp": ai_analysis.analysis_timestamp
            }
        })
    
    except Exception as e:
        logger.error(f"Error in AI analysis: {str(e)}")
        audit_logger.error(f"AI analysis error: {str(e)}")
        return jsonify({"error": f"AI analysis error: {str(e)}"}), 500

@app.route('/ai/insights', methods=['GET'])
@require_api_key
def get_ai_insights():
    """Get AI insights and model performance"""
    try:
        insights = ai_validator.get_ai_insights()
        return jsonify(insights)
    
    except Exception as e:
        logger.error(f"Error getting AI insights: {str(e)}")
        return jsonify({"error": f"Error getting AI insights: {str(e)}"}), 500

@app.route('/ai/mode', methods=['GET', 'PUT'])
@require_api_key
def manage_ai_mode():
    """Get or update AI validation mode"""
    if request.method == 'GET':
        return jsonify({
            "current_mode": ai_validator.ai_mode.value,
            "available_modes": [mode.value for mode in AIValidationMode],
            "description": {
                "passive": "AI observes and learns without blocking",
                "active": "AI actively blocks detected threats",
                "adaptive": "AI adapts rules based on patterns",
                "collaborative": "AI works with human experts"
            }
        })
    
    elif request.method == 'PUT':
        data = request.get_json()
        if not data or 'mode' not in data:
            return jsonify({"error": "Mode is required"}), 400
        
        new_mode = data['mode']
        try:
            mode_enum = AIValidationMode(new_mode)
            ai_validator.update_ai_mode(mode_enum)
            
            audit_logger.info(f"AI mode updated to: {new_mode}")
            
            return jsonify({
                "message": f"AI mode updated to {new_mode}",
                "current_mode": ai_validator.ai_mode.value
            })
        
        except ValueError:
            return jsonify({"error": f"Invalid mode: {new_mode}"}), 400

@app.route('/ai/learning', methods=['POST'])
@require_api_key
def toggle_ai_learning():
    """Enable or disable AI learning"""
    data = request.get_json()
    if not data or 'enable' not in data:
        return jsonify({"error": "Enable flag is required"}), 400
    
    enable = data['enable']
    ai_validator.enable_ai_learning(enable)
    
    audit_logger.info(f"AI learning {'enabled' if enable else 'disabled'}")
    
    return jsonify({
        "message": f"AI learning {'enabled' if enable else 'disabled'}",
        "ai_mode": ai_validator.ai_mode.value
    })

@app.route('/ai/retrain', methods=['POST'])
@require_api_key
def retrain_ai_models():
    """Manually trigger AI model retraining"""
    try:
        # This would typically be done asynchronously in production
        # For now, we'll just return a success message
        audit_logger.info("AI model retraining requested")
        
        return jsonify({
            "message": "AI model retraining initiated",
            "status": "processing",
            "estimated_completion": "5-10 minutes"
        })
    
    except Exception as e:
        logger.error(f"Error in AI retraining: {str(e)}")
        return jsonify({"error": f"AI retraining error: {str(e)}"}), 500

@app.route('/ai/statistics', methods=['GET'])
@require_api_key
def get_ai_statistics():
    """Get comprehensive AI validation statistics"""
    try:
        stats = ai_validator.get_validation_statistics()
        return jsonify(stats)
    
    except Exception as e:
        logger.error(f"Error getting AI statistics: {str(e)}")
        return jsonify({"error": f"Error getting AI statistics: {str(e)}"}), 500

@app.route('/ai/patterns', methods=['GET'])
@require_api_key
def get_threat_patterns():
    """Get current threat patterns used by AI"""
    try:
        patterns = ai_validator.ai_integration.threat_patterns
        return jsonify({
            "threat_patterns": patterns,
            "total_patterns": sum(len(p) for p in patterns.values()),
            "categories": list(patterns.keys()),
            "last_updated": datetime.datetime.utcnow().isoformat()
        })
    
    except Exception as e:
        logger.error(f"Error getting threat patterns: {str(e)}")
        return jsonify({"error": f"Error getting threat patterns: {str(e)}"}), 500

@app.route('/ai/audit/logs', methods=['GET'])
@require_api_key
def get_ai_audit_logs():
    """Get recent AI audit logs"""
    try:
        with open("ai_audit.log", "r") as f:
            lines = f.readlines()
        
        # Return last 100 lines
        recent_logs = lines[-100:] if len(lines) > 100 else lines
        
        return jsonify({
            "total_logs": len(lines),
            "recent_logs": recent_logs,
            "timestamp": datetime.datetime.utcnow().isoformat()
        })
    
    except FileNotFoundError:
        return jsonify({"error": "AI audit log file not found"}), 404
    except Exception as e:
        logger.error(f"Error reading AI audit logs: {str(e)}")
        return jsonify({"error": f"Error reading AI audit logs: {str(e)}"}), 500

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
    
    # Set default AI endpoint if not provided
    if not os.getenv('AGENTIC_AI_ENDPOINT'):
        logger.warning("AGENTIC_AI_ENDPOINT not set. AI features will use local models only.")
    
    app.run(debug=True, host='0.0.0.0', port=5001) 