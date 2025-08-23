"""
AI-Enhanced Python Client for Input Validation
Provides easy-to-use Python interface for AI-powered validation
"""

import requests
import json
from typing import Any, Dict, List, Union, Optional
from dataclasses import dataclass
import yaml


@dataclass
class AIThreatAnalysis:
    """AI threat analysis result"""
    threat_level: str
    confidence_score: float
    detected_patterns: List[str]
    risk_factors: List[str]
    recommendations: List[str]
    anomaly_detected: bool
    behavioral_score: float
    ai_model_version: str
    analysis_timestamp: str


@dataclass
class AIValidationResult:
    """AI-enhanced validation result"""
    is_valid: bool
    combined_risk_score: float
    confidence_level: str
    validation_mode: str
    traditional_validation: Dict[str, Any]
    ai_analysis: AIThreatAnalysis
    ai_recommendations: List[str]
    learning_applied: bool


class AIEnhancedInputValidatorClient:
    """AI-enhanced Python client for the Input Validation service"""
    
    def __init__(self, 
                 base_url: str = "http://localhost:5001",
                 api_key: str = None):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key or "default-key"
        self.session = requests.Session()
        self.session.headers.update({
            'X-API-Key': self.api_key,
            'Content-Type': 'application/json'
        })
    
    def _make_request(self, endpoint: str, method: str = 'GET', data: Dict = None) -> Dict:
        """Make HTTP request to the validation service"""
        url = f"{self.base_url}{endpoint}"
        
        try:
            if method.upper() == 'GET':
                response = self.session.get(url)
            elif method.upper() == 'POST':
                response = self.session.post(url, json=data)
            elif method.upper() == 'PUT':
                response = self.session.put(url, json=data)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            response.raise_for_status()
            return response.json()
        
        except requests.exceptions.RequestException as e:
            raise ConnectionError(f"Failed to connect to validation service: {e}")
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid response from validation service: {e}")
    
    def validate_field_with_ai(self, 
                              value: Any, 
                              field_type: str, 
                              enable_ai: bool = True,
                              **kwargs) -> AIValidationResult:
        """Validate a single field with AI enhancement"""
        data = {
            "value": value,
            "type": field_type,
            "params": kwargs,
            "enable_ai": enable_ai
        }
        
        response = self._make_request('/validate/ai/field', 'POST', data)
        
        # Parse AI analysis
        ai_analysis_data = response.get('ai_analysis', {})
        ai_analysis = AIThreatAnalysis(
            threat_level=ai_analysis_data.get('threat_level', 'unknown'),
            confidence_score=ai_analysis_data.get('confidence_score', 0.0),
            detected_patterns=ai_analysis_data.get('detected_patterns', []),
            risk_factors=ai_analysis_data.get('risk_factors', []),
            recommendations=ai_analysis_data.get('recommendations', []),
            anomaly_detected=ai_analysis_data.get('anomaly_detected', False),
            behavioral_score=ai_analysis_data.get('behavioral_score', 0.0),
            ai_model_version=ai_analysis_data.get('ai_model_version', 'unknown'),
            analysis_timestamp=ai_analysis_data.get('analysis_timestamp', '')
        )
        
        return AIValidationResult(
            is_valid=response['is_valid'],
            combined_risk_score=response['combined_risk_score'],
            confidence_level=response['confidence_level'],
            validation_mode=response['validation_mode'],
            traditional_validation=response['traditional_validation'],
            ai_analysis=ai_analysis,
            ai_recommendations=response.get('ai_recommendations', []),
            learning_applied=response.get('learning_applied', False)
        )
    
    def validate_schema_with_ai(self, 
                               data: Dict[str, Any], 
                               schema: Dict[str, Any],
                               enable_ai: bool = True) -> AIValidationResult:
        """Validate data against schema with AI enhancement"""
        request_data = {
            "data": data,
            "schema": schema,
            "enable_ai": enable_ai
        }
        
        response = self._make_request('/validate/ai/schema', 'POST', request_data)
        
        # Parse AI analysis
        ai_analysis_data = response.get('ai_analysis', {})
        ai_analysis = AIThreatAnalysis(
            threat_level=ai_analysis_data.get('threat_level', 'unknown'),
            confidence_score=ai_analysis_data.get('confidence_score', 0.0),
            detected_patterns=ai_analysis_data.get('detected_patterns', []),
            risk_factors=ai_analysis_data.get('risk_factors', []),
            recommendations=ai_analysis_data.get('recommendations', []),
            anomaly_detected=ai_analysis_data.get('anomaly_detected', False),
            behavioral_score=ai_analysis_data.get('behavioral_score', 0.0),
            ai_model_version=ai_analysis_data.get('ai_model_version', 'unknown'),
            analysis_timestamp=ai_analysis_data.get('analysis_timestamp', '')
        )
        
        return AIValidationResult(
            is_valid=response['is_valid'],
            combined_risk_score=response['combined_risk_score'],
            confidence_level=response['confidence_level'],
            validation_mode=response['validation_mode'],
            traditional_validation=response['traditional_validation'],
            ai_analysis=ai_analysis,
            ai_recommendations=response.get('ai_recommendations', []),
            learning_applied=response.get('learning_applied', False)
        )
    
    def analyze_with_ai(self, value: str) -> AIThreatAnalysis:
        """Perform AI analysis without validation"""
        data = {"value": value}
        
        response = self._make_request('/ai/analyze', 'POST', data)
        ai_analysis_data = response.get('ai_analysis', {})
        
        return AIThreatAnalysis(
            threat_level=ai_analysis_data.get('threat_level', 'unknown'),
            confidence_score=ai_analysis_data.get('confidence_score', 0.0),
            detected_patterns=ai_analysis_data.get('detected_patterns', []),
            risk_factors=ai_analysis_data.get('risk_factors', []),
            recommendations=ai_analysis_data.get('recommendations', []),
            anomaly_detected=ai_analysis_data.get('anomaly_detected', False),
            behavioral_score=ai_analysis_data.get('behavioral_score', 0.0),
            ai_model_version=ai_analysis_data.get('ai_model_version', 'unknown'),
            analysis_timestamp=ai_analysis_data.get('analysis_timestamp', '')
        )
    
    def get_ai_insights(self) -> Dict[str, Any]:
        """Get AI insights and model performance"""
        return self._make_request('/ai/insights')
    
    def get_ai_mode(self) -> Dict[str, Any]:
        """Get current AI validation mode"""
        return self._make_request('/ai/mode')
    
    def update_ai_mode(self, mode: str) -> Dict[str, Any]:
        """Update AI validation mode"""
        data = {"mode": mode}
        return self._make_request('/ai/mode', 'PUT', data)
    
    def toggle_ai_learning(self, enable: bool) -> Dict[str, Any]:
        """Enable or disable AI learning"""
        data = {"enable": enable}
        return self._make_request('/ai/learning', 'POST', data)
    
    def retrain_ai_models(self) -> Dict[str, Any]:
        """Manually trigger AI model retraining"""
        return self._make_request('/ai/retrain', 'POST')
    
    def get_ai_statistics(self) -> Dict[str, Any]:
        """Get comprehensive AI validation statistics"""
        return self._make_request('/ai/statistics')
    
    def get_threat_patterns(self) -> Dict[str, Any]:
        """Get current threat patterns used by AI"""
        return self._make_request('/ai/patterns')
    
    def get_ai_audit_logs(self) -> Dict[str, Any]:
        """Get recent AI audit logs"""
        return self._make_request('/ai/audit/logs')
    
    def health_check(self) -> Dict[str, Any]:
        """Check service health and AI status"""
        return self._make_request('/health')


# Convenience functions for common AI validations
def validate_email_with_ai(email: str, 
                          client: AIEnhancedInputValidatorClient = None,
                          enable_ai: bool = True) -> AIValidationResult:
    """Validate an email address with AI enhancement"""
    if client is None:
        client = AIEnhancedInputValidatorClient()
    return client.validate_field_with_ai(email, 'email', enable_ai)


def validate_url_with_ai(url: str, 
                        client: AIEnhancedInputValidatorClient = None,
                        enable_ai: bool = True) -> AIValidationResult:
    """Validate a URL with AI enhancement"""
    if client is None:
        client = AIEnhancedInputValidatorClient()
    return client.validate_field_with_ai(url, 'url', enable_ai)


def validate_user_input_with_ai(input_value: str,
                               client: AIEnhancedInputValidatorClient = None,
                               enable_ai: bool = True) -> AIValidationResult:
    """Validate user input with comprehensive AI analysis"""
    if client is None:
        client = AIEnhancedInputValidatorClient()
    
    # Use string validation with all security flags enabled
    return client.validate_field_with_ai(
        input_value, 
        'string', 
        enable_ai,
        sql_safe=True,
        xss_safe=True,
        command_safe=True,
        path_safe=True
    )


def analyze_security_threats(input_value: str,
                           client: AIEnhancedInputValidatorClient = None) -> AIThreatAnalysis:
    """Analyze input for security threats using AI"""
    if client is None:
        client = AIEnhancedInputValidatorClient()
    return client.analyze_with_ai(input_value)


def validate_user_registration_with_ai(user_data: Dict[str, Any],
                                     client: AIEnhancedInputValidatorClient = None,
                                     enable_ai: bool = True) -> AIValidationResult:
    """Validate user registration data with AI enhancement"""
    if client is None:
        client = AIEnhancedInputValidatorClient()
    
    # Define security-focused schema
    schema = {
        "username": {
            "type": "string",
            "required": True,
            "min_length": 3,
            "max_length": 30,
            "pattern": "^[a-zA-Z0-9_]+$",
            "sql_safe": True,
            "xss_safe": True
        },
        "email": {
            "type": "email",
            "required": True,
            "sql_safe": True,
            "xss_safe": True
        },
        "password": {
            "type": "string",
            "required": True,
            "min_length": 8,
            "pattern": "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$"
        },
        "full_name": {
            "type": "string",
            "required": True,
            "max_length": 100,
            "sql_safe": True,
            "xss_safe": True
        }
    }
    
    return client.validate_schema_with_ai(user_data, schema, enable_ai)


def validate_file_upload_with_ai(file_info: Dict[str, Any],
                                client: AIEnhancedInputValidatorClient = None,
                                enable_ai: bool = True) -> AIValidationResult:
    """Validate file upload information with AI enhancement"""
    if client is None:
        client = AIEnhancedInputValidatorClient()
    
    # Define file upload schema
    schema = {
        "filename": {
            "type": "string",
            "required": True,
            "max_length": 255,
            "path_safe": True,
            "sql_safe": True
        },
        "file_size": {
            "type": "integer",
            "required": True,
            "min_value": 1,
            "max_value": 10485760  # 10MB
        },
        "file_type": {
            "type": "string",
            "required": True,
            "allowed_values": [
                "image/jpeg", "image/png", "image/gif", "application/pdf",
                "text/plain", "application/msword"
            ]
        },
        "upload_path": {
            "type": "string",
            "required": False,
            "path_safe": True,
            "sql_safe": True
        }
    }
    
    return client.validate_schema_with_ai(file_info, schema, enable_ai)


# Example usage and demonstration
if __name__ == "__main__":
    # Example of using the AI-enhanced client
    client = AIEnhancedInputValidatorClient()
    
    # Test AI-enhanced email validation
    print("🔍 Testing AI-Enhanced Email Validation...")
    result = validate_email_with_ai("test@example.com", client)
    print(f"Valid: {result.is_valid}")
    print(f"Risk Score: {result.combined_risk_score}")
    print(f"AI Threat Level: {result.ai_analysis.threat_level}")
    
    # Test AI threat analysis
    print("\n🚨 Testing AI Threat Analysis...")
    threat_analysis = analyze_security_threats("'; DROP TABLE users; --")
    print(f"Threat Level: {threat_analysis.threat_level}")
    print(f"Detected Patterns: {threat_analysis.detected_patterns}")
    print(f"Recommendations: {threat_analysis.recommendations}")
    
    # Test AI-enhanced schema validation
    print("\n📋 Testing AI-Enhanced Schema Validation...")
    user_data = {
        "username": "john_doe",
        "email": "john@example.com",
        "password": "SecurePass123!",
        "full_name": "John Doe"
    }
    
    schema_result = validate_user_registration_with_ai(user_data, client)
    print(f"Valid: {schema_result.is_valid}")
    print(f"Risk Score: {schema_result.combined_risk_score}")
    print(f"AI Confidence: {schema_result.ai_analysis.confidence_score}") 