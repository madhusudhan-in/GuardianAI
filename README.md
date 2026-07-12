# GuardianAI - Universal Input Validation Module

[![CI](https://github.com/guardian-ai/guardianai/actions/workflows/python-package.yml/badge.svg)](https://github.com/guardian-ai/guardianai/actions/workflows/python-package.yml)

A comprehensive, security-focused input validation solution that provides multiple interfaces for applications written in any programming language or technology stack.

## Release
- Current version: 0.1.0
- Changelog: [CHANGELOG.md](CHANGELOG.md)

## Key Features

### 1. **Centralized Validation Rules Engine**
- **Security-First Validation**: Built-in protection against:
  - SQL injection attacks
  - Cross-Site Scripting (XSS)
  - Command injection
  - Path traversal attacks
- **Data Format Validation**: Email, phone, URL, IP address, UUID, JSON, etc.
- **Extensible Rule System**: Add custom validation logic
- **Context-Aware Parsing**: Intelligent threat detection

### 2. **AgenticAI Integration**
- **AI-Powered Threat Detection**: Machine learning-based attack pattern recognition
- **Behavioral Analysis**: Anomaly detection using isolation forests
- **Adaptive Learning**: Self-improving validation rules based on patterns
- **Intelligent Risk Scoring**: Combined traditional + AI risk assessment
- **Predictive Security**: Anticipate emerging threats before they become widespread

### 2. **Multi-Protocol Support**
- **REST API**: HTTP endpoints for web applications
- **Command Line Interface**: CLI tool for scripts and automation
- **Language Bindings**: SDKs for multiple programming languages
- **Real-time Validation**: Instant feedback and threat detection

### 3. **Language Bindings / SDKs**
- **Python**: Native Python client library
- **Node.js**: JavaScript/TypeScript client
- **Java**: Spring Boot integration (coming soon)
- **.NET**: C# client library (coming soon)
- **PHP**: Laravel integration (coming soon)

### 4. **Policy-as-Code Integration**
- **YAML/JSON Schemas**: Define validation policies declaratively
- **CI/CD Integration**: Automated policy enforcement
- **Version Control**: Track policy changes over time
- **Environment-Specific Rules**: Different policies for dev/staging/prod
- Example policy schema references are available in [docs/policies](docs/policies) and SIEM examples in [docs/siem](docs/siem)

### 5. **Audit Logging & Alerting**
- **Comprehensive Logging**: All validation attempts and failures
- **Security Event Tracking**: Monitor threat detection
- **SIEM Integration**: Compatible with Splunk, ELK Stack, etc.
- **Webhook Alerts**: Real-time notifications for critical violations

### 6. **Self-Updating Rule Sets**
- **Threat Intelligence**: Pull updates from security feeds
- **OWASP Integration**: Compatible with ModSecurity rules
- **Automated Updates**: Keep protection current
- **Custom Rule Management**: Add organization-specific rules

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Input Validation Module                   │
├─────────────────────────────────────────────────────────────┤
│     AgenticAI Intelligence Layer                          │
│  ├── ML Threat Detection                                  │
│  ├── Behavioral Analysis                                  │
│  ├── Anomaly Detection                                    │
│  ├── Adaptive Learning                                    │
│  └── Predictive Security                                  │
├─────────────────────────────────────────────────────────────┤
│  Core Security Engine                                      │
│  ├── SQL Injection Detection                              │
│  ├── XSS Detection                                        │
│  ├── Command Injection Detection                          │
│  ├── Path Traversal Detection                             │
│  └── Traditional Pattern Matching                         │
├─────────────────────────────────────────────────────────────┤
│  Interface Layer                                           │
│  ├── REST API (Flask) + AI Endpoints                      │
│  ├── Command Line Interface                               │
│  ├── AI-Enhanced Python Client                            │
│  ├── Node.js Client Library                               │
│  └── Language-Specific Wrappers                           │
├─────────────────────────────────────────────────────────────┤
│  Validation Rules Engine                                   │
│  ├── Built-in Security Rules                              │
│  ├── Data Format Rules                                    │
│  ├── AI-Generated Rules                                   │
│  ├── Custom Rules                                         │
│  └── Schema Validation                                     │
├─────────────────────────────────────────────────────────────┤
│  Audit & Monitoring                                        │
│  ├── Comprehensive Logging                                │
│  ├── AI Security Event Tracking                           │
│  ├── Behavioral Analytics                                 │
│  ├── SIEM Integration                                     │
│  └── AI-Powered Alerting                                  │
└─────────────────────────────────────────────────────────────┘
```

## Tech Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| **Core Engine** | Python 3.8+ | Validation logic & security rules |
| **API Server** | Flask | REST API endpoints |
| **Security Engine** | Python + Regex + ML | Threat detection |
| **Client Libraries** | Language-specific | Easy integration |
| **Storage** | File-based + Database | Logs & configurations |
| **Logging** | Python logging + ELK | Audit trails |
| **Deployment** | Docker + Kubernetes | Scalable deployment |
| **Security** | API Keys + TLS | Access control |

## Strategic Roadmap

The longer-term positioning plan for GuardianAI is documented in [docs/roadmap.md](docs/roadmap.md). It covers:
- benchmarking AI-assisted detection against rule-based detection on labeled datasets
- evaluating pip-installable packaging and a lightweight sidecar container
- deciding whether the project should be positioned as an internal accelerator or a standalone open-source project

## Quick Start

### Release and artifact notes
- The package is versioned through [src/__init__.py](src/__init__.py)
- AI model artifacts are stored as versioned JSON files with SHA-256 checksums rather than pickle payloads
- The current release is documented in [CHANGELOG.md](CHANGELOG.md)


### 1. **Installation**

```bash
# Clone the repository
git clone <repository-url>
cd Input-Validation

# Install dependencies
pip install -r requirements.txt
```

### 2. **Start the Validation Service**

```bash
# Set API key (optional, defaults to 'default-key')
export API_KEY=your-secure-api-key

# Start the REST API service
python src/api/app.py
```

The service will be available at `http://localhost:5000`

### 3. **Basic Usage**

#### Python Client
```python
from src.clients.python.input_validator_client import InputValidatorClient

# Create client
client = InputValidatorClient()

# Validate with security checks
result = client.validate_field("test@example.com", "email", sql_safe=True, xss_safe=True)
print(f"Valid: {result.is_valid}")

# Validate against schema
data = {"name": "John", "age": 30}
schema = {
    "name": {"type": "string", "min_length": 2, "sql_safe": True},
    "age": {"type": "integer", "min_value": 0, "max_value": 120}
}
result = client.validate_schema(data, schema)
```

#### REST API
```bash
# Validate a field
curl -X POST http://localhost:5000/validate/field \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "value": "test@example.com",
    "type": "email",
    "params": {"sql_safe": true, "xss_safe": true}
  }'

# Validate against schema
curl -X POST http://localhost:5000/validate/schema \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "data": {"name": "John", "age": 30},
    "schema": {
      "name": {"type": "string", "min_length": 2, "sql_safe": true},
      "age": {"type": "integer", "min_value": 0, "max_value": 120}
    }
  }'
```

#### Command Line
```bash
# Validate a single field
python src/cli/validator_cli.py field --value "test@example.com" --type email

# Validate files
python src/cli/validator_cli.py file --data data.json --schema schema.json
```

### 4. **🤖 AI-Enhanced Validation Examples**

#### AI-Powered Field Validation
```python
from src.clients.python.ai_enhanced_client import AIEnhancedInputValidatorClient

# Create AI-enhanced client
ai_client = AIEnhancedInputValidatorClient()

# AI-enhanced validation with threat intelligence
result = ai_client.validate_field_with_ai(
    "test@example.com", 
    "email", 
    enable_ai=True
)
print(f"Valid: {result.is_valid}")
print(f"Risk Score: {result.combined_risk_score}")
print(f"AI Threat Level: {result.ai_analysis.threat_level}")

# AI-powered security analysis
threat_analysis = ai_client.analyze_with_ai("'; DROP TABLE users; --")
print(f"Threat Level: {threat_analysis.threat_level}")
print(f"Detected Patterns: {threat_analysis.detected_patterns}")
```

#### AI-Enhanced Schema Validation
```python
# AI-enhanced user registration validation
user_data = {
    "username": "john_doe",
    "email": "john@example.com",
    "password": "SecurePass123!",
    "full_name": "John Doe"
}

result = ai_client.validate_schema_with_ai(user_data, user_schema, enable_ai=True)
print(f"AI Risk Assessment: {result.combined_risk_score}")
print(f"AI Recommendations: {result.ai_recommendations}")
```

#### REST API (AI Endpoints)
```bash
# AI-enhanced field validation
curl -X POST http://localhost:5001/validate/ai/field \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "value": "test@example.com",
    "type": "email",
    "enable_ai": true
  }'

# AI threat analysis only
curl -X POST http://localhost:5001/ai/analyze \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"value": "suspicious_input"}'

# Get AI insights and model performance
curl -X GET http://localhost:5001/ai/insights \
  -H "X-API-Key: your-api-key"
```

## Security Features

### **Threat Detection**
- **SQL Injection**: Detects common SQL attack patterns
- **XSS**: Identifies script injection attempts
- **Command Injection**: Prevents shell command execution
- **Path Traversal**: Blocks directory traversal attacks

### **Security Headers**
- Content Security Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- X-XSS-Protection
- HSTS

### **Access Control**
- API Key authentication
- Rate limiting (configurable)
- Audit logging for all requests
- Security event tracking

## Monitoring & Analytics

### **Audit Logging**
- All validation attempts logged
- Security threat detection events
- Performance metrics
- Error tracking

### **SIEM Integration**
- Structured log format
- Security event correlation
- Real-time alerting
- Compliance reporting

### **Metrics Dashboard**
- Validation success rates
- Threat detection statistics
- Performance monitoring
- Security posture assessment

## Configuration

### **Environment Variables**
```bash
# API Configuration
API_KEY=your-secure-api-key
FLASK_ENV=production
FLASK_DEBUG=false

# Security Configuration
SECURITY_LEVEL=high
THREAT_DETECTION=true
AUDIT_LOGGING=true

# Integration Configuration
SIEM_ENDPOINT=https://your-siem.com/api
WEBHOOK_URL=https://your-webhook.com/security

# AI Configuration
AGENTIC_AI_ENDPOINT=https://your-ai-service.com/api
AGENTIC_AI_API_KEY=your-ai-api-key
AI_VALIDATION_MODE=adaptive  # passive, active, adaptive, collaborative
ENABLE_AI_LEARNING=true

### **Schema Examples**

#### User Registration Schema
```json
{
  "username": {
    "type": "string",
    "required": true,
    "min_length": 3,
    "max_length": 30,
    "pattern": "^[a-zA-Z0-9_]+$",
    "sql_safe": true,
    "xss_safe": true
  },
  "email": {
    "type": "email",
    "required": true,
    "sql_safe": true,
    "xss_safe": true
  },
  "password": {
    "type": "string",
    "required": true,
    "min_length": 8,
    "pattern": "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$"
  }
}
```

#### File Upload Schema
```yaml
filename:
  type: string
  required: true
  max_length: 255
  path_safe: true
  sql_safe: true

file_size:
  type: integer
  required: true
  min_value: 1
  max_value: 10485760  # 10MB

file_type:
  type: string
  required: true
  allowed_values:
    - image/jpeg
    - image/png
    - image/gif
    - application/pdf
```

## Deployment

### **Docker Deployment**
```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "src.api.app:app"]
```

### **Kubernetes Deployment**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: input-validation
spec:
  replicas: 3
  selector:
    matchLabels:
      app: input-validation
  template:
    metadata:
      labels:
        app: input-validation
    spec:
      containers:
      - name: input-validation
        image: input-validation:latest
        ports:
        - containerPort: 5000
        env:
        - name: API_KEY
          valueFrom:
            secretKeyRef:
              name: api-secret
              key: api-key
```

## CI/CD Integration

### **GitHub Actions Example**
```yaml
name: Security Validation
on: [push, pull_request]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    
    - name: Run Input Validation
      run: |
        python src/cli/validator_cli.py file \
          --data test-data.json \
          --schema security-schema.json
    
    - name: Security Scan
      run: |
        python -m pytest tests/security/
```

## Performance & Scalability

### **Performance Metrics**
- **Response Time**: < 50ms for single field validation
- **Throughput**: 1000+ validations/second
- **Memory Usage**: < 100MB per instance
- **CPU Usage**: < 10% under normal load

### **Scaling Strategies**
- **Horizontal Scaling**: Multiple API instances
- **Load Balancing**: Distribute requests across instances
- **Caching**: Redis for frequently used schemas
- **Database**: PostgreSQL for audit logs and configurations

## Contributing

### **Development Setup**
```bash
# Clone and setup
git clone <repository-url>
cd Input-Validation

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run tests
python -m pytest

# Run linting
flake8 src/
black src/
```

### **Adding New Rules**
1. Extend the `SecurityValidator` class
2. Add new validation patterns
3. Update the `ValidationType` enum
4. Add tests for new functionality
5. Update documentation

## API Reference

### **Core Endpoints**
- `POST /validate/field` - Validate single field
- `POST /validate/schema` - Validate against schema
- `POST /validate/security` - Comprehensive security validation
- `GET /rules` - List available rules
- `POST /rules/custom` - Add custom rule
- `GET /audit/logs` - Get audit logs

### **Client Libraries**
- **Python**: `InputValidatorClient`
- **Node.js**: `InputValidatorClient`
- **Java**: Coming soon
- **.NET**: Coming soon

## Support & Troubleshooting

### **Common Issues**
1. **API Key Authentication**: Ensure `X-API-Key` header is set
2. **CORS Issues**: Check CORS configuration for web applications
3. **Performance**: Monitor memory and CPU usage
4. **Logging**: Check audit.log for detailed information

### **Getting Help**
- **Documentation**: Check this README and inline code comments
- **Issues**: Report bugs via GitHub Issues
- **Discussions**: Use GitHub Discussions for questions
- **Security**: Report security issues privately

## License

This project is licensed under the Apache License Version 2.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- **OWASP**: For security guidelines and best practices
- **Security Community**: For threat intelligence and patterns
- **Open Source Contributors**: For building amazing tools

---

**Built for securing applications everywhere** 
