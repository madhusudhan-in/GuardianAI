# GuardianAI — Universal Input Validation Module

[![CI](https://github.com/madhusudhan-in/GuardianAI/actions/workflows/python-package.yml/badge.svg)](https://github.com/madhusudhan-in/GuardianAI/actions)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)

A security-focused input validation library and service with optional AI-assisted threat detection for common input attacks (SQLi, XSS, command injection, path traversal). Designed to be language-agnostic via a REST API and SDKs.

## Table of Contents
- Quick Start
- Examples
- API Reference
- Configuration
- Security considerations
- Development & Testing
- Contributing
- License

## Release
- Current version: 0.1.0
- Changelog: [CHANGELOG.md](CHANGELOG.md)

## Key Features

### Centralized Validation Rules Engine
- Security-first validation with built-in protections against common classes of attacks:
  - SQL injection, Cross-Site Scripting (XSS), command injection, path traversal
- Data format validation: email, phone, URL, IP address, UUID, JSON, etc.
- Extensible rule system and custom rule management
- Context-aware parsing and threat scoring

### AI-Enhanced Detection (optional)
- AI-assisted threat detection and behavioral analysis (experimental)
- Adaptive learning is opt-in and can be disabled for privacy/compliance
- Risk scoring combines traditional rules + AI signals

### Multi-Protocol Support
- REST API (Flask)
- Command Line Interface (CLI)
- Language bindings / SDKs (Python, Node.js, others planned)
- Real-time validation and webhook alerts

### Audit, Monitoring & Policy-as-Code
- Audit logging for all validation attempts
- SIEM-friendly structured logs
- Declarative policy support (YAML/JSON schemas) and CI/CD policy checks

## Architecture

See `docs/` for detailed diagrams. High-level architecture:

- AI Intelligence Layer (optional)
- Core Security Engine (pattern & rule-based checks)
- Interface Layer (API, CLI, SDKs)
- Validation Rules Engine (built-in + custom rules)
- Audit & Monitoring (logs, SIEM, alerts)

## Quick Start

Clone, create a virtualenv, install, and run the API locally.

```bash
# Clone the repository
git clone https://github.com/madhusudhan-in/GuardianAI.git
cd GuardianAI

# Create a virtual environment and install dependencies
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

# Run the API locally
export API_KEY=your-secure-api-key
python -m src.api.app
```

The service will be available at http://localhost:5000 by default.

Docker (alternate):

```bash
# Build and run with Docker
docker build -t guardianai:latest .
docker run -e API_KEY=your-secure-api-key -p 5000:5000 guardianai:latest
```

Notes:
- The repo layout expects the main app at `src/api/app.py` exporting a WSGI `app` object or an entry point callable. Adjust run command if your entry differs (e.g., `gunicorn src.api.app:app`).

## Examples

### Example API response (field validation)

Request (POST /validate/field):

```json
{
  "value": "test@example.com",
  "type": "email",
  "params": {"sql_safe": true, "xss_safe": true}
}
```

Example response:

```json
{
  "is_valid": true,
  "errors": [],
  "risk_score": 0.02,
  "details": {
    "format": "email",
    "checks": {
      "sql_injection": "clean",
      "xss": "clean"
    }
  }
}
```

### Python client (local import)

```python
from src.clients.python.input_validator_client import InputValidatorClient

client = InputValidatorClient(api_key="your-secure-api-key", base_url="http://localhost:5000")
result = client.validate_field("test@example.com", "email", sql_safe=True, xss_safe=True)
print(result.is_valid, result.risk_score)
```

### Curl (REST)

```bash
curl -X POST http://localhost:5000/validate/field \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"value":"test@example.com","type":"email","params":{"sql_safe":true,"xss_safe":true}}'
```

### CLI

```bash
# Validate a single field
python src/cli/validator_cli.py field --value "test@example.com" --type email
```

## API Reference

Core endpoints (subject to change — prefer the code in `src/api` for canonical behaviour):
- POST /validate/field — Validate a single field
- POST /validate/schema — Validate data against a schema
- POST /validate/security — Comprehensive security validation
- GET /rules — List available built-in rules
- POST /rules/custom — Add a custom rule (admin)
- GET /audit/logs — Retrieve audit logs

## Configuration

Important environment variables (defaults are example-only):

```bash
API_KEY=your-secure-api-key
FLASK_ENV=production
FLASK_DEBUG=false
SECURITY_LEVEL=high
THREAT_DETECTION=true
AUDIT_LOGGING=true
SIEM_ENDPOINT=https://your-siem.com/api
WEBHOOK_URL=https://your-webhook.com/security
AGENTIC_AI_ENDPOINT=https://your-ai-service.com/api
AGENTIC_AI_API_KEY=your-ai-api-key
AI_VALIDATION_MODE=adaptive  # options: passive|active|adaptive|collaborative
ENABLE_AI_LEARNING=true
```

Privacy & compliance: adaptive learning and AI endpoints should only be enabled after understanding data collection, retention, and privacy implications for your deployment (GDPR, CCPA, etc.).

## Security considerations

- Claims about AI detection are experimental: treat AI outputs as advisory and keep traditional rule-based checks as the primary enforcement layer.
- Do not enable adaptive learning in production without reviewing privacy policy and obtaining consent where required.
- Store API keys and secrets in a secrets manager or Kubernetes Secrets; avoid committing them to source control.
- Add a SECURITY.md file describing responsible disclosure and contact details for security issues.

## Development & Testing

Development setup and testing commands:

```bash
# Create venv and install dev deps
python -m venv venv
source venv/bin/activate
python -m pip install -r requirements-dev.txt

# Run unit tests
python -m pytest

# Run linters
flake8 src/
black src/
```

CI: consider adding a lightweight smoke test that starts the app and verifies `/health` or `/validate/field`.

## Contributing

Please open issues for bugs or feature requests. For code contributions, add tests and update documentation.

Suggested repository files to add or update:
- CONTRIBUTING.md (how to contribute)
- CODE_OF_CONDUCT.md
- SECURITY.md (vulnerability disclosure)
- docs/ (examples, policies, AI benchmarks)

## License

This project is licensed under the Apache License Version 2.0 — see [LICENSE](LICENSE) for details.

## Acknowledgments

- OWASP for guidance on common vulnerabilities
- Open source community and contributors

---

Built for securing applications everywhere
