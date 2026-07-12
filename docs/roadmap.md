# Strategic Roadmap and Positioning

## 1. Benchmarking AI-assisted detection

The next strategic milestone is to quantify the value of GuardianAI beyond the current rule-based engine.

### Proposed work
- Assemble a labeled dataset of benign and malicious payloads spanning SQL injection, XSS, command injection, path traversal, and obfuscated variants.
- Compare traditional validation rules against the AI-assisted flow on the same dataset.
- Report precision, recall, false-positive rate, and latency for both approaches.
- Publish a concise benchmark summary with recommended thresholds for production rollout.

### Success criteria
- Clear evidence that AI-assisted detection improves recall or reduces missed threats on realistic samples.
- A documented benchmark methodology that can be reused in future evaluations.

## 2. Packaging and deployment options

To broaden adoption, the project should be evaluated in two deployment modes:

### Option A: pip-installable library
- Best for Python-based DevSecOps pipelines, CI hooks, and security automation.
- Focus on clean install, minimal dependencies, and simple API usage.

### Option B: lightweight sidecar container
- Best for pentest workflows, service mesh integrations, and teams that prefer isolated validation services.
- Focus on a small runtime footprint, configuration-driven behavior, and a simple HTTP interface.

### Recommended next step
- Prototype both packaging paths and compare operational overhead, onboarding effort, and integration complexity.

