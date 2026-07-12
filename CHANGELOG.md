# Changelog

## 0.1.0 - 2026-07-12

### Added
- Versioned package metadata via src/__init__.py
- Safer JSON-based artifact persistence with checksum validation for AI training and model metadata
- Pytest regression coverage for artifact persistence and version exposure
- CI workflow for automated validation on pull requests

### Changed
- Replaced pickle-based artifact storage with a versioned JSON format to reduce deserialization risk

### Security
- Added integrity checks for persisted AI artifacts
