import json
import os
import sys
from pathlib import Path

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src import __version__
from src.ai.agentic_ai_integration import AgenticAIIntegration, AIThreatAnalysis, AIThreatLevel


@pytest.fixture
def sample_threat_analysis():
    return AIThreatAnalysis(
        threat_level=AIThreatLevel.SAFE,
        confidence_score=0.9,
        detected_patterns=[],
        risk_factors=[],
        recommendations=["Input appears safe"],
        ai_model_version=__version__,
        analysis_timestamp="2026-07-12T00:00:00",
        behavioral_score=0.1,
        anomaly_detected=False,
    )


def test_package_version_is_exposed(tmp_path, sample_threat_analysis):
    assert __version__ == "0.1.0"

    integration = AgenticAIIntegration(artifact_dir=str(tmp_path))
    integration.learn_from_validation("safe input", True, sample_threat_analysis)

    insights = integration.get_ai_insights()
    assert insights["learning_progress"]["model_version"] == __version__
    assert insights["learning_progress"]["training_samples"] == 1


def test_training_and_model_artifacts_are_json_with_checksums(tmp_path, sample_threat_analysis):
    integration = AgenticAIIntegration(artifact_dir=str(tmp_path))
    integration.learn_from_validation("malicious input", False, sample_threat_analysis)
    integration._save_models()

    training_data_path = tmp_path / "ai_training_data.json"
    model_data_path = tmp_path / "ai_models.json"

    assert training_data_path.exists()
    assert model_data_path.exists()

    training_payload = json.loads(training_data_path.read_text())
    model_payload = json.loads(model_data_path.read_text())

    assert training_payload["version"] == 1
    assert model_payload["version"] == 1
    assert training_payload["checksum"]
    assert model_payload["checksum"]
    assert training_payload["data"][0]["input"] == "malicious input"
