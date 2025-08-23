"""
AI-Enhanced Input Validator
Combines traditional validation with AgenticAI intelligence for superior threat detection
"""

import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from datetime import datetime

from .validator import InputValidator, ValidationResult
from ..ai.agentic_ai_integration import (
    AgenticAIIntegration, 
    AIValidationMode, 
    AIThreatAnalysis,
    AIValidationResult
)

logger = logging.getLogger(__name__)


@dataclass
class AIEnhancedValidationResult:
    """Result of AI-enhanced validation"""
    is_valid: bool
    traditional_validation: ValidationResult
    ai_threat_analysis: AIThreatAnalysis
    combined_risk_score: float
    ai_recommendations: List[str]
    validation_mode: str
    confidence_level: str
    learning_applied: bool


class AIEnhancedValidator(InputValidator):
    """Enhanced validator with AI intelligence"""
    
    def __init__(self, 
                 ai_mode: AIValidationMode = AIValidationMode.ADAPTIVE,
                 ai_endpoint: str = None,
                 ai_api_key: str = None):
        super().__init__()
        
        # Initialize AI integration
        self.ai_integration = AgenticAIIntegration(
            api_endpoint=ai_endpoint,
            api_key=ai_api_key,
            mode=ai_mode
        )
        
        self.ai_mode = ai_mode
        logger.info(f"AI-Enhanced Validator initialized in {ai_mode.value} mode")
    
    def validate_field_with_ai(self, 
                              value: Any, 
                              field_type: str, 
                              enable_ai: bool = True,
                              **kwargs) -> AIEnhancedValidationResult:
        """Validate a field with AI enhancement"""
        # Perform traditional validation first
        traditional_result = super().validate_field(value, field_type, **kwargs)
        
        if not enable_ai:
            # Return basic result without AI
            return AIEnhancedValidationResult(
                is_valid=traditional_result.is_valid,
                traditional_validation=traditional_result,
                ai_threat_analysis=None,
                combined_risk_score=0.0 if traditional_result.is_valid else 1.0,
                ai_recommendations=[],
                validation_mode="traditional_only",
                confidence_level="medium",
                learning_applied=False
            )
        
        # Perform AI threat analysis
        ai_analysis = self.ai_integration.analyze_threat_intelligence(str(value))
        
        # Combine traditional and AI results
        combined_result = self._combine_validation_results(
            traditional_result, ai_analysis
        )
        
        # Apply AI learning
        self.ai_integration.learn_from_validation(
            str(value), combined_result.is_valid, ai_analysis
        )
        
        return combined_result
    
    def validate_schema_with_ai(self, 
                               data: Dict[str, Any], 
                               schema: Dict[str, Any],
                               enable_ai: bool = True) -> AIEnhancedValidationResult:
        """Validate schema with AI enhancement"""
        # Perform traditional schema validation
        traditional_result = super().validate_schema(data, schema)
        
        if not enable_ai:
            return AIEnhancedValidationResult(
                is_valid=traditional_result.is_valid,
                traditional_validation=traditional_result,
                ai_threat_analysis=None,
                combined_risk_score=0.0 if traditional_result.is_valid else 1.0,
                ai_recommendations=[],
                validation_mode="traditional_only",
                confidence_level="medium",
                learning_applied=False
            )
        
        # Perform AI analysis on all string fields
        ai_analyses = []
        for field_name, field_value in data.items():
            if isinstance(field_value, str):
                field_schema = schema.get(field_name, {})
                if field_schema.get('ai_validation', True):  # Enable AI by default
                    ai_analysis = self.ai_integration.analyze_threat_intelligence(field_value)
                    ai_analyses.append(ai_analysis)
        
        # Aggregate AI results
        aggregated_ai_analysis = self._aggregate_ai_analyses(ai_analyses)
        
        # Combine results
        combined_result = self._combine_validation_results(
            traditional_result, aggregated_ai_analysis
        )
        
        # Apply learning for each field
        for field_name, field_value in data.items():
            if isinstance(field_value, str):
                field_ai_analysis = next(
                    (a for a in ai_analyses if a is not None), None
                )
                if field_ai_analysis:
                    self.ai_integration.learn_from_validation(
                        field_value, combined_result.is_valid, field_ai_analysis
                    )
        
        return combined_result
    
    def _combine_validation_results(self, 
                                  traditional_result: ValidationResult,
                                  ai_analysis: AIThreatAnalysis) -> AIEnhancedValidationResult:
        """Combine traditional and AI validation results"""
        # Calculate combined risk score
        traditional_risk = 0.0 if traditional_result.is_valid else 1.0
        
        # Convert AI threat level to risk score
        ai_risk_mapping = {
            'safe': 0.0,
            'low_risk': 0.2,
            'medium_risk': 0.5,
            'high_risk': 0.8,
            'critical': 1.0
        }
        
        ai_risk = ai_risk_mapping.get(ai_analysis.threat_level.value, 0.5)
        
        # Weighted combination (AI gets higher weight for security)
        combined_risk = (traditional_risk * 0.3) + (ai_risk * 0.7)
        
        # Determine final validity
        is_valid = combined_risk < 0.7  # Threshold for acceptance
        
        # Determine confidence level
        if ai_analysis.confidence_score > 0.8:
            confidence_level = "high"
        elif ai_analysis.confidence_score > 0.6:
            confidence_level = "medium"
        else:
            confidence_level = "low"
        
        # Generate AI recommendations
        ai_recommendations = []
        if ai_analysis.threat_level.value in ['high_risk', 'critical']:
            ai_recommendations.append("AI detected high security risk - recommend rejection")
        
        if ai_analysis.anomaly_detected:
            ai_recommendations.append("AI detected anomalous input pattern")
        
        if ai_analysis.behavioral_score > 0.7:
            ai_recommendations.append("AI detected unusual behavioral pattern")
        
        # Add specific recommendations from AI analysis
        ai_recommendations.extend(ai_analysis.recommendations)
        
        return AIEnhancedValidationResult(
            is_valid=is_valid,
            traditional_validation=traditional_result,
            ai_threat_analysis=ai_analysis,
            combined_risk_score=combined_risk,
            ai_recommendations=ai_recommendations,
            validation_mode=f"ai_{self.ai_mode.value}",
            confidence_level=confidence_level,
            learning_applied=True
        )
    
    def _aggregate_ai_analyses(self, ai_analyses: List[AIThreatAnalysis]) -> AIThreatAnalysis:
        """Aggregate multiple AI analyses into a single result"""
        if not ai_analyses:
            return self._create_default_ai_analysis()
        
        # Find the highest threat level
        threat_levels = [analysis.threat_level for analysis in ai_analyses]
        max_threat_level = max(threat_levels, key=lambda x: list(x.value))
        
        # Average confidence scores
        avg_confidence = sum(analysis.confidence_score for analysis in ai_analyses) / len(ai_analyses)
        
        # Combine all detected patterns
        all_patterns = []
        for analysis in ai_analyses:
            all_patterns.extend(analysis.detected_patterns)
        
        # Combine all risk factors
        all_risk_factors = []
        for analysis in ai_analyses:
            all_risk_factors.extend(analysis.risk_factors)
        
        # Combine all recommendations
        all_recommendations = []
        for analysis in ai_analyses:
            all_recommendations.extend(analysis.recommendations)
        
        # Average behavioral scores
        avg_behavioral_score = sum(analysis.behavioral_score for analysis in ai_analyses) / len(ai_analyses)
        
        # Check if any anomalies were detected
        any_anomalies = any(analysis.anomaly_detected for analysis in ai_analyses)
        
        return AIThreatAnalysis(
            threat_level=max_threat_level,
            confidence_score=avg_confidence,
            detected_patterns=list(set(all_patterns)),  # Remove duplicates
            risk_factors=list(set(all_risk_factors)),
            recommendations=list(set(all_recommendations)),
            ai_model_version="1.0.0",
            analysis_timestamp=datetime.utcnow().isoformat(),
            behavioral_score=avg_behavioral_score,
            anomaly_detected=any_anomalies
        )
    
    def _create_default_ai_analysis(self) -> AIThreatAnalysis:
        """Create a default AI analysis when no analyses are available"""
        from ..ai.agentic_ai_integration import AIThreatLevel
        
        return AIThreatAnalysis(
            threat_level=AIThreatLevel.SAFE,
            confidence_score=0.5,
            detected_patterns=[],
            risk_factors=[],
            recommendations=["No AI analysis available"],
            ai_model_version="1.0.0",
            analysis_timestamp=datetime.utcnow().isoformat(),
            behavioral_score=0.5,
            anomaly_detected=False
        )
    
    def get_ai_insights(self) -> Dict[str, Any]:
        """Get insights from AI integration"""
        return self.ai_integration.get_ai_insights()
    
    def update_ai_mode(self, new_mode: AIValidationMode):
        """Update AI validation mode"""
        self.ai_mode = new_mode
        self.ai_integration.mode = new_mode
        logger.info(f"AI validation mode updated to {new_mode.value}")
    
    def enable_ai_learning(self, enable: bool = True):
        """Enable or disable AI learning"""
        if enable:
            self.ai_mode = AIValidationMode.ADAPTIVE
        else:
            self.ai_mode = AIValidationMode.PASSIVE
        
        self.ai_integration.mode = self.ai_mode
        logger.info(f"AI learning {'enabled' if enable else 'disabled'}")
    
    def get_validation_statistics(self) -> Dict[str, Any]:
        """Get comprehensive validation statistics"""
        stats = {
            "ai_mode": self.ai_mode.value,
            "ai_insights": self.get_ai_insights(),
            "validation_performance": {
                "total_validations": 0,  # Would need to track this
                "ai_enhanced_validations": 0,
                "threat_detection_rate": 0.0
            }
        }
        
        return stats 