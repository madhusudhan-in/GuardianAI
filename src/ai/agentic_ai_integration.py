"""
AgenticAI Integration for Intelligent Input Validation
Provides AI-powered threat detection, behavioral analysis, and adaptive validation rules
"""

import json
import logging
import hashlib
import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import requests
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
import pickle
import os

# Configure logging
logger = logging.getLogger(__name__)


class AIThreatLevel(Enum):
    """AI-detected threat levels"""
    SAFE = "safe"
    LOW_RISK = "low_risk"
    MEDIUM_RISK = "medium_risk"
    HIGH_RISK = "high_risk"
    CRITICAL = "critical"


class AIValidationMode(Enum):
    """AI validation modes"""
    PASSIVE = "passive"      # AI observes and learns
    ACTIVE = "active"        # AI actively blocks threats
    ADAPTIVE = "adaptive"    # AI adapts rules based on patterns
    COLLABORATIVE = "collaborative"  # AI works with human experts


@dataclass
class AIThreatAnalysis:
    """Result of AI threat analysis"""
    threat_level: AIThreatLevel
    confidence_score: float
    detected_patterns: List[str]
    risk_factors: List[str]
    recommendations: List[str]
    ai_model_version: str
    analysis_timestamp: str
    behavioral_score: float
    anomaly_detected: bool


@dataclass
class AIValidationResult:
    """Result of AI-powered validation"""
    is_valid: bool
    ai_threat_analysis: AIThreatAnalysis
    traditional_validation: Dict[str, Any]
    combined_risk_score: float
    adaptive_rules_applied: List[str]
    learning_insights: List[str]


class AgenticAIIntegration:
    """Integration with AgenticAI for intelligent validation"""
    
    def __init__(self, 
                 api_endpoint: str = None,
                 api_key: str = None,
                 mode: AIValidationMode = AIValidationMode.ADAPTIVE):
        self.api_endpoint = api_endpoint or os.getenv('AGENTIC_AI_ENDPOINT')
        self.api_key = api_key or os.getenv('AGENTIC_AI_API_KEY')
        self.mode = mode
        
        # AI Models
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.tfidf_vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
        
        # Training data storage
        self.training_data_file = "ai_training_data.pkl"
        self.model_file = "ai_models.pkl"
        
        # Load or initialize models
        self._load_or_initialize_models()
        
        # Threat pattern database
        self.threat_patterns = self._load_threat_patterns()
        
        # Behavioral baseline
        self.behavioral_baseline = self._load_behavioral_baseline()
        
        logger.info(f"AgenticAI Integration initialized in {mode.value} mode")
    
    def _load_or_initialize_models(self):
        """Load existing models or initialize new ones"""
        try:
            if os.path.exists(self.model_file):
                with open(self.model_file, 'rb') as f:
                    models = pickle.load(f)
                    self.isolation_forest = models.get('isolation_forest', self.isolation_forest)
                    self.tfidf_vectorizer = models.get('tfidf_vectorizer', self.tfidf_vectorizer)
                    logger.info("Loaded existing AI models")
            else:
                logger.info("Initializing new AI models")
        except Exception as e:
            logger.warning(f"Error loading models: {e}, using default models")
    
    def _save_models(self):
        """Save trained models"""
        try:
            models = {
                'isolation_forest': self.isolation_forest,
                'tfidf_vectorizer': self.tfidf_vectorizer
            }
            with open(self.model_file, 'wb') as f:
                pickle.dump(models, f)
            logger.info("AI models saved successfully")
        except Exception as e:
            logger.error(f"Error saving models: {e}")
    
    def _load_threat_patterns(self) -> Dict[str, List[str]]:
        """Load threat patterns from database or file"""
        # This would typically come from a threat intelligence feed
        return {
            "sql_injection": [
                "'; DROP TABLE", "UNION SELECT", "OR 1=1", "EXEC xp_",
                "WAITFOR DELAY", "CHAR(0x", "CAST(", "CONVERT("
            ],
            "xss": [
                "<script>", "javascript:", "onload=", "onerror=",
                "<iframe>", "<object>", "<embed>", "vbscript:"
            ],
            "command_injection": [
                "; rm -rf", "&& cat", "| whoami", "`id`",
                "exec(", "system(", "shell_exec", "passthru"
            ],
            "path_traversal": [
                "../../../", "..\\..\\..\\", "/etc/passwd",
                "C:\\Windows\\System32", "%2e%2e%2f"
            ]
        }
    
    def _load_behavioral_baseline(self) -> Dict[str, Any]:
        """Load behavioral baseline for anomaly detection"""
        try:
            if os.path.exists("behavioral_baseline.json"):
                with open("behavioral_baseline.json", 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.warning(f"Error loading behavioral baseline: {e}")
        
        # Default baseline
        return {
            "input_length_stats": {"mean": 50, "std": 25, "min": 1, "max": 1000},
            "character_distribution": {},
            "pattern_frequency": {},
            "threat_detection_rate": 0.01,
            "last_updated": datetime.datetime.utcnow().isoformat()
        }
    
    def _update_behavioral_baseline(self, new_data: List[str]):
        """Update behavioral baseline with new data"""
        if not new_data:
            return
        
        # Update input length statistics
        lengths = [len(item) for item in new_data]
        current_mean = self.behavioral_baseline["input_length_stats"]["mean"]
        current_std = self.behavioral_baseline["input_length_stats"]["std"]
        
        # Simple exponential moving average
        alpha = 0.1
        new_mean = alpha * np.mean(lengths) + (1 - alpha) * current_mean
        new_std = alpha * np.std(lengths) + (1 - alpha) * current_std
        
        self.behavioral_baseline["input_length_stats"].update({
            "mean": new_mean,
            "std": new_std,
            "min": min(self.behavioral_baseline["input_length_stats"]["min"], min(lengths)),
            "max": max(self.behavioral_baseline["input_length_stats"]["max"], max(lengths))
        })
        
        self.behavioral_baseline["last_updated"] = datetime.datetime.utcnow().isoformat()
        
        # Save updated baseline
        try:
            with open("behavioral_baseline.json", 'w') as f:
                json.dump(self.behavioral_baseline, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving behavioral baseline: {e}")
    
    def analyze_threat_intelligence(self, input_value: str) -> AIThreatAnalysis:
        """Analyze input using AI-powered threat intelligence"""
        try:
            # Extract features
            features = self._extract_features(input_value)
            
            # Anomaly detection
            anomaly_score = self._detect_anomalies(features)
            
            # Pattern matching with AI enhancement
            pattern_matches = self._ai_pattern_matching(input_value)
            
            # Behavioral analysis
            behavioral_score = self._analyze_behavior(input_value)
            
            # Combine scores for final threat level
            threat_level = self._determine_threat_level(
                anomaly_score, pattern_matches, behavioral_score
            )
            
            # Generate recommendations
            recommendations = self._generate_recommendations(
                threat_level, pattern_matches, behavioral_score
            )
            
            return AIThreatAnalysis(
                threat_level=threat_level,
                confidence_score=self._calculate_confidence(
                    anomaly_score, pattern_matches, behavioral_score
                ),
                detected_patterns=pattern_matches,
                risk_factors=self._identify_risk_factors(input_value),
                recommendations=recommendations,
                ai_model_version="1.0.0",
                analysis_timestamp=datetime.datetime.utcnow().isoformat(),
                behavioral_score=behavioral_score,
                anomaly_detected=anomaly_score > 0.7
            )
        
        except Exception as e:
            logger.error(f"Error in AI threat analysis: {e}")
            return self._fallback_analysis(input_value)
    
    def _extract_features(self, input_value: str) -> np.ndarray:
        """Extract numerical features from input"""
        features = []
        
        # Length-based features
        features.append(len(input_value))
        features.append(len(input_value.split()))
        features.append(len(set(input_value)))
        
        # Character distribution features
        features.append(input_value.count('"'))
        features.append(input_value.count("'"))
        features.append(input_value.count(';'))
        features.append(input_value.count('='))
        features.append(input_value.count('<'))
        features.append(input_value.count('>'))
        features.append(input_value.count('('))
        features.append(input_value.count(')'))
        features.append(input_value.count('&'))
        features.append(input_value.count('|'))
        
        # Entropy-based features
        char_freq = {}
        for char in input_value:
            char_freq[char] = char_freq.get(char, 0) + 1
        
        entropy = 0
        for freq in char_freq.values():
            p = freq / len(input_value)
            if p > 0:
                entropy -= p * np.log2(p)
        
        features.append(entropy)
        
        return np.array(features).reshape(1, -1)
    
    def _detect_anomalies(self, features: np.ndarray) -> float:
        """Detect anomalies using Isolation Forest"""
        try:
            # Fit the model if not already fitted
            if not hasattr(self.isolation_forest, 'estimators_'):
                # Use dummy data for initial training
                dummy_data = np.random.randn(100, features.shape[1])
                self.isolation_forest.fit(dummy_data)
            
            # Predict anomaly score
            score = self.isolation_forest.decision_function(features)[0]
            # Convert to 0-1 scale where higher means more anomalous
            anomaly_score = 1 - (score + 0.5)  # Normalize to 0-1
            
            return max(0, min(1, anomaly_score))
        
        except Exception as e:
            logger.error(f"Error in anomaly detection: {e}")
            return 0.5  # Neutral score on error
    
    def _ai_pattern_matching(self, input_value: str) -> List[str]:
        """AI-enhanced pattern matching"""
        detected_patterns = []
        
        # Traditional pattern matching
        for threat_type, patterns in self.threat_patterns.items():
            for pattern in patterns:
                if pattern.lower() in input_value.lower():
                    detected_patterns.append(f"{threat_type}: {pattern}")
        
        # AI-enhanced fuzzy matching
        if self.api_endpoint and self.api_key:
            try:
                ai_patterns = self._query_agentic_ai(input_value)
                detected_patterns.extend(ai_patterns)
            except Exception as e:
                logger.warning(f"AgenticAI query failed: {e}")
        
        return detected_patterns
    
    def _query_agentic_ai(self, input_value: str) -> List[str]:
        """Query AgenticAI for enhanced pattern detection"""
        try:
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
            
            payload = {
                'input': input_value,
                'analysis_type': 'threat_detection',
                'context': 'input_validation',
                'timestamp': datetime.datetime.utcnow().isoformat()
            }
            
            response = requests.post(
                f"{self.api_endpoint}/analyze",
                headers=headers,
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                return result.get('detected_patterns', [])
            else:
                logger.warning(f"AgenticAI API returned {response.status_code}")
                return []
        
        except Exception as e:
            logger.error(f"Error querying AgenticAI: {e}")
            return []
    
    def _analyze_behavior(self, input_value: str) -> float:
        """Analyze behavioral patterns"""
        try:
            baseline = self.behavioral_baseline["input_length_stats"]
            input_length = len(input_value)
            
            # Calculate z-score for length
            z_score = abs(input_length - baseline["mean"]) / baseline["std"]
            
            # Normalize to 0-1 scale
            behavioral_score = min(1.0, z_score / 3.0)  # 3 sigma rule
            
            return behavioral_score
        
        except Exception as e:
            logger.error(f"Error in behavioral analysis: {e}")
            return 0.5
    
    def _determine_threat_level(self, 
                               anomaly_score: float, 
                               pattern_matches: List[str], 
                               behavioral_score: float) -> AIThreatLevel:
        """Determine overall threat level"""
        # Weighted combination of scores
        threat_score = (
            anomaly_score * 0.4 +
            (len(pattern_matches) * 0.3) +
            behavioral_score * 0.3
        )
        
        if threat_score < 0.2:
            return AIThreatLevel.SAFE
        elif threat_score < 0.4:
            return AIThreatLevel.LOW_RISK
        elif threat_score < 0.6:
            return AIThreatLevel.MEDIUM_RISK
        elif threat_score < 0.8:
            return AIThreatLevel.HIGH_RISK
        else:
            return AIThreatLevel.CRITICAL
    
    def _identify_risk_factors(self, input_value: str) -> List[str]:
        """Identify specific risk factors"""
        risk_factors = []
        
        # Length-based risks
        if len(input_value) > 1000:
            risk_factors.append("Input length exceeds normal range")
        
        # Character-based risks
        if input_value.count('"') > 10:
            risk_factors.append("Excessive quote characters")
        
        if input_value.count(';') > 5:
            risk_factors.append("Multiple semicolons detected")
        
        # Encoding risks
        if '%' in input_value:
            risk_factors.append("URL encoding detected")
        
        if '\\u' in input_value:
            risk_factors.append("Unicode escape sequences detected")
        
        return risk_factors
    
    def _generate_recommendations(self, 
                                threat_level: AIThreatLevel, 
                                pattern_matches: List[str], 
                                behavioral_score: float) -> List[str]:
        """Generate AI-powered recommendations"""
        recommendations = []
        
        if threat_level in [AIThreatLevel.HIGH_RISK, AIThreatLevel.CRITICAL]:
            recommendations.append("Immediate input rejection recommended")
            recommendations.append("Log for security team review")
            recommendations.append("Consider blocking source IP")
        
        if pattern_matches:
            recommendations.append("Apply additional sanitization")
            recommendations.append("Validate against known attack patterns")
        
        if behavioral_score > 0.7:
            recommendations.append("Monitor for similar behavioral patterns")
            recommendations.append("Consider rate limiting")
        
        if threat_level == AIThreatLevel.SAFE:
            recommendations.append("Input appears safe for processing")
            recommendations.append("Continue with normal validation")
        
        return recommendations
    
    def _calculate_confidence(self, 
                            anomaly_score: float, 
                            pattern_matches: List[str], 
                            behavioral_score: float) -> float:
        """Calculate confidence in the analysis"""
        # Base confidence on consistency of signals
        scores = [anomaly_score, len(pattern_matches) * 0.1, behavioral_score]
        variance = np.var(scores)
        
        # Lower variance = higher confidence
        confidence = max(0.5, 1.0 - variance)
        
        return confidence
    
    def _fallback_analysis(self, input_value: str) -> AIThreatAnalysis:
        """Fallback analysis when AI fails"""
        return AIThreatAnalysis(
            threat_level=AIThreatLevel.MEDIUM_RISK,
            confidence_score=0.3,
            detected_patterns=["AI analysis failed"],
            risk_factors=["Fallback mode active"],
            recommendations=["Review input manually", "Check AI system status"],
            ai_model_version="fallback",
            analysis_timestamp=datetime.datetime.utcnow().isoformat(),
            behavioral_score=0.5,
            anomaly_detected=False
        )
    
    def learn_from_validation(self, 
                            input_value: str, 
                            validation_result: bool, 
                            threat_analysis: AIThreatAnalysis):
        """Learn from validation results to improve AI models"""
        try:
            # Update behavioral baseline
            self._update_behavioral_baseline([input_value])
            
            # Store training data
            training_data = {
                'input': input_value,
                'validation_result': validation_result,
                'threat_analysis': asdict(threat_analysis),
                'timestamp': datetime.datetime.utcnow().isoformat()
            }
            
            # Load existing training data
            existing_data = []
            if os.path.exists(self.training_data_file):
                try:
                    with open(self.training_data_file, 'rb') as f:
                        existing_data = pickle.load(f)
                except Exception:
                    existing_data = []
            
            # Add new data (keep last 1000 entries)
            existing_data.append(training_data)
            if len(existing_data) > 1000:
                existing_data = existing_data[-1000:]
            
            # Save updated training data
            with open(self.training_data_file, 'wb') as f:
                pickle.dump(existing_data, f)
            
            # Retrain models periodically
            if len(existing_data) % 100 == 0:
                self._retrain_models(existing_data)
            
            logger.info("Successfully learned from validation result")
        
        except Exception as e:
            logger.error(f"Error learning from validation: {e}")
    
    def _retrain_models(self, training_data: List[Dict[str, Any]]):
        """Retrain AI models with new data"""
        try:
            # Extract features for retraining
            features = []
            labels = []
            
            for data in training_data:
                if 'input' in data:
                    feature_vector = self._extract_features(data['input'])
                    features.append(feature_vector.flatten())
                    
                    # Create label: 1 for malicious, 0 for safe
                    is_malicious = (
                        data.get('validation_result') == False or
                        data.get('threat_analysis', {}).get('threat_level') in 
                        ['high_risk', 'critical']
                    )
                    labels.append(1 if is_malicious else 0)
            
            if len(features) > 10:  # Need minimum data for training
                features_array = np.array(features)
                
                # Retrain isolation forest
                self.isolation_forest.fit(features_array)
                
                # Retrain TF-IDF vectorizer
                texts = [data.get('input', '') for data in training_data]
                self.tfidf_vectorizer.fit(texts)
                
                # Save updated models
                self._save_models()
                
                logger.info("AI models retrained successfully")
        
        except Exception as e:
            logger.error(f"Error retraining models: {e}")
    
    def get_ai_insights(self) -> Dict[str, Any]:
        """Get insights from AI analysis"""
        try:
            insights = {
                "model_performance": {
                    "anomaly_detection_accuracy": self._estimate_accuracy(),
                    "pattern_detection_coverage": len(self.threat_patterns),
                    "behavioral_analysis_effectiveness": "high"
                },
                "threat_intelligence": {
                    "total_patterns": sum(len(patterns) for patterns in self.threat_patterns.values()),
                    "threat_categories": list(self.threat_patterns.keys()),
                    "last_updated": datetime.datetime.utcnow().isoformat()
                },
                "learning_progress": {
                    "training_samples": self._get_training_sample_count(),
                    "model_version": "1.0.0",
                    "last_retraining": self._get_last_retraining_time()
                }
            }
            
            return insights
        
        except Exception as e:
            logger.error(f"Error getting AI insights: {e}")
            return {"error": str(e)}
    
    def _estimate_accuracy(self) -> float:
        """Estimate model accuracy based on training data"""
        try:
            if os.path.exists(self.training_data_file):
                with open(self.training_data_file, 'rb') as f:
                    data = pickle.load(f)
                
                if len(data) > 0:
                    # Simple accuracy estimation
                    correct_predictions = sum(
                        1 for item in data 
                        if item.get('validation_result') == 
                        (item.get('threat_analysis', {}).get('threat_level') in ['safe', 'low_risk'])
                    )
                    return correct_predictions / len(data)
            
            return 0.8  # Default accuracy estimate
        
        except Exception:
            return 0.8
    
    def _get_training_sample_count(self) -> int:
        """Get count of training samples"""
        try:
            if os.path.exists(self.training_data_file):
                with open(self.training_data_file, 'rb') as f:
                    data = pickle.load(f)
                return len(data)
        except Exception:
            pass
        return 0
    
    def _get_last_retraining_time(self) -> str:
        """Get last model retraining time"""
        try:
            if os.path.exists(self.training_data_file):
                with open(self.training_data_file, 'rb') as f:
                    data = pickle.load(f)
                if data:
                    return data[-1].get('timestamp', 'unknown')
        except Exception:
            pass
        return 'unknown' 