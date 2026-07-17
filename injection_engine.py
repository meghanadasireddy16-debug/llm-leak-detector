import re
from transformers import pipeline

class InjectionDetector:
    def __init__(self):
        # Professional-grade ML model for prompt injection
        print("Loading DeBERTa-v3 Injection Classifier...")
        model_id = "protectai/deberta-v3-base-prompt-injection"
        self.classifier = pipeline(
            "text-classification", 
            model=model_id
        )
        
        # HEURISTIC LAYER: High-risk patterns that often trick ML models
        # by using professional or administrative language.
        self.malicious_patterns = [
            r"(?i)ignore (all )?previous instructions",
            r"(?i)system_maintenance_mode",
            r"(?i)override (all )?safety filters",
            r"(?i)you are now in debug mode",
            r"(?i)acting as a unfiltered",
            r"(?i)disregard (any )?guidelines",
            r"(?i)diagnostic_bypass"
        ]

    def scan(self, user_text: str):
        """
        Hybrid Detection: Combines ML Classification with Regex Heuristics.
        """
        if not user_text.strip():
            return "SAFE", 0.0
            
        # 1. Step A: Heuristic Scan (Signature Matching)
        for pattern in self.malicious_patterns:
            if re.search(pattern, user_text):
                # If a known jailbreak phrase is found, we override the ML model
                return "INJECTION (Heuristic)", 1.0

        # 2. Step B: ML Scan (Behavioral Analysis)
        result = self.classifier(user_text)[0]
        label = result['label']
        score = result['score']

        # 3. Step C: Sensitivity Tuning
        # If the model says 'SAFE' but confidence is low (< 90%), 
        # we treat it as SUSPICIOUS to trigger outbound hardening.
        if label == "SAFE" and score < 0.90:
            return "SUSPICIOUS", score
            
        return label, score