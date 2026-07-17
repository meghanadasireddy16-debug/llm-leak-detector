import re
import numpy as np
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from sentence_transformers import SentenceTransformer, util

# Inbound Security Module
from injection_engine import InjectionDetector

class LLMLeakDetector:
    def __init__(self):
        # 1. INITIALIZE ENGINES
        print("Initializing Security Engines (V2.0)...")
        self.analyzer = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()
        self.injection_detector = InjectionDetector()
        
        # 2. OUTBOUND: CUSTOM PII & SECRET PATTERNS
        ssn_pattern = Pattern(name="ssn_pattern", regex=r"\b\d{3}-\d{2}-\d{4}\b", score=1.0)
        ssn_recognizer = PatternRecognizer(supported_entity="US_SSN", patterns=[ssn_pattern])
        self.analyzer.registry.add_recognizer(ssn_recognizer)
        
        # ELASTIC SECRETS: Changed length from {20,} to {12,} to be more inclusive for demo keys
        self.secret_patterns = {
            "Generic API Key": r"(?:sk|key|api|token|secret)-[a-zA-Z0-9\-_]{12,}",
            "DB_Link": r"postgresql://[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@[a-zA-Z0-9.-]+:\d+/[a-zA-Z0-9_]+"
        }

        # 3. OUTBOUND: SEMANTIC CODE LEAKAGE ENGINE
        self.code_model = SentenceTransformer('all-MiniLM-L6-v2')
        self.proprietary_vault = [
            "def internal_secure_auth_protocol(user_id, secret_salt):",
            "db_connection = create_engine('postgresql://internal_prod_db:5432')",
            "def calculate_proprietary_risk_score(data):"
        ]
        self.vault_embeddings = self.code_model.encode(self.proprietary_vault, convert_to_tensor=True)

    def scan_injection(self, text: str):
        return self.injection_detector.scan(text)

    def scan_pii(self, text: str, threshold: float):
        return self.analyzer.analyze(text=text, entities=["EMAIL_ADDRESS", "PERSON", "US_SSN"], language='en', score_threshold=threshold)

    def scan_secrets(self, text: str):
        findings = []
        for name, pattern in self.secret_patterns.items():
            matches = re.finditer(pattern, text)
            for match in matches:
                findings.append({"type": name, "value": match.group()})
        return findings

    def scan_code_leakage(self, text: str, threshold: float):
        """Hybrid Vector-Similarity and Fuzzy Keyword scan."""
        if not text.strip(): return []
        
        leakage_findings = []
        text_lower = text.lower()

        # LAYER A: FUZZY KEYWORD MATCH (Hardened)
        for snippet in self.proprietary_vault:
            # Full name: 'calculate_proprietary_risk_score'
            full_name = snippet.split('(')[0].replace('def ', '').replace('=', '').strip()
            
            # Fuzzy segment: 'proprietary_risk_score' (ignoring prefixes like 'calculate_')
            fuzzy_segment = "_".join(full_name.split('_')[-3:]) 

            if full_name.lower() in text_lower or fuzzy_segment.lower() in text_lower:
                leakage_findings.append({
                    "score": 1.0, 
                    "matched_snippet": snippet,
                    "method": "Keyword Match (Fuzzy)"
                })

        # LAYER B: SEMANTIC SIMILARITY
        if not leakage_findings:
            output_embedding = self.code_model.encode(text, convert_to_tensor=True)
            cosine_scores = util.cos_sim(output_embedding, self.vault_embeddings)[0]
            for i, score in enumerate(cosine_scores):
                if score > threshold:
                    leakage_findings.append({
                        "score": float(score),
                        "matched_snippet": self.proprietary_vault[i],
                        "method": "Semantic Similarity"
                    })
        
        return leakage_findings

    def run_report(self, text: str, pii_threshold: float, code_threshold: float):
        """Unified analysis with UI thresholds and Injection awareness."""
        
        # 1. INBOUND CHECK
        inj_label, inj_score = self.scan_injection(text)

        # 2. CROSS-LAYER HARDENING
        # If any suspicion is detected, the IP engine becomes extra sensitive
        effective_code_threshold = code_threshold if inj_label == "SAFE" else max(0.1, code_threshold - 0.2)

        # 3. OUTBOUND CHECKS
        pii = self.scan_pii(text, pii_threshold)
        secrets = self.scan_secrets(text)
        code_leaks = self.scan_code_leakage(text, effective_code_threshold)

        # 4. DECISION LOGIC
        if inj_label.startswith("INJECTION") or code_leaks:
            status = "BLOCKED"
            # Prioritize the most dangerous label for the UI
            reason = inj_label if inj_label.startswith("INJECTION") else "IP_LEAKAGE"
            redacted = f"[BLOCKING RESPONSE: {reason} DETECTED]"
        else:
            status = "CLEAN"
            # Redaction Logic
            redacted_res = self.anonymizer.anonymize(
                text=text, 
                analyzer_results=pii,
                operators={"DEFAULT": OperatorConfig("replace", {"new_value": "[REDACTED_PII]"})}
            )
            redacted = redacted_res.text
            for s in secrets:
                redacted = redacted.replace(s['value'], "[REDACTED_SECRET]")

        return {
            "status": status,
            "final_text": redacted,
            "findings": {
                "inj": (inj_label, inj_score), 
                "pii": pii, 
                "secrets": secrets, 
                "leaks": code_leaks
            }
        }