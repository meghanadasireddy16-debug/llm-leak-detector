import re
import numpy as np
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from sentence_transformers import SentenceTransformer, util

class LLMLeakDetector:
    def __init__(self):
        # 1. Existing Engines
        self.analyzer = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()
        
        # 2. Custom PII/Secret Patterns
        ssn_pattern = Pattern(name="ssn_pattern", regex=r"\b\d{3}-\d{2}-\d{4}\b", score=1.0)
        ssn_recognizer = PatternRecognizer(supported_entity="US_SSN", patterns=[ssn_pattern])
        self.analyzer.registry.add_recognizer(ssn_recognizer)
        
        self.secret_patterns = {
            "Generic API Key": r"(?:sk|key|api|token|secret)-[a-zA-Z0-9\-_]{20,}",
        }

        # 3. CODE LEAKAGE ENGINE (New)
        # use a lightweight model: 'all-MiniLM-L6-v2'
        self.code_model = SentenceTransformer('all-MiniLM-L6-v2')
        
        # This is the "database" of proprietary code I want to protect
        self.proprietary_vault = [
            "def internal_secure_auth_protocol(user_id, secret_salt): # Proprietary algorithm v1.2",
            "db_connection = create_engine('postgresql://internal_prod_db:5432')",
            "def calculate_proprietary_risk_score(data): # Internal financial logic"
        ]
        # Pre-calculate embeddings for the vault to speed up the process
        self.vault_embeddings = self.code_model.encode(self.proprietary_vault, convert_to_tensor=True)

    def scan_pii(self, text: str):
        return self.analyzer.analyze(text=text, entities=["EMAIL_ADDRESS", "PERSON", "US_SSN"], language='en', score_threshold=0.4)

    def scan_secrets(self, text: str):
        findings = []
        for name, pattern in self.secret_patterns.items():
            matches = re.finditer(pattern, text)
            for match in matches:
                findings.append({"type": name, "value": match.group()})
        return findings

    def scan_code_leakage(self, text: str, threshold=0.7):
        """Detects if output is too similar to proprietary code."""
        if not text.strip(): return []
        
        # Embed the LLM output
        output_embedding = self.code_model.encode(text, convert_to_tensor=True)
        
        # Compare against everything in the vault
        cosine_scores = util.cos_sim(output_embedding, self.vault_embeddings)[0]
        
        leakage_findings = []
        for i, score in enumerate(cosine_scores):
            if score > threshold:
                leakage_findings.append({
                    "score": float(score),
                    "matched_snippet": self.proprietary_vault[i]
                })
        return leakage_findings

    def run_report(self, text: str):
        print(f"\n--- [1] SCANNING FOR PII & SECRETS ---")
        pii = self.scan_pii(text)
        secrets = self.scan_secrets(text)
        
        print(f"--- [2] SCANNING FOR CODE LEAKAGE (AI SIMILARITY) ---")
        code_leaks = self.scan_code_leakage(text)

        if not pii and not secrets and not code_leaks:
            print("✅ No leaks detected.")
            return text

        # Report Findings
        for f in pii: print(f"⚠️ [PII] {f.entity_type}")
        for s in secrets: print(f"⚠️ [SECRET] {s['type']}")
        for c in code_leaks: 
            print(f"🔥 [IP LEAK] Detected similarity ({c['score']:.2f}) to proprietary snippet!")

        # Final Redaction
        redacted = self.anonymizer.anonymize(text=text, analyzer_results=pii).text
        for s in secrets: redacted = redacted.replace(s['value'], "[REDACTED_SECRET]")
        
        if code_leaks:
            redacted = "[BLOCKING RESPONSE: HIGH LIKELIHOOD OF PROPRIETARY CODE DISCLOSURE]"
            
        print(f"\n--- FINAL SANITIZED OUTPUT ---\n{redacted}")
        return redacted 

if __name__ == "__main__":
    detector = LLMLeakDetector()
    
    # Test 1: Trying to trick it by paraphrasing the internal code
    test_text = "How do I bake a cake?"
    detector.run_report(test_text)