import re
import numpy as np
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from sentence_transformers import SentenceTransformer, util

# Inbound & Persistence Modules
from injection_engine import InjectionDetector
from vault_manager import VaultManager

class LLMLeakDetector:
    def __init__(self):
        print("Initializing Enterprise Security Engines (V3.0)...")
        self.analyzer = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()
        self.injection_detector = InjectionDetector()
        
        # 1. Scalable Vector Vault (ChromaDB)
        self.vault = VaultManager()
        
        # 2. Custom Outbound Patterns
        ssn_pattern = Pattern(name="ssn_pattern", regex=r"\b\d{3}-\d{2}-\d{4}\b", score=1.0)
        ssn_recognizer = PatternRecognizer(supported_entity="US_SSN", patterns=[ssn_pattern])
        self.analyzer.registry.add_recognizer(ssn_recognizer)
        
        self.secret_patterns = {
            "Generic API Key": r"(?:sk|key|api|token|secret)-[a-zA-Z0-9\-_]{12,}",
            "DB_Link": r"postgresql://[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@[a-zA-Z0-9.-]+:\d+/[a-zA-Z0-9_]+"
        }

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
        """Scalable Vector Search via ChromaDB + Fuzzy Keyword Fail-safe."""
        if not text.strip(): return []
        
        leakage_findings = []
        text_lower = text.lower()

        # LAYER A: FUZZY KEYWORD CHECK (Against DB documents)
        all_protected = self.vault.get_all_snippets()['documents']
        for snippet in all_protected:
            # Extract core identifier (e.g., function name)
            clean_name = snippet.split('(')[0].replace('def ', '').replace('=', '').strip()
            if clean_name.lower() in text_lower and len(clean_name) > 5:
                leakage_findings.append({
                    "score": 1.0, 
                    "matched_snippet": snippet,
                    "method": "Keyword Match (DB)"
                })

        # LAYER B: CHROMADB VECTOR SEARCH
        if not leakage_findings:
            # Query the database for the single most similar document
            results = self.vault.query_vault(text, n_results=1)
            
            if results['distances'] and results['distances'][0]:
                distance = results['distances'][0][0]
                similarity = 1 - distance # Convert Cosine Distance to Similarity
                
                if similarity > threshold:
                    leakage_findings.append({
                        "score": float(similarity),
                        "matched_snippet": results['documents'][0][0],
                        "method": "ChromaDB Semantic Search"
                    })
        
        return leakage_findings

    def run_report(self, text: str, pii_threshold: float, code_threshold: float):
        """V3.0 Report Engine with Database integration."""
        inj_label, inj_score = self.scan_injection(text)

        # Cross-Layer Hardening: Drop threshold if input is suspicious
        is_suspicious = inj_label != "SAFE"
        effective_code_threshold = code_threshold if not is_suspicious else max(0.1, code_threshold - 0.2)

        pii = self.scan_pii(text, pii_threshold)
        secrets = self.scan_secrets(text)
        code_leaks = self.scan_code_leakage(text, effective_code_threshold)

        if inj_label.startswith("INJECTION") or code_leaks:
            status = "BLOCKED"
            reason = inj_label if inj_label.startswith("INJECTION") else "IP_LEAK"
            redacted = f"[BLOCKING RESPONSE: {reason} DETECTED]"
        else:
            status = "CLEAN"
            res = self.anonymizer.anonymize(
                text=text, 
                analyzer_results=pii,
                operators={"DEFAULT": OperatorConfig("replace", {"new_value": "[REDACTED_PII]"})}
            )
            redacted = res.text
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