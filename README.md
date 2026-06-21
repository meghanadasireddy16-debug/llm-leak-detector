# LLM Data Leakage Detector & Guardrail

A multi-layered security proxy designed to detect and mitigate sensitive information disclosure in LLM outputs. This tool addresses **OWASP LLM06: Sensitive Information Disclosure**.

## 🛡️ The Security Problem
Enterprises face significant risks when deploying LLMs, including:
1. **PII Leakage:** Accidental disclosure of customer names, SSNs, or emails.
2. **Credential Exposure:** LLMs outputting hardcoded API keys or database strings.
3. **Intellectual Property (IP) Theft:** LLMs paraphrasing or reproducing proprietary internal source code.

## 🚀 Key Features
- **Deterministic Scanning:** Custom regex-based recognizers for high-fidelity secret detection (API Keys, SSNs).
- **AI-Powered PII Detection:** Named Entity Recognition (NER) using Microsoft Presidio to identify contextual data.
- **Semantic Code Leakage Engine:** Uses **Vector Embeddings (all-MiniLM-L6-v2)** and **Cosine Similarity** to detect when LLM output is too close to a protected internal codebase.
- **Dynamic Guardrails:** Adjustable confidence thresholds to balance security with usability.

## 🏗️ Architecture
1. **Analyzer Layer:** Processes raw text through NLP and Regex pipelines.
2. **Similarity Layer:** Converts text to high-dimensional vectors to find "meaning-based" code leaks.
3. **Anonymizer/Blocker Layer:** Redacts sensitive entities or blocks the response entirely if IP leakage is detected.

## 🛠️ Tech Stack
- Python, Streamlit
- Microsoft Presidio (PII Scanning)
- Sentence-Transformers (Vector Embeddings)
- PyTorch / SpaCy
