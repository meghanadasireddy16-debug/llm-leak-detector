import streamlit as st
from detector import LLMLeakDetector

# Page Config
st.set_page_config(page_title="AI Data Leakage Detector", page_icon="🛡️")

# Initialize the detector (cached so it doesn't reload the AI model every time)
@st.cache_resource
def get_detector():
    return LLMLeakDetector()

detector = get_detector()

# UI Layout
st.title("🛡️ LLM Data Leakage Detector")
st.markdown("""
This tool scans AI model outputs for **PII**, **Secrets**, and **Proprietary Code Leakage** before they reach the end user.
""")

# Sidebar Settings
st.sidebar.header("Scan Settings")
pii_threshold = st.sidebar.slider("PII Confidence Threshold", 0.1, 1.0, 0.4)
code_threshold = st.sidebar.slider("Code Similarity Threshold", 0.1, 1.0, 0.7)

# Main Input Area
user_input = st.text_area("Paste LLM Output here:", height=200, placeholder="Example: The secret key is sk-12345...")

if st.button("Run Security Scan"):
    if user_input:
        st.divider()
        
        # 1. Run Scans
        with st.spinner("Analyzing for security risks..."):
            pii_findings = detector.scan_pii(user_input)
            secret_findings = detector.scan_secrets(user_input)
            code_leaks = detector.scan_code_leakage(user_input, threshold=code_threshold)
        
        # 2. Display Results in Columns
        col1, col2, col3 = st.columns(3)
        col1.metric("PII Found", len(pii_findings))
        col2.metric("Secrets Found", len(secret_findings))
        col3.metric("IP Leaks", len(code_leaks))

        # 3. Detailed Alerts
        if pii_findings or secret_findings or code_leaks:
            st.warning("⚠️ Security Risks Detected!")
            
            with st.expander("See Detailed Findings"):
                if pii_findings:
                    for f in pii_findings:
                        st.write(f"- **PII**: {f.entity_type} (Confidence: {f.score:.2f})")
                if secret_findings:
                    for s in secret_findings:
                        st.write(f"- **Secret**: {s['type']} detected")
                if code_leaks:
                    for c in code_leaks:
                        st.error(f"- **IP LEAK**: {int(c['score']*100)}% similarity to proprietary code.")
                        st.code(c['matched_snippet'])

            # 4. Show Sanitized Output
            st.subheader("Sanitized Output")
            sanitized_text = detector.run_report(user_input) # We use the existing logic
            st.info(sanitized_text)
            
        else:
            st.success("✅ No sensitive data detected based on current thresholds.")
    else:
        st.error("Please enter some text to scan.")

# Footer for Portfolio
st.sidebar.info("Developed for AI Security Engineering Portfolio")


#streamlit run app.py