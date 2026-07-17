import streamlit as st
from detector import LLMLeakDetector
import time

st.set_page_config(page_title="Sentinel-LLM V2", page_icon="🛡️", layout="wide")

@st.cache_resource
def get_detector():
    return LLMLeakDetector()

detector = get_detector()

# --- SIDEBAR CONFIGURATION ---
st.sidebar.header("🛡️ Security Configuration")
st.sidebar.subheader("Detection Sensitivity")

# Restore the sliders
pii_thresh = st.sidebar.slider("PII Confidence Threshold", 0.1, 1.0, 0.4, help="Lower values catch more PII but increase false positives.")
code_thresh = st.sidebar.slider("Code Similarity Threshold", 0.1, 1.0, 0.7, help="Lower values make the IP detector more aggressive.")

st.sidebar.divider()
st.sidebar.info("**V2.0 Core Engines:**\n- Injection: DeBERTa-v3\n- IP: MiniLM-L6 (Hybrid)\n- PII: Presidio/SpaCy")

# --- MAIN UI ---
st.title("🛡️ Sentinel-LLM: Bi-Directional Guardrail")
st.markdown("Automated protection against Prompt Injection & Sensitive Data Leakage.")

user_input = st.text_area("Input Prompt or LLM Output:", height=150, placeholder="Paste suspicious text here...")

if st.button("🛡️ Run Security Audit"):
    if user_input:
        start = time.time()
        
        # Pass the slider values to the report engine
        report = detector.run_report(user_input, pii_threshold=pii_thresh, code_threshold=code_thresh)
        f = report['findings']
        
        # Metrics Display
        col1, col2, col3, col4 = st.columns(4)
        inj_label, inj_score = f['inj']
        
        col1.metric("Input Status", inj_label, delta=f"{inj_score:.2%}", delta_color="inverse" if inj_label != "SAFE" else "normal")
        col2.metric("PII Found", len(f['pii']))
        col3.metric("Secrets Found", len(f['secrets']))
        col4.metric("IP Leaks", len(f['leaks']))

        # Alert Logic
        if report['status'] == "BLOCKED":
            st.error(f"🚨 RESPONSE BLOCKED: Security Threat Detected")
            with st.expander("Security Audit Details"):
                if inj_label != "SAFE": st.write(f"**Injection Engine:** Detected '{inj_label}' with {inj_score:.2%} confidence.")
                if f['leaks']: st.write(f"**IP Protection:** {len(f['leaks'])} proprietary snippet(s) flagged.")
        else:
            st.success("✅ Analysis Complete: No blocking threats detected.")

        st.subheader("Final Output")
        st.code(report['final_text'], language="text")
        st.caption(f"Audit completed in {time.time() - start:.2f}s")
    else:
        st.error("Please enter text to scan.")


#streamlit run app.py
