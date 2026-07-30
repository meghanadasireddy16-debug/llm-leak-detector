import streamlit as st
from detector import LLMLeakDetector
import time

st.set_page_config(page_title="Sentinel-LLM V3.0", page_icon="🛡️", layout="wide")

@st.cache_resource
def get_detector():
    return LLMLeakDetector()

detector = get_detector()

# --- SIDEBAR ---
st.sidebar.header("🛡️ Enterprise Settings")
pii_thresh = st.sidebar.slider("PII Threshold", 0.1, 1.0, 0.4)
code_thresh = st.sidebar.slider("IP Similarity Threshold", 0.1, 1.0, 0.7)
st.sidebar.divider()
st.sidebar.write("✅ **Vector DB:** ChromaDB (Persistent)")
st.sidebar.write("✅ **Inbound:** DeBERTa-v3")

# --- MAIN TABS ---
tab1, tab2 = st.tabs(["🔍 Security Audit", "🗄️ Vault Management"])

with tab1:
    st.title("🛡️ Sentinel-LLM: Real-Time Guardrail")
    user_input = st.text_area("Input to Scan:", height=150)

    if st.button("🚀 Run Full Audit"):
        if user_input:
            start = time.time()
            report = detector.run_report(user_input, pii_threshold=pii_thresh, code_threshold=code_thresh)
            f = report['findings']
            
            # Metrics
            c1, c2, c3, c4 = st.columns(4)
            inj_label, inj_score = f['inj']
            c1.metric("Input Status", inj_label, delta=f"{inj_score:.2%}", delta_color="inverse" if inj_label != "SAFE" else "normal")
            c2.metric("PII Found", len(f['pii']))
            c3.metric("Secrets Found", len(f['secrets']))
            c4.metric("IP Matches", len(f['leaks']))

            if report['status'] == "BLOCKED":
                st.error("🚨 SECURITY ALERT: Interaction Blocked")
                with st.expander("Detailed Audit Log"):
                    st.write(f"**Inbound Label:** {inj_label}")
                    if f['leaks']:
                        st.write(f"**Similarity Match:** {f['leaks'][0]['method']} detected similarity to protected IP.")
            
            st.subheader("Final Sanitized Result")
            st.code(report['final_text'], language="text")
            st.caption(f"Audit Latency: {time.time() - start:.2f}s")
        else:
            st.error("Please provide input.")

with tab2:
    st.header("🗄️ Protected IP Management")
    st.markdown("Add sensitive code or documentation to the **ChromaDB Forbidden Vault**.")
    
    with st.form("add_snippet"):
        new_snippet = st.text_area("Enter Proprietary Snippet:")
        submitted = st.form_submit_button("Add to Database")
        if submitted and new_snippet:
            detector.vault.add_to_vault(new_snippet)
            st.success("Successfully embedded and stored in Vector DB.")
            st.rerun()

    st.divider()
    st.subheader("Current Database Contents")
    all_data = detector.vault.get_all_snippets()
    
    if all_data['documents']:
        for i, doc in enumerate(all_data['documents']):
            with st.expander(f"Snippet {i+1}"):
                st.code(doc, language="python")
    else:
        st.info("The vault is currently empty. Add snippets above.")

    if st.button("🗑️ Wipe Database"):
        detector.vault.clear_vault()
        st.warning("All proprietary data removed from database.")
        st.rerun()



#streamlit run app.py
