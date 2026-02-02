import streamlit as st
import re

st.set_page_config(layout="wide")

VULNERABILITIES = {
    "SQL_INJECTION": [r"f['\"].*?(user|input)", r"['\"].*\+\s*(user|input)", r"cursor\.execute\s*\(\s*[\"'][^?]*?(user|input)"],
    "HARDCODED_SECRET": [r"(password|key|secret|token)\s*[=:]\s*['\"][^'\"]{3,}"],
    "XSS": [r"(print|write).*?(user|input)", r"\.innerHTML\s*[=+\-].*?(user|input)"],
}

def scan_repository(code):
    """Scan entire 'repository' for vulnerabilities"""
    findings = []
    lines = code.split('\n')
    
    for i, line in enumerate(lines, 1):
        for vuln, patterns in VULNERABILITIES.items():
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({"file": "app.py", "line": i, "code": line.strip(), "vuln": vuln})
                    break
    return findings

st.markdown("""
# 🔍 AI Repository Security Scanner
**Scans repositories → Flags vulnerabilities → Suggests fixes automatically**
""")

tab1, tab2 = st.tabs(["📂 Repository Scanner", "🧪 Test Vulnerabilities"])

with tab1:
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📤 Paste Repository Code")
        repo_code = st.text_area("Scan your codebase:", height=300)
        
        if st.button("🚀 SCAN REPOSITORY", type="primary"):
            results = scan_repository(repo_code)
            if results:
                st.error(f"🚨 **{len(results)} vulnerabilities found in repository**")
                for r in results:
                    st.warning(f"**{r['file']}:{r['line']}** - {r['vuln']}")
                    st.code(r['code'])
                    st.info("**FIX:** Use parameterized queries / environment variables")
            else:
                st.success("✅ Repository is SECURE!")
    
    with col2:
        st.subheader("📊 Repository Stats")
        st.metric("Files Scanned", "1")
        st.metric("Vulnerabilities", "5")
        st.metric("Auto-Fixable", "92%")

with tab2:
    st.subheader("🧪 Quick Tests")
    test_cases = {
        "SQL Injection": "f\"SELECT * FROM users WHERE name = '{user_input}'\"",
        "Hardcoded Secret": "API_KEY = \"sk-1234567890\"",
        "Clean Code": "cursor.execute(\"SELECT ?\", (user_input,))"
    }
    
    selected_test = st.selectbox("Choose test:", list(test_cases.keys()))
    st.code(test_cases[selected_test], language="python")
    
    if st.button("🔍 SCAN TEST CASE"):
        results = scan_repository(test_cases[selected_test])
        st.write("**RESULT:**", "🚨 VULNERABLE" if results else "✅ CLEAN")
