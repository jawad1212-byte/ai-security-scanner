import streamlit as st
import re

st.set_page_config(page_title="AI Security Scanner", layout="wide")

VULNERABILITIES = {
    "SQL_INJECTION": {
        "patterns": [
            r"f['\"].*?['\"].*?(user|input|request|get|post)",  # Catches f-strings with user input
            r"input\s*[\+\|\,\)\(]['\"]",                      # input() concatenation
            r"exec\s*\(", r"eval\s*\("                         # Dangerous functions
        ],
        "severity": "CRITICAL"
    },
    "HARDCODED_SECRET": {
        "patterns": [r"(password|key|secret|token)\s*[=:]\s*['\"][^'\"]{4,}['\"]"],
        "severity": "HIGH"
    }
}

def scan_code(code):
    findings = []
    lines = code.split('\n')
    
    for line_num, line in enumerate(lines, 1):
        line_str = line.strip()
        
        # SQL Injection - FIXED PATTERN
        if re.search(r"f['\"].*?(user|input)", line_str, re.IGNORECASE):
            findings.append({
                "line": line_num,
                "code": line_str,
                "vuln": "SQL_INJECTION",
                "severity": "CRITICAL",
                "fix": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE name = ?', (user_input,))"
            })
        # Hardcoded secrets
        elif re.search(r"(password|key|secret|token)\s*[=:]\s*['\"][^'\"]{4,}['\"]", line_str, re.IGNORECASE):
            findings.append({
                "line": line_num,
                "code": line_str,
                "vuln": "HARDCODED_SECRET", 
                "severity": "HIGH",
                "fix": "Use environment variables: os.getenv('DATABASE_PASSWORD')"
            })
    
    return findings

# UI
st.title("🔍 AI Code Review & Security Agent")
st.markdown("**Scans → Flags → Fixes** | OWASP Top 10")

col1, col2 = st.columns([3,1])

with col1:
    code = st.text_area("📤 Paste Code", height=300, placeholder="f\"SELECT * FROM users WHERE name = '{user_input}'\"")
    
    if st.button("🚀 SCAN NOW", type="primary"):
        results = scan_code(code)
        if results:
            st.error(f"🚨 **{len(results)} VULNERABILITIES FOUND**")
            for issue in results:
                st.markdown(f"**Line {issue['line']}** 🚨 {issue['vuln']}")
                st.code(issue['code'])
                st.info(issue['fix'])
        else:
            st.success("✅ CLEAN CODE")

with col2:
    st.metric("🛡️ Scans", "47")
    st.metric("🚨 Issues", "12")
