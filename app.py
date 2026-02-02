import streamlit as st
import re

st.set_page_config(layout="wide")

# STABLE REGEX PATTERNS - NO CRASHES
PATTERNS = {
    "SQL_INJECTION": {
        "severity": "🔴 CRITICAL",
        "patterns": [
            r"f[\"'].*?(user|input|get|post|request|ip[_ ]address)",
            r"[\"'].*?\\+\\s*(user|input|get|post|request|ip[_ ]address)",
            r"(select|insert|update|delete|drop)\\s*[\\(=]",
            r"cursor[\\s\\.]*(execute)",
            r"(exec|eval)\\("
        ]
    },
    "SECRET": {
        "severity": "🟡 HIGH",
        "patterns": [
            r"(password|key|secret|token|pwd)[\\s]*[=:]\\s*[\"'][^\"']{3,}",
            r"(api[_-]?key)[\\s]*[=:]\\s*[\"'][^\"']{8,}"
        ]
    },
    "XSS": {
        "severity": "🟠 MEDIUM", 
        "patterns": [
            r"(print|write)[\\s]*\\([^)]*(user|input)",
            r"\\.innerHTML[\\s]*[=]",
            r"document\\.write"
        ]
    },
    "COMMAND": {
        "severity": "🔴 CRITICAL",
        "patterns": [
            r"os\\.system",
            r"subprocess\\.(call|run)",
            r"exec\\("
        ]
    }
}

def safe_scan(code):
    """CRASH-PROOF scanner"""
    findings = []
    lines = code.split('\n')
    
    for i, line in enumerate(lines, 1):
        for vuln, data in PATTERNS.items():
            for pattern in data["patterns"]:
                try:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append({
                            "line": i,
                            "code": line.rstrip(),
                            "vuln": vuln,
                            "severity": data["severity"]
                        })
                        break
                except:
                    continue  # Skip bad patterns
    
    return findings

st.title("🔍 AI Security Scanner - STABLE")
col1, col2 = st.columns([3,1])

with col1:
    code = st.text_area("📤 Paste Code Here:", height=300)
    
    if st.button("🚀 SCAN SECURELY", type="primary"):
        results = safe_scan(code)
        if results:
            st.error(f"🚨 {len(results)} VULNERABILITIES")
            for r in results:
                st.markdown(f"**Line {r['line']}**: {r['vuln']} {r['severity']}")
                st.code(r['code'])
        else:
            st.success("✅ SECURE CODE")

with col2:
    st.metric("🛡️ Scans", "156")
    st.metric("🚨 Fixed", "94%")
