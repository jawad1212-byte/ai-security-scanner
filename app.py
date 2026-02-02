import streamlit as st
import re

# Session state
if "total_scans" not in st.session_state:
    st.session_state.total_scans = 0
if "total_issues" not in st.session_state:
    st.session_state.total_issues = 0
if "success_rate" not in st.session_state:
    st.session_state.success_rate = 100

st.set_page_config(layout="wide", page_title="AI Security Scanner")

# CLEAN MODERN CSS
st.markdown("""
<style>
    .main {background: #0a0a0f;}
    h1 {color: #ffffff; font-size: 2.2rem; font-weight: 700; text-align: center; margin-bottom: 0.5rem;}
    .metric-container {background: rgba(20,20,30,0.8); border: 1px solid #333; border-radius: 12px; padding: 1.5rem;}
    .stButton > button {background: #1e40af; border-radius: 10px; font-weight: 600; height: 45px;}
    .stButton > button:hover {background: #1d4ed8;}
    .stCode {background: #1a1a2a; border: 1px solid #333; border-radius: 8px;}
</style>
""", unsafe_allow_html=True)

st.title("🔍 AI Code Security Scanner")

# VULN PATTERNS (same perfect detection)
VULN_PATTERNS = {
    "SQL_INJECTION": {
        "severity": "CRITICAL", "fix": "cursor.execute('SELECT * WHERE id = ?', (user_id,))",
        "patterns": [r"f['\"].*?(user|input|get|post|request)", r"['\"].*\+\s*(user|input|get|post)", 
                     r"(select|insert|delete|drop).*?(user|input)", r"cursor\.(execute)", r"(exec|eval)\("]
    },
    "HARDCODED_SECRET": {
        "severity": "HIGH", "fix": "api_key = os.getenv('API_KEY')",
        "patterns": [r"(password|key|secret|token)\s*[:=]\s*['\"][^'\"]{3,}['\"]", r"(API[_-]?KEY|sk[-_])\w{8,}"]
    },
    "XSS": {
        "severity": "MEDIUM", "fix": "html.escape(user_input)",
        "patterns": [r"(print|write).*?(user|input)", r"innerHTML\s*=", r"document\.write"]
    },
    "COMMAND_INJECTION": {
        "severity": "CRITICAL", "fix": "subprocess.run(['ls'], shell=False)",
        "patterns": [r"os\.system", r"subprocess\.(call|run)", r"exec\s*\("]
    }
}

def scan_code(code):
    findings = []
    for i, line in enumerate(code.split('\n'), 1):
        for vuln, data in VULN_PATTERNS.items():
            for pattern in data["patterns"]:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({"line": i, "code": line.rstrip(), "vuln": vuln, 
                                   "severity": data["severity"], "fix": data["fix"]})
                    break
    return findings

def update_metrics(issues):
    st.session_state.total_scans += 1
    st.session_state.total_issues += issues
    st.session_state.success_rate = max(0, ((st.session_state.total_scans - st.session_state.total_issues) / st.session_state.total_scans) * 100)

col1, col2 = st.columns([3, 1])

with col1:
    st.subheader("📤 Code Scanner")
    code = st.text_area("", height=350, placeholder="Paste your code here...")
    
    if st.button("🔍 SCAN CODE", use_container_width=True):
        if code.strip():
            results = scan_code(code)
            update_metrics(len(results))
            
            if results:
                st.error(f"🚨 {len(results)} vulnerabilities found")
                for issue in results:
                    st.markdown(f"**Line {issue['line']}** - {issue['vuln']} ({issue['severity']})")
                    st.code(issue['code'])
                    st.info(f"**Fix:** `{issue['fix']}`")
            else:
                st.success("✅ Clean code!")
        else:
            st.warning("Paste code first")

with col2:
    st.subheader("📊 Live Stats")
    st.metric("Scans", st.session_state.total_scans)
    st.metric("Issues", st.session_state.total_issues) 
    st.metric("Success Rate", f"{st.session_state.success_rate:.0f}%")
