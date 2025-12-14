import streamlit as st
import pandas as pd
import re
from datetime import datetime

st.set_page_config(page_title="Cybersecurity Log Analyzer", page_icon="🔐", layout="centered")

st.markdown("""
<style>
.title {font-size:34px;font-weight:700;color:#0052CC;}
.subtitle {font-size:16px;color:#4F4F4F;margin-bottom:20px;}
.card {background:#F8F9FC;padding:18px;border-radius:10px;border:1px solid #E3E6F3;margin-bottom:12px;}
</style>
""", unsafe_allow_html=True)

st.markdown('<div class="title">🔐 Cybersecurity Log Analyzer</div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle">SOC-style threat detection using Python & Streamlit (Cisco-aligned)</div>', unsafe_allow_html=True)
st.write("---")

uploaded_file = st.file_uploader("Upload a system/server log file (.txt)", type=["txt"])

ATTACK_SIGNATURES = {
    "Brute Force Attack": ["failed login", "invalid password", "authentication failed"],
    "SQL Injection": ["sql", "union select", "drop table", "or 1=1"],
    "XSS Attack": ["<script>", "alert(", "onerror"],
    "Unauthorized Access": ["unauthorized", "forbidden", "access denied"]
}

IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def analyze_logs(lines):
    ip_activity = {}
    attack_count = {}
    threat_samples = []
    for line in lines:
        lower = line.lower()
        for ip in IP_REGEX.findall(lower):
            ip_activity[ip] = ip_activity.get(ip, 0) + 1
        for attack, keys in ATTACK_SIGNATURES.items():
            if any(k in lower for k in keys):
                attack_count[attack] = attack_count.get(attack, 0) + 1
                threat_samples.append({"Attack Type": attack, "Log Entry": line.strip()})
    return ip_activity, attack_count, threat_samples

if uploaded_file:
    logs = uploaded_file.read().decode("utf-8", errors="ignore").splitlines()
    ip_activity, attack_count, threat_samples = analyze_logs(logs)

    st.subheader("📊 Security KPIs")
    c1, c2, c3 = st.columns(3)
    c1.metric("Total Log Lines", len(logs))
    c2.metric("Threat Events", sum(attack_count.values()))
    c3.metric("Suspicious IPs", len(ip_activity))

    st.subheader("📌 Security Summary")
    st.markdown(f"""
    <div class="card">
    <b>Analysis Time (UTC):</b> {datetime.utcnow().strftime("%Y-%m-%d %H:%M")}<br>
    <b>Detected Attack Types:</b> {", ".join(attack_count.keys()) if attack_count else "None"}
    </div>
    """, unsafe_allow_html=True)

    if ip_activity:
        st.subheader("⚠️ Suspicious IP Addresses")
        st.dataframe(pd.DataFrame(ip_activity.items(), columns=["IP Address", "Event Count"]).sort_values("Event Count", ascending=False), use_container_width=True)

    if attack_count:
        st.subheader("🛑 Attack Breakdown")
        st.dataframe(pd.DataFrame.from_dict(attack_count, orient="index", columns=["Occurrences"]).sort_values("Occurrences", ascending=False), use_container_width=True)

    if threat_samples:
        st.subheader("📄 Sample Malicious Log Entries")
        st.dataframe(pd.DataFrame(threat_samples).head(15), use_container_width=True)

    report = {"total_logs": len(logs), "attack_summary": attack_count, "ip_activity": ip_activity}

    st.download_button("⬇️ Download Security Report (JSON)", data=str(report), file_name="security_report.json", mime="application/json")
    st.success("Log analysis completed successfully.")
else:
    st.info("Upload a .txt log file to begin security analysis.")
