import streamlit as st
from groq import Groq
from androguard.core.apk import APK
import tempfile
import os
import re

# ---------- PAGE CONFIG ----------
st.set_page_config(
    page_title="APK Fraud Risk Scorer",
    page_icon="🛡️",
    layout="centered",
)

# ---------- STYLES ----------
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Inter:wght@400;500;600;700&display=swap');

html, body, [class*="css"]  {
    font-family: 'Inter', sans-serif;
}

.stApp {
    background-color: #0B1929;
}

/* Header block */
.header-wrap {
    text-align: center;
    padding: 1.5rem 0 1rem 0;
    border-bottom: 1px solid #1E3A5F;
    margin-bottom: 2rem;
}
.header-eyebrow {
    font-family: 'JetBrains Mono', monospace;
    color: #E8A33D;
    font-size: 0.75rem;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    margin-bottom: 0.4rem;
}
.header-title {
    color: #F8FAFC;
    font-size: 1.9rem;
    font-weight: 700;
    margin: 0;
}
.header-sub {
    color: #8DA3BF;
    font-size: 0.95rem;
    margin-top: 0.5rem;
}

/* Upload box label override */
[data-testid="stFileUploaderDropzone"] {
    background-color: #122436;
    border: 1.5px dashed #2D5180;
    border-radius: 8px;
}
[data-testid="stFileUploaderDropzone"]:hover {
    border-color: #E8A33D;
}

/* Card styling */
.info-card {
    background-color: #122436;
    border: 1px solid #1E3A5F;
    border-radius: 10px;
    padding: 1.25rem 1.5rem;
    margin-bottom: 1.2rem;
}
.info-card h4 {
    color: #8DA3BF;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.72rem;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    margin: 0 0 0.8rem 0;
}
.info-row {
    display: flex;
    justify-content: space-between;
    padding: 0.45rem 0;
    border-bottom: 1px solid #1A2E45;
    font-size: 0.92rem;
}
.info-row:last-child { border-bottom: none; }
.info-label { color: #8DA3BF; }
.info-value {
    color: #F8FAFC;
    font-family: 'JetBrains Mono', monospace;
    font-weight: 500;
    text-align: right;
}

.perm-flag {
    background-color: #1A1418;
    border-left: 3px solid #DC2626;
    border-radius: 4px;
    padding: 0.6rem 0.9rem;
    margin-bottom: 0.5rem;
}
.perm-flag-name {
    font-family: 'JetBrains Mono', monospace;
    color: #F87171;
    font-size: 0.82rem;
    font-weight: 500;
}
.perm-flag-desc {
    color: #C9D4E2;
    font-size: 0.85rem;
    margin-top: 0.2rem;
}

.perm-clean {
    background-color: #0F1F17;
    border-left: 3px solid #16A34A;
    border-radius: 4px;
    padding: 0.7rem 0.9rem;
    color: #86EFAC;
    font-size: 0.88rem;
}

/* Risk gauge */
.gauge-wrap {
    text-align: center;
    padding: 1rem 0 0.5rem 0;
}
.gauge-score {
    font-family: 'JetBrains Mono', monospace;
    font-size: 3.2rem;
    font-weight: 700;
    line-height: 1;
}
.gauge-max {
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.1rem;
    color: #5A7392;
}
.gauge-level {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.85rem;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    font-weight: 600;
    padding: 0.3rem 1rem;
    border-radius: 20px;
    display: inline-block;
    margin-top: 0.6rem;
}

.explain-box {
    background-color: #122436;
    border: 1px solid #1E3A5F;
    border-radius: 10px;
    padding: 1.25rem 1.5rem;
    color: #D6E1EE;
    font-size: 0.95rem;
    line-height: 1.6;
    margin-top: 1rem;
}

.footer-note {
    text-align: center;
    color: #3D5878;
    font-size: 0.78rem;
    font-family: 'JetBrains Mono', monospace;
    margin-top: 2.5rem;
    padding-top: 1rem;
    border-top: 1px solid #1E3A5F;
}

.stButton button {
    background-color: #E8A33D;
    color: #0B1929;
    font-weight: 600;
    border: none;
    border-radius: 6px;
}
.stButton button:hover {
    background-color: #F4B85C;
    color: #0B1929;
}
</style>
""", unsafe_allow_html=True)

# ---------- HEADER ----------
st.markdown("""
<div class="header-wrap">
    <div class="header-eyebrow">PSB Cybersecurity &amp; Fraud AI Hackathon 2026 · Problem Statement 1</div>
    <p class="header-title">🛡️ GenAI APK Fraud Risk Scorer</p>
    <p class="header-sub">Upload an Android APK to extract its permissions and generate an AI-reasoned fraud risk assessment.</p>
</div>
""", unsafe_allow_html=True)

# ---------- SETUP ----------
api_key = st.secrets["GROQ_API_KEY"]
client = Groq(api_key=api_key)

RISKY_PERMISSIONS = {
    "android.permission.READ_SMS": "Can read text messages — often used to intercept OTPs",
    "android.permission.SEND_SMS": "Can send text messages without user action",
    "android.permission.RECEIVE_SMS": "Can intercept incoming messages silently",
    "android.permission.READ_CONTACTS": "Can access the full contact list",
    "android.permission.SYSTEM_ALERT_WINDOW": "Can draw over other apps — used in overlay attacks",
    "android.permission.REQUEST_INSTALL_PACKAGES": "Can install other apps without explicit consent",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "Can read and control on-screen content",
    "android.permission.ACCESS_FINE_LOCATION": "Tracks precise real-time location",
}

def analyze_apk_risk(app_description: str) -> str:
    prompt = f"""You are a mobile app security analyst. Analyze the following Android app's
behavior and permissions, and respond in this exact format:

Risk Score: [a number from 0 to 100]
Risk Level: [Low / Medium / High / Critical]
Explanation: [2-3 sentences explaining why, in plain English]

App details to analyze:
{app_description}
"""
    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
    )
    return response.choices[0].message.content


def parse_ai_result(text: str):
    score_match = re.search(r"Risk Score:\s*(\d+)", text)
    level_match = re.search(r"Risk Level:\s*(\w+)", text)
    explain_match = re.search(r"Explanation:\s*(.+)", text, re.DOTALL)
    score = int(score_match.group(1)) if score_match else None
    level = level_match.group(1) if level_match else "Unknown"
    explanation = explain_match.group(1).strip() if explain_match else text
    return score, level, explanation


LEVEL_COLORS = {
    "Low": ("#16A34A", "#0F1F17"),
    "Medium": ("#E8A33D", "#2A1F0D"),
    "High": ("#F97316", "#2A180C"),
    "Critical": ("#DC2626", "#2A1014"),
}

# ---------- UPLOAD ----------
uploaded_file = st.file_uploader("Upload an APK file", type=["apk"], label_visibility="collapsed")

if uploaded_file is not None:
    with st.spinner("Decompiling and extracting permissions..."):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
            tmp.write(uploaded_file.getvalue())
            tmp_path = tmp.name

        try:
            a = APK(tmp_path)
            app_name = a.get_app_name()
            package_name = a.get_package()
            permissions = a.get_permissions()
            found_risky = [(p, RISKY_PERMISSIONS[p]) for p in permissions if p in RISKY_PERMISSIONS]

            # --- App info card ---
            st.markdown(f"""
            <div class="info-card">
                <h4>Extracted App Information</h4>
                <div class="info-row"><span class="info-label">App Name</span><span class="info-value">{app_name}</span></div>
                <div class="info-row"><span class="info-label">Package</span><span class="info-value">{package_name}</span></div>
                <div class="info-row"><span class="info-label">Total Permissions</span><span class="info-value">{len(permissions)}</span></div>
                <div class="info-row"><span class="info-label">Flagged Permissions</span><span class="info-value">{len(found_risky)}</span></div>
            </div>
            """, unsafe_allow_html=True)

            # --- Permission flags card ---
            if found_risky:
                flags_html = "".join([
                    f'<div class="perm-flag"><div class="perm-flag-name">⚠ {p}</div><div class="perm-flag-desc">{desc}</div></div>'
                    for p, desc in found_risky
                ])
                st.markdown(f'<div class="info-card"><h4>Flagged Permission Patterns</h4>{flags_html}</div>', unsafe_allow_html=True)
            else:
                st.markdown('<div class="info-card"><h4>Flagged Permission Patterns</h4><div class="perm-clean">✓ No commonly-flagged risky permissions detected</div></div>', unsafe_allow_html=True)

            # --- Build description for AI ---
            real_app_description = f"""
App Name: {app_name}
Package Name: {package_name}
Total Permissions Requested: {len(permissions)}
All Permissions: {', '.join(permissions)}
Flagged Risky Permissions: {len(found_risky)}
"""
            if found_risky:
                real_app_description += "\nRisky Permission Details:\n"
                for perm, reason in found_risky:
                    real_app_description += f"- {perm}: {reason}\n"

            with st.spinner("Running GenAI risk analysis..."):
                result = analyze_apk_risk(real_app_description)

            score, level, explanation = parse_ai_result(result)
            color, bg = LEVEL_COLORS.get(level, ("#8DA3BF", "#1A2333"))

            # --- Risk gauge ---
            st.markdown(f"""
            <div class="gauge-wrap">
                <span class="gauge-score" style="color:{color}">{score if score is not None else '—'}</span><span class="gauge-max">/100</span>
                <div>
                    <span class="gauge-level" style="color:{color}; background-color:{bg};">{level} Risk</span>
                </div>
            </div>
            <div class="explain-box">{explanation}</div>
            """, unsafe_allow_html=True)

        except Exception as e:
            st.error(f"Could not process this APK file: {e}")
        finally:
            os.remove(tmp_path)

st.markdown('<div class="footer-note">Bank of India × IIT Hyderabad — CyberShield Hackathon 2026</div>', unsafe_allow_html=True)
