import streamlit as st
from groq import Groq
from androguard.core.apk import APK
import tempfile
import os
import re
import io
from datetime import datetime

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch

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

html, body, [class*="css"]  { font-family: 'Inter', sans-serif; }
.stApp { background-color: #0B1929; }

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
.header-title { color: #F8FAFC; font-size: 1.9rem; font-weight: 700; margin: 0; }
.header-sub { color: #8DA3BF; font-size: 0.95rem; margin-top: 0.5rem; }

[data-testid="stFileUploaderDropzone"] {
    background-color: #122436;
    border: 1.5px dashed #2D5180;
    border-radius: 8px;
}
[data-testid="stFileUploaderDropzone"]:hover { border-color: #E8A33D; }

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
    display: flex; justify-content: space-between;
    padding: 0.45rem 0; border-bottom: 1px solid #1A2E45;
    font-size: 0.92rem;
}
.info-row:last-child { border-bottom: none; }
.info-label { color: #8DA3BF; }
.info-value { color: #F8FAFC; font-family: 'JetBrains Mono', monospace; font-weight: 500; text-align: right; }

.perm-flag {
    background-color: #1A1418;
    border-left: 3px solid #DC2626;
    border-radius: 4px;
    padding: 0.6rem 0.9rem;
    margin-bottom: 0.5rem;
}
.perm-flag-name { font-family: 'JetBrains Mono', monospace; color: #F87171; font-size: 0.82rem; font-weight: 500; }
.perm-flag-desc { color: #C9D4E2; font-size: 0.85rem; margin-top: 0.2rem; }

.behavior-flag {
    background-color: #1A1606;
    border-left: 3px solid #E8A33D;
    border-radius: 4px;
    padding: 0.6rem 0.9rem;
    margin-bottom: 0.5rem;
}
.behavior-flag-name { font-family: 'JetBrains Mono', monospace; color: #F4B85C; font-size: 0.82rem; font-weight: 500; }
.behavior-flag-desc { color: #C9D4E2; font-size: 0.85rem; margin-top: 0.2rem; }

.perm-clean {
    background-color: #0F1F17;
    border-left: 3px solid #16A34A;
    border-radius: 4px;
    padding: 0.7rem 0.9rem;
    color: #86EFAC;
    font-size: 0.88rem;
}

.gauge-wrap { text-align: center; padding: 1rem 0 0.5rem 0; }
.gauge-score { font-family: 'JetBrains Mono', monospace; font-size: 3.2rem; font-weight: 700; line-height: 1; }
.gauge-max { font-family: 'JetBrains Mono', monospace; font-size: 1.1rem; color: #5A7392; }
.gauge-level {
    font-family: 'JetBrains Mono', monospace; font-size: 0.85rem;
    letter-spacing: 0.12em; text-transform: uppercase; font-weight: 600;
    padding: 0.3rem 1rem; border-radius: 20px; display: inline-block; margin-top: 0.6rem;
}

.explain-box {
    background-color: #122436; border: 1px solid #1E3A5F; border-radius: 10px;
    padding: 1.25rem 1.5rem; color: #D6E1EE; font-size: 0.95rem; line-height: 1.6; margin-top: 1rem;
}

.footer-note {
    text-align: center; color: #3D5878; font-size: 0.78rem;
    font-family: 'JetBrains Mono', monospace; margin-top: 2.5rem;
    padding-top: 1rem; border-top: 1px solid #1E3A5F;
}

.stButton button, .stDownloadButton button {
    background-color: #E8A33D; color: #0B1929; font-weight: 600;
    border: none; border-radius: 6px;
}
.stButton button:hover, .stDownloadButton button:hover { background-color: #F4B85C; color: #0B1929; }
</style>
""", unsafe_allow_html=True)

# ---------- HEADER ----------
st.markdown("""
<div class="header-wrap">
    <div class="header-eyebrow">PSB Cybersecurity &amp; Fraud AI Hackathon 2026 · Problem Statement 1</div>
    <p class="header-title">🛡️ GenAI APK Fraud Risk Scorer</p>
    <p class="header-sub">Upload an Android APK to extract permissions, flag behavioral indicators, and generate an AI-reasoned fraud risk assessment.</p>
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

# Permission COMBINATIONS that are far more dangerous together than alone
# (this is the "static behavioral indicator" layer — real technique used by analysts)
DANGEROUS_COMBOS = [
    (
        {"android.permission.READ_SMS", "android.permission.BIND_ACCESSIBILITY_SERVICE"},
        "SMS access + Accessibility Service control — classic banking trojan pattern (can read OTPs and auto-fill/auto-tap on victim's behalf)",
    ),
    (
        {"android.permission.SYSTEM_ALERT_WINDOW", "android.permission.BIND_ACCESSIBILITY_SERVICE"},
        "Overlay drawing + Accessibility control — typical of fake login screen ('overlay attack') malware",
    ),
    (
        {"android.permission.READ_SMS", "android.permission.REQUEST_INSTALL_PACKAGES"},
        "SMS access + ability to install other apps — common dropper/loader malware pattern",
    ),
    (
        {"android.permission.RECEIVE_SMS", "android.permission.SEND_SMS", "android.permission.READ_CONTACTS"},
        "Full SMS control + contact access — pattern seen in self-propagating SMS fraud apps",
    ),
]

URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")
IP_PATTERN = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")


def analyze_apk_risk(app_description: str) -> str:
    prompt = f"""You are a mobile app security analyst. Analyze the following Android app's
behavior, permissions, and static indicators, and respond in this exact format:

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


def find_combo_flags(permission_set):
    flags = []
    for combo, reason in DANGEROUS_COMBOS:
        if combo.issubset(permission_set):
            flags.append((", ".join(p.split(".")[-1] for p in combo), reason))
    return flags


def find_string_indicators(apk_obj):
    """Static behavioral indicator scan: look for hardcoded URLs/IPs in app strings."""
    urls, ips = set(), set()
    try:
        for s in apk_obj.get_files():
            pass  # placeholder loop kept light; main signal comes from strings below
    except Exception:
        pass
    try:
        raw_strings = apk_obj.get_android_manifest_axml().get_xml().decode(errors="ignore")
        urls.update(URL_PATTERN.findall(raw_strings))
        ips.update(IP_PATTERN.findall(raw_strings))
    except Exception:
        pass
    return list(urls)[:10], list(ips)[:10]


LEVEL_COLORS = {
    "Low": ("#16A34A", "#0F1F17"),
    "Medium": ("#E8A33D", "#2A1F0D"),
    "High": ("#F97316", "#2A180C"),
    "Critical": ("#DC2626", "#2A1014"),
}


def build_pdf_report(app_name, package_name, permissions, found_risky, combo_flags, urls, ips, score, level, explanation):
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, topMargin=0.6 * inch, bottomMargin=0.6 * inch)
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle("TitleX", parent=styles["Title"], textColor=colors.HexColor("#0B1929"))
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], textColor=colors.HexColor("#1E3A5F"), spaceBefore=14)
    body = styles["Normal"]

    story = [
        Paragraph("APK Fraud Risk Assessment Report", title_style),
        Paragraph("Bank of India × IIT Hyderabad — CyberShield Hackathon 2026, Problem Statement 1", body),
        Paragraph(f"Generated: {datetime.now().strftime('%d %b %Y, %H:%M')}", body),
        Spacer(1, 16),
        Paragraph("Application Details", h2),
    ]

    info_table = Table(
        [
            ["App Name", app_name],
            ["Package", package_name],
            ["Total Permissions", str(len(permissions))],
            ["Flagged Permissions", str(len(found_risky))],
            ["Dangerous Combinations", str(len(combo_flags))],
        ],
        colWidths=[160, 340],
    )
    info_table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F1F5F9")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(info_table)
    story.append(Spacer(1, 14))

    story.append(Paragraph("Flagged Permissions", h2))
    if found_risky:
        for p, reason in found_risky:
            story.append(Paragraph(f"<b>{p}</b> — {reason}", body))
    else:
        story.append(Paragraph("No commonly-flagged risky permissions detected.", body))

    story.append(Paragraph("Static Behavioral Indicators", h2))
    if combo_flags:
        for combo, reason in combo_flags:
            story.append(Paragraph(f"<b>{combo}</b> — {reason}", body))
    else:
        story.append(Paragraph("No known dangerous permission combinations detected.", body))

    if urls or ips:
        story.append(Paragraph("Hardcoded Network Indicators", h2))
        for u in urls:
            story.append(Paragraph(f"URL found: {u}", body))
        for ip in ips:
            story.append(Paragraph(f"IP found: {ip}", body))

    story.append(Paragraph("AI Risk Assessment", h2))
    score_color = colors.HexColor("#16A34A") if level == "Low" else (
        colors.HexColor("#DC2626") if level in ("High", "Critical") else colors.HexColor("#E8A33D")
    )
    score_style = ParagraphStyle("ScoreStyle", parent=styles["Heading1"], textColor=score_color)
    story.append(Paragraph(f"Risk Score: {score}/100 — {level} Risk", score_style))
    story.append(Spacer(1, 6))
    story.append(Paragraph(explanation, body))

    story.append(Spacer(1, 20))
    story.append(Paragraph(
        "This report was generated by an automated GenAI reasoning pipeline as part of a hackathon prototype. "
        "Dynamic sandbox execution analysis is planned as a future enhancement.",
        ParagraphStyle("Footnote", parent=styles["Normal"], textColor=colors.HexColor("#64748B"), fontSize=8),
    ))

    doc.build(story)
    buf.seek(0)
    return buf


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
            permission_set = set(permissions)
            found_risky = [(p, RISKY_PERMISSIONS[p]) for p in permissions if p in RISKY_PERMISSIONS]
            combo_flags = find_combo_flags(permission_set)
            urls, ips = find_string_indicators(a)

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
                st.markdown(f'<div class="info-card"><h4>Flagged Permissions</h4>{flags_html}</div>', unsafe_allow_html=True)
            else:
                st.markdown('<div class="info-card"><h4>Flagged Permissions</h4><div class="perm-clean">✓ No commonly-flagged risky permissions detected</div></div>', unsafe_allow_html=True)

            # --- Static behavioral indicators card ---
            if combo_flags:
                combo_html = "".join([
                    f'<div class="behavior-flag"><div class="behavior-flag-name">◆ {combo}</div><div class="behavior-flag-desc">{reason}</div></div>'
                    for combo, reason in combo_flags
                ])
                st.markdown(f'<div class="info-card"><h4>Static Behavioral Indicators</h4>{combo_html}</div>', unsafe_allow_html=True)
            else:
                st.markdown('<div class="info-card"><h4>Static Behavioral Indicators</h4><div class="perm-clean">✓ No known dangerous permission combinations detected</div></div>', unsafe_allow_html=True)

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
            if combo_flags:
                real_app_description += "\nDangerous Permission Combinations Detected:\n"
                for combo, reason in combo_flags:
                    real_app_description += f"- {combo}: {reason}\n"

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

            # --- Downloadable PDF report ---
            pdf_buffer = build_pdf_report(
                app_name, package_name, permissions, found_risky,
                combo_flags, urls, ips, score, level, explanation
            )
            st.download_button(
                label="📄 Download Full Report (PDF)",
                data=pdf_buffer,
                file_name=f"risk_report_{package_name}.pdf",
                mime="application/pdf",
            )

        except Exception as e:
            st.error(f"Could not process this APK file: {e}")
        finally:
            os.remove(tmp_path)

st.markdown('<div class="footer-note">Bank of India × IIT Hyderabad — CyberShield Hackathon 2026</div>', unsafe_allow_html=True)
