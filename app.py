import streamlit as st
from groq import Groq
from androguard.core.apk import APK
import tempfile
import os

st.set_page_config(page_title="APK Fraud Risk Scorer", page_icon="🛡️")

st.title("🛡️ GenAI-Powered APK Fraud Risk Scorer")
st.write("Upload a real .apk file to get an AI-generated risk assessment.")

api_key = st.secrets["GROQ_API_KEY"]
client = Groq(api_key=api_key)

risky_permissions = {
    "android.permission.READ_SMS": "Can read text messages (often used to steal OTPs)",
    "android.permission.SEND_SMS": "Can send text messages without user action",
    "android.permission.RECEIVE_SMS": "Can intercept incoming messages",
    "android.permission.READ_CONTACTS": "Can access your contact list",
    "android.permission.SYSTEM_ALERT_WINDOW": "Can draw over other apps (used in overlay attacks)",
    "android.permission.REQUEST_INSTALL_PACKAGES": "Can install other apps without consent",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "Can read/control screen content (high-risk)",
    "android.permission.ACCESS_FINE_LOCATION": "Tracks precise real-time location",
}

def analyze_apk_risk(app_description):
    prompt = f"""
You are a mobile app security analyst. Analyze the following Android app's
behavior and permissions, and respond in this exact format:

Risk Score: [a number from 0 to 100]
Risk Level: [Low / Medium / High / Critical]
Explanation: [2-3 sentences explaining why, in plain English]

App details to analyze:
{app_description}
"""
    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content

uploaded_file = st.file_uploader("Upload an APK file", type=["apk"])

if uploaded_file is not None:
    with st.spinner("Reading APK file..."):
        # Save uploaded file temporarily so androguard can read it
        with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
            tmp.write(uploaded_file.getvalue())
            tmp_path = tmp.name

        try:
            a = APK(tmp_path)
            app_name = a.get_app_name()
            package_name = a.get_package()
            permissions = a.get_permissions()

            found_risky = []
            for perm in permissions:
                if perm in risky_permissions:
                    found_risky.append((perm, risky_permissions[perm]))

            st.subheader("📋 Extracted App Info")
            st.write(f"**App Name:** {app_name}")
            st.write(f"**Package Name:** {package_name}")
            st.write(f"**Total Permissions:** {len(permissions)}")
            st.write(f"**Risky Permissions Flagged:** {len(found_risky)}")

            if found_risky:
                st.write("**Flagged permissions:**")
                for perm, reason in found_risky:
                    st.write(f"- `{perm}` — {reason}")

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

            with st.spinner("Running AI risk analysis..."):
                result = analyze_apk_risk(real_app_description)

            st.subheader("🧠 AI Risk Analysis")
            st.markdown(result)

        except Exception as e:
            st.error(f"Could not process this APK file: {e}")
        finally:
            os.remove(tmp_path)
