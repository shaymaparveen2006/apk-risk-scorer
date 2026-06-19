import streamlit as st
from groq import Groq

st.set_page_config(page_title="APK Fraud Risk Scorer", page_icon="🛡️")

st.title("🛡️ GenAI-Powered APK Fraud Risk Scorer")
st.write("Paste an app's permissions and behavior below to get an AI-generated risk assessment.")

api_key = st.secrets["GROQ_API_KEY"]
client = Groq(api_key=api_key)

app_description = st.text_area(
    "App Details (name, permissions, behavior):",
    height=200,
    placeholder="App Name: QuickLoan Pro\nPermissions: READ_SMS, SEND_SMS...\nBehavior: ..."
)

if st.button("Analyze Risk"):
    if app_description.strip() == "":
        st.warning("Please enter some app details first.")
    else:
        with st.spinner("Analyzing..."):
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
            result = response.choices[0].message.content
            st.success("Analysis complete")
            st.markdown(result)
