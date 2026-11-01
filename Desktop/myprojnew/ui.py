


import streamlit as st
from groq import Groq
import os
import pandas as pd
from tools import detect_ddos, abuseipdb_check
from ai import generate_pdf

from tools import (
    detect_sqli,
    recon_check,
    detect_steganography,
    detect_ddos
)

from db import (
    save_log,
    init_db,
    authenticate_user,
    create_user,
    update_password,
    load_logs
)

# =========================================================
# INIT
# =========================================================

init_db()

from db import create_admin

create_admin()


# =========================================================
# SESSION INIT
# =========================================================

if "auth_mode" not in st.session_state:
    st.session_state["auth_mode"] = "Login"

if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False


# =========================================================
# AUTH UI
# =========================================================

def auth_ui():

    st.title("🔐 Authentication")

    options = ["Login", "Register", "Change Password"]

    option = st.selectbox(
        "Choose option",
        options,
        index=options.index(st.session_state["auth_mode"])
    )

    st.session_state["auth_mode"] = option

    # ---------------- LOGIN ----------------

    if option == "Login":

        with st.form("login_form"):

            username = st.text_input("Username")

            password = st.text_input(
                "Password",
                type="password"
            )

            submit = st.form_submit_button("Login")

            if submit:

                if not username or not password:

                    st.warning("Please fill all fields")

                else:

                    user = authenticate_user(
                        username,
                        password
                    )

                    if user:

                        st.session_state["authenticated"] = True
                        st.session_state["user"] = user[0]
                        st.session_state["role"] = user[1]

                        st.success("Login successful")

                        st.rerun()

                    else:

                        st.error("Invalid credentials")

    # ---------------- REGISTER ----------------

    elif option == "Register":

        with st.form("register_form"):

            username = st.text_input("Username")

            password = st.text_input(
                "Password",
                type="password"
            )

            submit = st.form_submit_button("Register")

            if submit:

                if not username or not password:

                    st.warning("Please fill all fields")

                else:

                    result = create_user(
                        username,
                        password
                    )

                    if result == "SUCCESS":

                        st.success("User created successfully!")

                        st.session_state["auth_mode"] = "Login"

                        st.rerun()

                    elif result == "USER_EXISTS":

                        st.error("User already exists")

                    elif result == "INVALID_USERNAME":

                        st.error(
                            "Username must start with CW"
                        )

                    elif result == "WEAK_PASSWORD":

                        st.error(
                            "Password must contain uppercase and special character"
                        )

    # ---------------- CHANGE PASSWORD ----------------

    elif option == "Change Password":

        with st.form("change_password_form"):

            username = st.text_input("Username")

            password = st.text_input(
                "Current Password",
                type="password"
            )

            new_password = st.text_input(
                "New Password",
                type="password"
            )

            submit = st.form_submit_button(
                "Update Password"
            )

            if submit:

                if not username or not password or not new_password:

                    st.warning("Fill all fields")

                elif authenticate_user(username, password):

                    result = update_password(
                        username,
                        new_password
                    )

                    if result == "WEAK_PASSWORD":

                        st.error("Weak password")

                    else:

                        st.success(
                            "Password updated successfully"
                        )

                        st.rerun()

                else:

                    st.error("Invalid credentials")


# =========================================================
# AUTH CONTROL
# =========================================================

if not st.session_state["authenticated"]:

    auth_ui()

    st.stop()


# =========================================================
# SIDEBAR
# =========================================================

st.sidebar.write(
    f"👤 Logged in as: "
    f"{st.session_state['user']} "
    f"({st.session_state['role']})"
)

if st.sidebar.button("Logout"):

    st.session_state.clear()

    st.rerun()


# =========================================================
# MAIN TITLE
# =========================================================

st.title("🔐 Cybersecurity AI Agent")


# =========================================================
# GROQ CLIENT
# =========================================================
client = Groq(
    api_key="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"
)


# =========================================================
# SAFE AI GENERATION
# =========================================================

def safe_generate(prompt):

    try:

        response = client.chat.completions.create(

            model="llama-3.1-8b-instant",

            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ],

            temperature=0.3
        )

        return response.choices[0].message.content

    except Exception:

        return "AI service temporarily unavailable."


# =========================================================
# CLASSIFICATION
# =========================================================

def classify_input(inp):

    text = inp.lower()

    # SQLi
    if (
        "'" in text
        or "--" in text
        or "select" in text
        or "union" in text
        or " or 1=1" in text
        or "drop" in text
        or "insert" in text
        or "delete" in text
    ):

        return "sqli"

    # Recon
    if (
        text.startswith("http")
        or "www" in text
    ):

        return "recon"

    # Stego
    if text.endswith(
        (".png", ".jpg", ".jpeg")
    ):

        return "stego"

    return "unknown"


# =========================================================
# AI ANALYSIS
# =========================================================

def get_ai_analysis(inp, tool_used, tool_output):

    prompt = f"""
You are a cybersecurity analyst.

Input: {inp}

Tool: {tool_used}

Output: {tool_output}

Generate:
1. Summary
2. Attack Type
3. Severity
4. Explanation
5. Impact
6. Prevention
"""

    ai_response = safe_generate(prompt)

    if "temporarily unavailable" in ai_response.lower():

        return generate_rule_based_report(
            inp,
            tool_used,
            tool_output
        )

    return ai_response


# =========================================================
# RULE-BASED FALLBACK
# =========================================================

def generate_rule_based_report(
    inp,
    tool_used,
    tool_output
):

    severity = "LOW"

    report = []

    # ---------------- SQLi ----------------

    if tool_used == "SQL Injection":

        if "Threat Detected" in tool_output:

            severity = "HIGH"

            report.append(
                "Potential SQL Injection attack detected."
            )

        else:

            report.append(
                "No SQL Injection detected."
            )

    # ---------------- Recon ----------------

    elif tool_used == "Reconnaissance":

        if "HIGH" in tool_output:

            severity = "HIGH"

        elif "MEDIUM" in tool_output:

            severity = "MEDIUM"

        report.append(
            "URL analyzed using reconnaissance detection engine."
        )

    # ---------------- Stego ----------------

    elif tool_used == "Steganography":

        if "HIGH" in tool_output:

            severity = "HIGH"

        elif "MEDIUM" in tool_output:

            severity = "MEDIUM"

        report.append(
            "Image analyzed using entropy and correlation analysis."
        )

    # ---------------- DDoS ----------------

    elif tool_used == "DDoS":

        if "HIGH" in tool_output:

            severity = "HIGH"

        elif "MEDIUM" in tool_output:

            severity = "MEDIUM"

        report.append(
            "Traffic volume analyzed for denial-of-service indicators."
        )

    else:

        report.append(
            "No known threats detected."
        )

    final_report = f"""
Summary:
{' '.join(report)}

Attack Type:
{tool_used}

Severity:
{severity}

Explanation:
The analysis was generated using rule-based cybersecurity heuristics.

Impact:
Potential security risks depend on severity level.

Prevention:
Validate all inputs and continuously monitor suspicious activity.
"""

    return final_report


# =========================================================
# MAIN INPUT
# =========================================================

st.subheader("🛡 Main Threat Analysis")

inp = st.text_input(
    "Enter SQL / URL / Image Path"
)


# =========================================================
# RUN MAIN ANALYSIS
# =========================================================

if st.button("Run Analysis"):

    decision = classify_input(inp)

    # ---------------- SQLi ----------------

    if decision == "sqli":

        tool_used = "SQL Injection"

        tool_output = detect_sqli(inp)

    # ---------------- Recon ----------------

    elif decision == "recon":

        tool_used = "Reconnaissance"

        tool_output = recon_check(inp)

    # ---------------- Stego ----------------

    elif decision == "stego":

        tool_used = "Steganography"

        tool_output = detect_steganography(inp)

    # ---------------- Unknown ----------------

    else:

        tool_used = "Unknown"

        tool_output = "No attack detected"

    # ---------------- AI REPORT ----------------

    ai_report = get_ai_analysis(
        inp,
        tool_used,
        tool_output
    )

    # ---------------- SAVE LOG ----------------

    save_log(
        st.session_state["user"],
        inp,
        tool_used,
        tool_output
    )

    # ---------------- STORE SESSION ----------------

    st.session_state["done"] = True

    st.session_state["inp"] = inp

    st.session_state["tool_used"] = tool_used

    st.session_state["tool_output"] = tool_output

    st.session_state["ai_report"] = ai_report

    # ---------------- DISPLAY ----------------

    st.subheader("🛠 Tool Used")

    st.success(tool_used)

    st.subheader("⚙ Tool Result")

    st.code(tool_output)

    # st.subheader("🤖 AI Security Analysis")

    # st.write(ai_report)


# =========================================================
# DDOS ANALYSIS
# =========================================================

st.subheader("🌐 DDoS Traffic Analysis")

ddos_ip = st.text_input("IP Address")

ddos_requests = st.number_input(
    "Requests Per Minute",
    min_value=1,
    step=1
)

if st.button("Run DDoS Analysis"):

    tool_used = "DDoS"

    # ---------------- LOCAL DDOS ANALYSIS ----------------

    tool_output = detect_ddos(
        ddos_ip,
        ddos_requests
    )

    # # ---------------- LIVE IP REPUTATION ----------------
    # live_output, abuse_score = abuseipdb_check(ip)


    # # live_output = abuseipdb_check(
    # #     ddos_ip
    # # )

    # # ---------------- MERGE RESULTS ----------------
     
    # tool_output += "\n" + live_output

    ai_report = get_ai_analysis(
        ddos_ip,
        tool_used,
        tool_output
    )

    save_log(
        st.session_state["user"],
        ddos_ip,
        tool_used,
        tool_output
    )

    st.subheader("🛠 Tool Used")

    st.success(tool_used)

    st.subheader("⚙ Tool Result")

    st.code(tool_output)

    # st.subheader("🤖 AI Security Analysis")

    # st.write(ai_report)

    # Store for PDF

    st.session_state["done"] = True

    st.session_state["inp"] = ddos_ip

    st.session_state["tool_used"] = tool_used

    st.session_state["tool_output"] = tool_output

    st.session_state["ai_report"] = ai_report


# =========================================================
# LOG DASHBOARD
# =========================================================

if st.checkbox("Show Logs Dashboard"):

    df = load_logs(
        st.session_state["user"],
        st.session_state["role"]
    )

    st.dataframe(df)


# =========================================================
# PDF REPORT
# =========================================================

if st.button("Generate PDF Report"):

    if st.session_state.get("done"):

        file_path = generate_pdf(

            st.session_state["inp"],

            st.session_state["tool_used"],

            st.session_state["tool_output"],

            st.session_state["ai_report"]
        )

        st.success("PDF Generated!")

        with open(file_path, "rb") as f:

            st.download_button(
                "Download Report",
                f,
                file_name="analysis_report.pdf"
            )

    else:

        st.warning("Run analysis first!")

