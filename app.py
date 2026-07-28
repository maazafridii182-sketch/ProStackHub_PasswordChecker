"""
ProStackHub Cybersecurity Internship - Task
Password Strength & Breach Checker (Web Version)

This is a Streamlit-based web interface for the password checker.
Run locally with:  streamlit run app.py
Or deploy for free on Streamlit Community Cloud so it works on any
device (including mobile phones) through a simple web link.
"""

import hashlib
import requests
from zxcvbn import zxcvbn
import secrets
import string
import streamlit as st

# ---------------------------------------------------------
# Core logic (same as the CLI version)
# ---------------------------------------------------------

def check_strength(password):
    result = zxcvbn(password)
    strength_labels = {
        0: "Very Weak",
        1: "Weak",
        2: "Fair",
        3: "Strong",
        4: "Very Strong",
    }
    return {
        "score": result["score"],
        "label": strength_labels[result["score"]],
        "crack_time": result["crack_times_display"]["offline_slow_hashing_1e4_per_second"],
        "warning": result["feedback"]["warning"],
        "suggestions": result["feedback"]["suggestions"],
    }


def check_breach(password):
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        return {"error": f"Could not connect to the HIBP API: {e}"}

    hashes = response.text.splitlines()
    for line in hashes:
        hash_suffix, count = line.split(':')
        if hash_suffix == suffix:
            return {"breached": True, "count": int(count)}

    return {"breached": False, "count": 0}


def generate_password(length=16, use_symbols=True):
    characters = string.ascii_letters + string.digits
    if use_symbols:
        characters += "!@#$%^&*()_+-="
    return ''.join(secrets.choice(characters) for _ in range(length))


# ---------------------------------------------------------
# Streamlit Web Interface
# ---------------------------------------------------------

st.set_page_config(page_title="Password Strength & Breach Checker", page_icon="🔐")

st.title("🔐 Password Strength & Breach Checker")
st.caption("ProStackHub Cybersecurity Internship Project")

tab1, tab2 = st.tabs(["Check a Password", "Generate a Secure Password"])

# --- TAB 1: Check password ---
with tab1:
    st.subheader("Check Password Strength & Breach Status")
    password = st.text_input("Enter a password to check:", type="password")

    if st.button("Check Password", use_container_width=True):
        if not password:
            st.warning("Please enter a password first.")
        else:
            strength = check_strength(password)

            st.markdown("### Strength Result")
            score = strength["score"]
            colors = ["🔴", "🟠", "🟡", "🟢", "🟢"]
            st.write(f"{colors[score]} **Score: {score}/4 ({strength['label']})**")
            st.write(f"Estimated crack time: **{strength['crack_time']}**")
            if strength["warning"]:
                st.info(f"Warning: {strength['warning']}")
            if strength["suggestions"]:
                st.write("Suggestions: " + ", ".join(strength["suggestions"]))

            st.markdown("### Breach Check Result")
            with st.spinner("Checking HaveIBeenPwned database..."):
                breach_result = check_breach(password)

            if "error" in breach_result:
                st.error(breach_result["error"])
            elif breach_result["breached"]:
                st.error(
                    f"⚠️ This password has appeared in **{breach_result['count']:,}** known data breaches! "
                    "You should change it immediately."
                )
            else:
                st.success("✅ Good news: This password was not found in any known breach.")

# --- TAB 2: Generate password ---
with tab2:
    st.subheader("Generate a New Secure Password")
    length = st.slider("Password length", min_value=8, max_value=32, value=16)
    use_symbols = st.checkbox("Include symbols", value=True)

    if st.button("Generate Password", use_container_width=True):
        new_password = generate_password(length=length, use_symbols=use_symbols)
        st.code(new_password, language=None)
        st.caption("Tap the copy icon in the box above to copy this password.")

st.divider()
st.caption("Built with Python, zxcvbn, and the HaveIBeenPwned API (k-anonymity model) | ProStackHub Cybersecurity Internship")
