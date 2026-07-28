"""
ProStackHub Cybersecurity Internship - Task 3
Password Strength & Breach Checker

This script performs three functions:
1. Checks password strength using the zxcvbn library.
2. Checks whether a password has appeared in known data breaches, using the
   HaveIBeenPwned (HIBP) API with the k-anonymity model, so the full password
   or hash is never transmitted over the network.
3. Generates a strong, secure random password on request.
"""

import hashlib
import requests
from zxcvbn import zxcvbn
import secrets
import string


# ---------------------------------------------------------
# FUNCTION 1: Password Strength Check
# ---------------------------------------------------------
def check_strength(password):
    """
    Uses zxcvbn to analyze the password and assign a score from 0 to 4:
    0 = Very Weak (easily guessable)
    4 = Very Strong

    Returns a dictionary containing the score, a human-readable label,
    an estimated crack time, and improvement suggestions.
    """
    result = zxcvbn(password)

    strength_labels = {
        0: "Very Weak",
        1: "Weak",
        2: "Fair",
        3: "Strong",
        4: "Very Strong"
    }

    return {
        "score": result["score"],
        "label": strength_labels[result["score"]],
        "crack_time": result["crack_times_display"]["offline_slow_hashing_1e4_per_second"],
        "warning": result["feedback"]["warning"],
        "suggestions": result["feedback"]["suggestions"]
    }


# ---------------------------------------------------------
# FUNCTION 2: Breach Check using HaveIBeenPwned API (k-anonymity)
# ---------------------------------------------------------
def check_breach(password):
    """
    Checks the password against the HaveIBeenPwned breach database.

    Steps:
    1. Hash the password using SHA-1.
    2. Send only the first 5 characters of the hash ("prefix") to the HIBP API.
    3. The server returns all hash suffixes that share that same prefix.
    4. Locally, check whether our full hash suffix appears in that returned list.

    This way, the full password or full hash is never sent over the network -
    only a 5-character prefix is shared, which preserves privacy (k-anonymity).
    """
    # Step 1: Hash the password with SHA-1 and convert to uppercase hex
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()

    # Step 2: Split the hash into prefix (first 5 chars) and suffix (the rest)
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    # Step 3: Query the HIBP API with only the prefix
    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        return {"error": f"Could not connect to the HIBP API: {e}"}

    # Step 4: Search for our suffix in the returned list
    hashes = response.text.splitlines()

    for line in hashes:
        hash_suffix, count = line.split(':')
        if hash_suffix == suffix:
            return {
                "breached": True,
                "count": int(count)
            }

    return {"breached": False, "count": 0}


# ---------------------------------------------------------
# FUNCTION 3: Secure Password Generator
# ---------------------------------------------------------
def generate_password(length=16, use_symbols=True):
    """
    Generates a cryptographically secure random password.
    Uses the 'secrets' module (more secure than the 'random' module,
    since it is designed for generating security-sensitive values).
    """
    characters = string.ascii_letters + string.digits
    if use_symbols:
        characters += "!@#$%^&*()_+-="

    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password


# ---------------------------------------------------------
# MAIN PROGRAM
# ---------------------------------------------------------
def main():
    print("=" * 55)
    print(" ProStackHub - Password Strength & Breach Checker")
    print("=" * 55)

    while True:
        print("\nOptions:")
        print("1. Check a password (strength + breach status)")
        print("2. Generate a new secure password")
        print("3. Exit")

        choice = input("\nSelect an option (1/2/3): ").strip()

        if choice == "1":
            password = input("Enter your password: ")

            # Strength check
            strength = check_strength(password)
            print(f"\n--- Strength Result ---")
            print(f"Score: {strength['score']}/4  ({strength['label']})")
            print(f"Estimated crack time: {strength['crack_time']}")
            if strength['warning']:
                print(f"Warning: {strength['warning']}")
            if strength['suggestions']:
                print(f"Suggestions: {', '.join(strength['suggestions'])}")

            # Breach check
            print(f"\n--- Breach Check Result ---")
            breach_result = check_breach(password)
            if "error" in breach_result:
                print(breach_result["error"])
            elif breach_result["breached"]:
                print(f"⚠️  This password has appeared in {breach_result['count']} known data breaches!")
                print("You should change this password immediately.")
            else:
                print("✅ Good news: This password was not found in any known breach.")

        elif choice == "2":
            length = input("Desired password length (default 16): ").strip()
            length = int(length) if length.isdigit() else 16
            new_password = generate_password(length=length)
            print(f"\nGenerated Password: {new_password}")

        elif choice == "3":
            print("Exiting program. Goodbye!")
            break

        else:
            print("Invalid option, please try again.")


if __name__ == "__main__":
    main()
