import math
import re

# List of common weak passwords to flag immediately
COMMON_WEAK_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "123456789", 
    "12345", "1234", "111111", "admin", "prince", "welcome"
}

def calculate_entropy(password):
    """Calculates password entropy in bits based on character set size."""
    charset_size = 0
    if re.search(r'[a-z]', password):
        charset_size += 26
    if re.search(r'[A-Z]', password):
        charset_size += 26
    if re.search(r'[0-9]', password):
        charset_size += 10
    if re.search(r'[^a-zA-Z0-9]', password):
        charset_size += 32  # Standard special characters

    if charset_size == 0 or len(password) == 0:
        return 0.0

    # Entropy formula: E = length * log2(charset_size)
    return round(len(password) * math.log2(charset_size), 2)

def evaluate_password(password):
    """Evaluates password strength and returns score, strength label, and feedback."""
    feedback = []
    
    # Check against common weak list
    if password.lower() in COMMON_WEAK_PASSWORDS:
        return "Very Weak", 0, 0.0, ["This password is on the top list of common leaked passwords!"]

    # Check length
    length = len(password)
    if length < 8:
        feedback.append("Password is too short (aim for at least 12 characters).")
    elif length >= 12:
        feedback.append("Good length.")

    # Check character types
    if not re.search(r'[a-z]', password):
        feedback.append("Add lowercase letters.")
    if not re.search(r'[A-Z]', password):
        feedback.append("Add uppercase letters.")
    if not re.search(r'[0-9]', password):
        feedback.append("Add numbers.")
    if not re.search(r'[^a-zA-Z0-9]', password):
        feedback.append("Add special characters (e.g., @, #, $).")

    # Calculate Entropy
    entropy = calculate_entropy(password)

    # Categorize strength based on entropy & length
    if entropy < 30 or length < 6:
        strength = "Very Weak"
        score = 1
    elif entropy < 50 or length < 8:
        strength = "Weak"
        score = 2
    elif entropy < 70 or length < 12:
        strength = "Moderate"
        score = 3
    elif entropy < 90:
        strength = "Strong"
        score = 4
    else:
        strength = "Very Strong"
        score = 5

    return strength, score, entropy, feedback

if __name__ == "__main__":
    print("--- Password Strength & Entropy Evaluator ---")
    user_password = input("Enter a password to test: ")
    
    strength, score, entropy, feedback = evaluate_password(user_password)
    
    print("\n--- Evaluation Results ---")
    print(f"Strength Rating : {strength} ({score}/5)")
    print(f"Entropy         : {entropy} bits")
    print("\nFeedback/Tips:")
    for tip in feedback:
        print(f"- {tip}")