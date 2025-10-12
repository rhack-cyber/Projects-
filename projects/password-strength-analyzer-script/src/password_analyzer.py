import re
import getpass

def check_password_strength(password):
    score = 0
    feedback = []


    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Password is too short. It should be at least 8 characters long.")

    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("Add at least one uppercase letter.")

    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("Add at least one lowercase letter.")

    if re.search(r'[0-9]', password):
        score += 1
    else:
        feedback.append("Add at least one number.")

    if re.search(r'[^A-Za-z0-9]', password): # New condition for special characters
        score += 1
    else:
        feedback.append("Add at least one special character (e.g., !, @, #, $).")

    return score, feedback

def main():
   
    print("Welcome to the Password Strength Analyzer!")
    print("Enter 'Ctrl+C' to exit.")

    while True:
        try:

            password = getpass.getpass("Enter password: ")
            

            if not password:
                print("Password cannot be empty. Please try again.")
                continue

            score, feedback = check_password_strength(password)
            
            print("\n--- Password Strength Analysis ---")
            
            if score == 5:
                print("✅ Status: VERY STRONG")
                print("Your password is very strong! 👍")
            elif score >= 3:
                print("⚠️ Status: STRONG")
                print("Your password is of strong strength. To make it even stronger, consider the following:")
                for item in feedback:
                    print(f"- {item}")
            elif score >= 2:
                print("⚠️ Status: MEDIUM")
                print("Your password is of medium strength. To make it stronger, consider the following:")
                for item in feedback:
                    print(f"- {item}")
            else:
                print("❌ Status: WEAK")
                print("Your password is weak. You must improve it by addressing the following issues:")
                for item in feedback:
                    print(f"- {item}")

            print("----------------------------------\n")

        except KeyboardInterrupt:
            print("\nExiting script. Goodbye!")
            break

if __name__ == "__main__":
    main()