from encryption import generate_key

if __name__ == "__main__":
    password = input("Enter a password to generate an encryption key: ")
    generate_key(password)

