from encryption import encrypt_file, decrypt_file

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Secure File Storage System")
    parser.add_argument("operation", choices=["encrypt", "decrypt"], help="Operation to perform")
    parser.add_argument("file", help="File to process")
    parser.add_argument("password", help="Password for encryption/decryption")

    args = parser.parse_args()

    if args.operation == "encrypt":
        encrypt_file(args.file, args.password)
    elif args.operation == "decrypt":
        decrypt_file(args.file, args.password)
