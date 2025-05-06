**AES Encryption Tool**

A simple and secure command-line tool for encrypting and decrypting messages using AES encryption.

Table of Contents
- about
- features
- how-it-works
- usage
- security-considerations
- contributing
- license

About

The AES Encryption Tool is a Java-based command-line application that provides a simple and secure way to encrypt and decrypt messages using AES encryption. This tool is designed to be easy to use and provides a high level of security for sensitive data.

Features
- *AES Encryption*: Uses the Advanced Encryption Standard (AES) algorithm to encrypt and decrypt messages.
- *Password-Based Key Derivation*: Derives a secret key from a password using PBKDF2 with HMAC SHA-256.
- *Secure Random Salt Generation*: Generates a random salt for key derivation to prevent rainbow table attacks.
- *Base64 Encoding*: Encodes encrypted messages using base64 for easy storage and transmission.

How it Works
1. *Key Derivation*: The tool derives a secret key from a password using PBKDF2 with HMAC SHA-256. A random salt is generated for key derivation to prevent rainbow table attacks.
2. *Encryption*: The tool uses the AES algorithm to encrypt messages. The encrypted message is then encoded using base64 for easy storage and transmission.
3. *Decryption*: The tool uses the same secret key to decrypt the encrypted message. The decrypted message is then returned to the user.

Usage
1. *Run the Tool*: Run the AES Encryption Tool using Java.
2. *Choose an Option*: Choose an option to encrypt or decrypt a message.
3. *Enter Message*: Enter the message to encrypt or decrypt.
4. *Enter Password*: Enter the password to derive the secret key.

Security Considerations
- *Use Strong Passwords*: Use strong and unique passwords to derive secret keys.
- *Keep Passwords Secret*: Keep passwords secret to prevent unauthorized access to encrypted data.
- *Use Secure Random Salts*: Use secure random salts for key derivation to prevent rainbow table attacks.

Contributing
Contributions are welcome! If you'd like to contribute to the AES Encryption Tool, please fork the repository and submit a pull request.

License
The AES Encryption Tool is licensed under the MIT License. See the LICENSE file for details.
