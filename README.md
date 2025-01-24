# Secured-File-Encryption


```markdown
# Secured File Encryption

## Overview
"Secured File Encryption" is a Python-based application that implements file encryption and decryption using AES (Advanced Encryption Standard) and RSA (Rivest-Shamir-Adleman) encryption techniques. This project ensures the confidentiality and security of sensitive data.

## Features
- AES encryption for file content.
- RSA encryption for securely sharing keys.
- Support for file decryption using secure keys.
- User-friendly implementation with modular code.

## Installation
1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/Secured-File-Encryption.git
   ```
2. Navigate to the project directory:
   ```bash
   cd Secured-File-Encryption
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage
1. Run the main script:
   ```bash
   python main.py
   ```
2. Follow the on-screen instructions to encrypt or decrypt files.

## Technologies Used
- **Python**
- **AES Encryption** (using `pycryptodome` library)
- **RSA Encryption**

## Contributing
Feel free to contribute by opening issues or submitting pull requests.

## License
This project is licensed under the MIT License.
```

## Sample Python Files

### main.py
```python
from encryption.aes_encryption import encrypt_file, decrypt_file
from encryption.rsa_encryption import generate_keys, encrypt_key, decrypt_key

def main():
    print("Welcome to Secured File Encryption!")
    choice = input("Choose an option: 1. Encrypt 2. Decrypt\n")

    if choice == "1":
        file_path = input("Enter the file path to encrypt: ")
        encrypted_file, key = encrypt_file(file_path)
        print(f"File encrypted successfully: {encrypted_file}")
        print(f"Encryption Key: {key}")
    elif choice == "2":
        file_path = input("Enter the file path to decrypt: ")
        key = input("Enter the decryption key: ")
        decrypted_file = decrypt_file(file_path, key)
        print(f"File decrypted successfully: {decrypted_file}")
    else:
        print("Invalid choice. Exiting.")

if __name__ == "__main__":
    main()
```

### encryption/aes_encryption.py
```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

def encrypt_file(file_path):
    key = get_random_bytes(16)  # Generate AES key
    cipher = AES.new(key, AES.MODE_EAX)

    with open(file_path, 'rb') as f:
        data = f.read()
    ciphertext, tag = cipher.encrypt_and_digest(data)

    encrypted_file = file_path + '.enc'
    with open(encrypted_file, 'wb') as f:
        f.write(cipher.nonce)
        f.write(tag)
        f.write(ciphertext)

    return encrypted_file, key

def decrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()

    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)

    decrypted_file = file_path.replace('.enc', '')
    with open(decrypted_file, 'wb') as f:
        f.write(data)

    return decrypted_file
```

### encryption/rsa_encryption.py
```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_key(public_key, key):
    recipient_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_key = cipher_rsa.encrypt(key)
    return encrypted_key

def decrypt_key(private_key, encrypted_key):
    private_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    key = cipher_rsa.decrypt(encrypted_key)
    return key
```

### requirements.txt
```
pycryptodome
```

