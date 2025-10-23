**Password Toolkit**  
**Atheer Almomtan — 202246520 — F05**

---

## Overview  
This Homework is a simple command-line toolkit
It provides basic password security tools such as:  
- Password strength checking  
- PBKDF2 password hashing and user storage  
- Bloom filter blacklist  
- Password cracking simulation  
- AES-GCM encryption and decryption  

---

## Requirements  
- Python 3.8 or later  
- PyCryptodome library  

### To install dependencies:
```bash
pip install pycryptodome
```

## Usage

All commands must be run from the terminal inside the project folder.

### Examples:

Check password strength:
```bash
python toolkit.py check-strength --password "MyP@ssw0rd!"
```

Hash a password and store user:
```bash
python toolkit.py hash-password --username alice --password "MyP@ssw0rd!"
```

Add a password to the bloom filter blacklist:
```bash
python toolkit.py add-blacklist --password "123456"
```

Simulate password cracking:
```bash
python toolkit.py crack-password --hash "stored_hash_here"
```

Encrypt a file using AES-GCM:
```bash
python toolkit.py encrypt --input secret.txt --output secret.enc --key "myencryptionkey"
```

Decrypt a file using AES-GCM:
```bash
python toolkit.py decrypt --input secret.enc --output secret_decrypted.txt --key "myencryptionkey"
```

---

## Notes

- Ensure that you have Python 3.8 or later installed.
- The PyCryptodome library is required for cryptographic functions.
- The bloom filter helps to quickly check if a password is blacklisted.
- Password cracking simulation is for educational purposes only.
- AES-GCM encryption requires a secure key; keep it confidential.

---

## Output Files

	•	data/sample_users.json — stores users, salts, and hashes
	•	data/bloom.bin — Bloom filter file
	•	data/plain.enc — encrypted file output
	•	data/plain.dec — decrypted file output

---

## Author

Atheer Almomtan  
Student ID: 202246520  
Section: F05