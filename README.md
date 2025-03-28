# TextVault

A secure text encryption tool with both CLI and GUI interfaces. TextVault uses AES encryption (via Fernet) with PBKDF2 key derivation for strong security.

## Features

- Strong AES encryption
- Password-based key derivation using PBKDF2
- Both CLI and GUI interfaces
- Simple and intuitive user interface
- Secure password handling

## Installation

1. Clone this repository
2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### GUI Mode
To launch the graphical interface:
```bash
python textvault.py --gui
```

### CLI Mode

To encrypt text:
```bash
python textvault.py --encrypt "Your text here" --password "your_password"
```

To decrypt text:
```bash
python textvault.py --decrypt "encrypted_text_here" --password "your_password"
```

## Security Features

- Uses AES encryption (via Fernet)
- PBKDF2 key derivation with 100,000 iterations
- SHA256 hashing algorithm
- Secure password handling
- No storage of passwords or encrypted data

## Note

This tool is for educational purposes. While it uses strong encryption, always use established security tools for sensitive data in production environments. 