import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import sys
import tkinter as tk
from tkinter import messagebox, scrolledtext
import argparse
import random
import time
from colorama import init, Fore, Back, Style

# Initialize colorama for Windows support
init()

# Version and creator information
VERSION = "1.0.0"
CREATOR = "@its-hritika"
DESCRIPTION = "A secure text encryption tool using AES encryption with a user-friendly interface"

# Color scheme
COLORS = {
    'primary': '#FFFFFF',      # White
    'secondary': '#F5F5F5',    # Light gray
    'accent': '#3498DB',       # Bright blue
    'success': '#2ECC71',      # Green
    'warning': '#F1C40F',      # Yellow
    'error': '#E74C3C',        # Red
    'text': '#2C3E50',         # Dark blue-gray
    'input': '#FFFFFF',        # White
    'button': '#3498DB',       # Bright blue
    'button_hover': '#2980B9', # Darker blue
    'border': '#E0E0E0'        # Light gray for borders
}

class BannerGenerator:
    """Handles banner generation and styling"""
    @staticmethod
    def get_banner():
        return r"""
        .___________. __________   ___ .___________.____    ____  ___      __    __   __      .___________.
        |           ||   ____\  \ /  / |           |\   \  /   / /   \    |  |  |  | |  |     |           |
        `---|  |----`|  |__   \  V  /  `---|  |----` \   \/   / /  ^  \   |  |  |  | |  |     `---|  |----`
            |  |     |   __|   >   <       |  |       \      / /  /_\  \  |  |  |  | |  |         |  |     
            |  |     |  |____ /  .  \      |  |        \    / /  _____  \ |  `--'  | |  `----.    |  |     
            |__|     |_______/__/ \__\     |__|         \__/ /__/     \__\ \______/  |_______|    |__|     
                                                                                                        
        """

    @staticmethod
    def get_info_text():
        return f"""
        {Fore.CYAN}TextVault v{VERSION}{Style.RESET_ALL}
        {Fore.GREEN}Created by {CREATOR}{Style.RESET_ALL}
        {Fore.YELLOW}{DESCRIPTION}{Style.RESET_ALL}
        """

    @staticmethod
    def get_random_color():
        colors = [
            '#FF0000', '#00FF00', '#0000FF', '#FFFF00', '#FF00FF', '#00FFFF',
            '#FFA500', '#800080', '#008000', '#FFC0CB', '#A52A2A', '#FFD700'
        ]
        return random.choice(colors)

class TextVault:
    def __init__(self):
        self.key = None
        self.cipher_suite = None

    def generate_key(self, password):
        """Generate a key from the password using PBKDF2"""
        salt = b'TextVault_Salt'  # In production, use a random salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        self.key = key
        self.cipher_suite = Fernet(self.key)

    def encrypt_text(self, text):
        """Encrypt the given text"""
        if not self.cipher_suite:
            raise ValueError("Key not generated. Call generate_key first.")
        return self.cipher_suite.encrypt(text.encode()).decode()

    def decrypt_text(self, encrypted_text):
        """Decrypt the given text"""
        if not self.cipher_suite:
            raise ValueError("Key not generated. Call generate_key first.")
        return self.cipher_suite.decrypt(encrypted_text.encode()).decode()

class TextVaultGUI:
    def __init__(self):
        self.vault = TextVault()
        self.window = tk.Tk()
        self.window.title(f"TextVault v{VERSION} - Secure Text Encryption")
        self.window.geometry("800x600")
        self.window.configure(bg=COLORS['primary'])
        self.setup_gui()
        self.animate_banner()

    def setup_gui(self):
        # Banner Frame
        banner_frame = tk.Frame(self.window, bg=COLORS['primary'])
        banner_frame.pack(pady=10, padx=10, fill='x')

        # Create banner label with larger font and proper spacing
        self.banner_label = tk.Label(
            banner_frame, 
            text=BannerGenerator.get_banner(), 
            font=('Courier', 10),
            justify='center',
            pady=10,
            bg=COLORS['primary'],
            fg=COLORS['text']
        )
        self.banner_label.pack(expand=True)

        # Info Frame
        info_frame = tk.Frame(self.window, bg=COLORS['primary'])
        info_frame.pack(pady=5, padx=10, fill='x')

        info_text = BannerGenerator.get_info_text()
        self.info_label = tk.Label(
            info_frame,
            text=info_text,
            font=('Courier', 9),
            justify='center',
            pady=5,
            bg=COLORS['primary'],
            fg=COLORS['text']
        )
        self.info_label.pack(expand=True)

        # Password Frame
        password_frame = tk.Frame(self.window, bg=COLORS['primary'])
        password_frame.pack(pady=10, padx=10, fill='x')

        tk.Label(
            password_frame, 
            text="Password:", 
            bg=COLORS['primary'],
            fg=COLORS['text']
        ).pack(side='left')
        
        self.password_entry = tk.Entry(
            password_frame, 
            show="*",
            bg=COLORS['input'],
            fg=COLORS['text'],
            insertbackground=COLORS['text'],
            relief='solid',
            bd=1
        )
        self.password_entry.pack(side='left', fill='x', expand=True)

        # Text Area
        text_frame = tk.Frame(self.window, bg=COLORS['primary'])
        text_frame.pack(pady=10, padx=10, fill='both', expand=True)

        self.text_area = scrolledtext.ScrolledText(
            text_frame, 
            wrap=tk.WORD,
            bg=COLORS['input'],
            fg=COLORS['text'],
            insertbackground=COLORS['text'],
            relief='solid',
            bd=1
        )
        self.text_area.pack(fill='both', expand=True)

        # Buttons Frame
        button_frame = tk.Frame(self.window, bg=COLORS['primary'])
        button_frame.pack(pady=10, padx=10, fill='x')

        # Create buttons with specific width and padding
        buttons = [
            ("Encrypt", self.encrypt, COLORS['success']),
            ("Decrypt", self.decrypt, COLORS['accent']),
            ("Clear", self.clear, COLORS['error'])
        ]

        for text, command, color in buttons:
            btn = tk.Button(
                button_frame,
                text=text,
                command=command,
                width=10,
                padx=5,
                bg=color,
                fg='white',
                activebackground=color,
                activeforeground='white',
                relief='flat'
            )
            btn.pack(side='left', padx=5)

        # Add some padding to the bottom
        tk.Frame(self.window, height=10, bg=COLORS['primary']).pack()

    def animate_banner(self):
        """Animate the banner with random colors"""
        self.banner_label.config(fg=BannerGenerator.get_random_color())
        self.window.after(1000, self.animate_banner)

    def encrypt(self):
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return

        try:
            self.vault.generate_key(password)
            text = self.text_area.get("1.0", tk.END).strip()
            if text:
                encrypted = self.vault.encrypt_text(text)
                self.text_area.delete("1.0", tk.END)
                self.text_area.insert("1.0", encrypted)
                messagebox.showinfo("Success", "Text encrypted successfully!")
            else:
                messagebox.showwarning("Warning", "Please enter text to encrypt")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    def decrypt(self):
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return

        try:
            self.vault.generate_key(password)
            text = self.text_area.get("1.0", tk.END).strip()
            if text:
                decrypted = self.vault.decrypt_text(text)
                self.text_area.delete("1.0", tk.END)
                self.text_area.insert("1.0", decrypted)
                messagebox.showinfo("Success", "Text decrypted successfully!")
            else:
                messagebox.showwarning("Warning", "Please enter text to decrypt")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

    def clear(self):
        self.text_area.delete("1.0", tk.END)
        self.password_entry.delete(0, tk.END)
        messagebox.showinfo("Success", "Text and password cleared!")

    def run(self):
        self.window.mainloop()

def cli_encrypt(text, password):
    vault = TextVault()
    vault.generate_key(password)
    return vault.encrypt_text(text)

def cli_decrypt(encrypted_text, password):
    vault = TextVault()
    vault.generate_key(password)
    return vault.decrypt_text(encrypted_text)

def print_cli_banner():
    """Print the banner and info in CLI mode"""
    print(f"{Fore.CYAN}{BannerGenerator.get_banner()}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{BannerGenerator.get_info_text()}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{'-' * 80}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(
        description=f'{DESCRIPTION}\nCreated by {CREATOR}',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--gui', action='store_true', help='Launch the GUI version')
    parser.add_argument('--encrypt', help='Text to encrypt')
    parser.add_argument('--decrypt', help='Text to decrypt')
    parser.add_argument('--password', help='Password for encryption/decryption')
    parser.add_argument('--version', action='version', version=f'TextVault v{VERSION}')

    args = parser.parse_args()

    # Show banner and help if no arguments provided
    if len(sys.argv) == 1:
        print_cli_banner()
        print(f"{Fore.CYAN}Usage Examples:{Style.RESET_ALL}")
        print(f"{Fore.GREEN}GUI Mode:{Style.RESET_ALL}")
        print("  python textvault.py --gui")
        print(f"\n{Fore.GREEN}CLI Mode:{Style.RESET_ALL}")
        print("  python textvault.py --encrypt \"Hello World\" --password \"mypassword\"")
        print("  python textvault.py --decrypt \"encrypted_text\" --password \"mypassword\"")
        print(f"\n{Fore.YELLOW}Options:{Style.RESET_ALL}")
        parser.print_help()
        return

    if args.gui:
        app = TextVaultGUI()
        app.run()
        return

    # Print banner and info in CLI mode
    print_cli_banner()

    if not args.password:
        print(f"{Fore.RED}Error: Password is required for CLI operations{Style.RESET_ALL}")
        sys.exit(1)

    if args.encrypt:
        try:
            encrypted = cli_encrypt(args.encrypt, args.password)
            print(f"{Fore.GREEN}Encrypted text:{Style.RESET_ALL}", encrypted)
        except Exception as e:
            print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
            sys.exit(1)

    if args.decrypt:
        try:
            decrypted = cli_decrypt(args.decrypt, args.password)
            print(f"{Fore.GREEN}Decrypted text:{Style.RESET_ALL}", decrypted)
        except Exception as e:
            print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
            sys.exit(1)

if __name__ == "__main__":
    main()