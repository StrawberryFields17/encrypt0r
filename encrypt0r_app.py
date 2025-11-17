import os
import sys
import base64
import secrets
import tempfile
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from tkinter.scrolledtext import ScrolledText
from tkinter import ttk

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet


APP_NAME = "encrypt0r"
LOCK_EXTENSION = ".locked"
PBKDF2_ITERATIONS = 390000  # reasonably strong

# Dark theme colors
BG_MAIN = "#020617"      # almost black (slate-950)
BG_INPUT = "#020617"
FG_TEXT = "#e5e7eb"      # gray-200
FG_SUBTLE = "#9ca3af"    # gray-400
ACCENT = "#22c55e"       # green-500
ACCENT_DARK = "#16a34a"  # green-600


# ---------- High DPI / anti-blur for Windows ----------

def enable_high_dpi():
    """
    Enable high-DPI awareness on Windows so the UI is crisp at 150% / 200% scaling.
    Safe no-op on other platforms.
    """
    if sys.platform.startswith("win"):
        try:
            import ctypes
            try:
                # Windows 8.1+ per-monitor DPI awareness
                ctypes.windll.shcore.SetProcessDpiAwareness(1)
            except Exception:
                # Older Windows versions
                ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            # If anything fails, just ignore and continue
            pass


# ---------- Crypto helpers ----------

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """
    Derive a Fernet-compatible key from a password and salt using PBKDF2-HMAC-SHA256.
    Returns a key suitable for Fernet.
    """
    password_bytes = password.encode("utf-8")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    key = kdf.derive(password_bytes)
    return base64.urlsafe_b64encode(key)


def encrypt_file(path: str, password: str, delete_original: bool, log_callback):
    """
    Encrypt a single file:
    - Generate a random salt
    - Derive key using password + salt
    - Encrypt with Fernet
    - Write [salt][ciphertext] to <path>.locked
    - Optionally delete original
    """
    if path.endswith(LOCK_EXTENSION):
        log_callback(f"Skipping already encrypted file: {path}")
        return False

    try:
        with open(path, "rb") as f:
            plaintext = f.read()
    except Exception as e:
        log_callback(f"Failed to read {path}: {e}")
        return False

    log_callback(f"Encrypting: {path}")

    salt = secrets.token_bytes(16)
    key = derive_key_from_password(password, salt)
    fernet = Fernet(key)
    ciphertext = fernet.encrypt(plaintext)

    out_path = path + LOCK_EXTENSION
    try:
        with open(out_path, "wb") as f:
            f.write(salt + ciphertext)
    except Exception as e:
        log_callback(f"Failed to write encrypted file for {path}: {e}")
        return False

    if delete_original:
        try:
            os.remove(path)
            log_callback(f"Deleted original: {path}")
        except Exception as e:
            log_callback(f"Failed to delete original {path}: {e}")

    return True


def decrypt_file(path: str, password: str, log_callback):
    """
    Decrypt a single .locked file:
    - Read first 16 bytes as salt
    - Rest is ciphertext
    - Derive key using same salt + password
    - Decrypt with Fernet
    - Write to file without .locked extension
    - Delete encrypted file on success
    Returns True if decryption succeeded, False otherwise.
    """
    if not path.endswith(LOCK_EXTENSION):
        log_callback(f"Skipping non-encrypted file: {path}")
        return False

    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception as e:
        log_callback(f"Failed to read {path}: {e}")
        return False

    if len(data) < 17:
        log_callback(f"File too small / corrupted: {path}")
        return False

    salt = data[:16]
    ciphertext = data[16:]

    key = derive_key_from_password(password, salt)
    fernet = Fernet(key)

    try:
        plaintext = fernet.decrypt(ciphertext)
    except Exception as e:
        # Wrong password or corrupted file
        log_callback(f"Failed to decrypt {path}: {e}")
        return False

    out_path = path[: -len(LOCK_EXTENSION)]
    try:
        with open(out_path, "wb") as f:
            f.write(plaintext)
    except Exception as e:
        log_callback(f"Failed to write decrypted file for {path}: {e}")
        return False

    try:
        os.remove(path)
        log_callback(f"Removed encrypted file: {path}")
    except Exception as e:
        log_callback(f"Failed to remove encrypted file {path}: {e}")

    return True


# ---------- GUI app (folder mode) ----------

class Encrypt0rApp:
    def __init__(self, master):
        self.master = master
        master.title(APP_NAME)

        # Base window styling
        master.configure(bg=BG_MAIN)

        # Try to set icon if available
        try:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            icon_path = os.path.join(base_dir, "assets", "encrypt0r_icon.ico")
            if os.path.exists(icon_path):
                master.iconbitmap(icon_path)
        except Exception:
            pass

        # ttk style
        self.style = ttk.Style(master)
        try:
            self.style.theme_use("clam")
        except Exception:
            pass

        default_font = ("Segoe UI", 10)
        title_font = ("Segoe UI", 16, "bold")

        self.style.configure("Encrypt0r.TFrame", background=BG_MAIN)
        self.style.configure("Encrypt0r.TLabel",
                             background=BG_MAIN,
                             foreground=FG_TEXT,
                             font=default_font)
        self.style.configure("Encrypt0r.Subtle.TLabel",
                             background=BG_MAIN,
                             foreground=FG_SUBTLE,
                             font=("Segoe UI", 9))
        self.style.configure("Encrypt0r.TEntry",
                             fieldbackground=BG_INPUT,
                             foreground=FG_TEXT,
                             bordercolor="#111827",
                             lightcolor="#111827",
                             darkcolor="#020617")
        self.style.configure("Encrypt0r.TButton",
                             background=ACCENT,
                             foreground="#020617",
                             borderwidth=0,
                             focusthickness=1,
                             focuscolor=ACCENT_DARK,
                             font=default_font,
                             padding=(10, 4))
        self.style.map("Encrypt0r.TButton",
                       background=[("active", ACCENT_DARK)])

        self.style.configure("Encrypt0r.Secondary.TButton",
                             background="#111827",
                             foreground=FG_TEXT,
                             borderwidth=0,
                             font=default_font,
                             padding=(10, 4))
        self.style.map("Encrypt0r.Secondary.TButton",
                       background=[("active", "#1f2937")])

        self.style.configure("Encrypt0r.TCheckbutton",
                             background=BG_MAIN,
                             foreground=FG_SUBTLE,
                             font=("Segoe UI", 9))

        # Main frame
        frame = ttk.Frame(master, style="Encrypt0r.TFrame", padding=(16, 16, 16, 16))
        frame.grid(row=0, column=0, sticky="nsew")
        master.columnconfigure(0, weight=1)
        master.rowconfigure(0, weight=1)

        # Header
        title_label = ttk.Label(frame, text="encrypt0r", style="Encrypt0r.TLabel",
                                font=title_font)
        title_label.grid(row=0, column=0, columnspan=3, sticky="w")

        subtitle_label = ttk.Label(
            frame,
            text="Encrypt and decrypt folders with a single password.",
            style="Encrypt0r.Subtle.TLabel"
        )
        subtitle_label.grid(row=1, column=0, columnspan=3, sticky="w", pady=(0, 12))

        # Folder selection
        folder_label = ttk.Label(frame, text="Folder", style="Encrypt0r.TLabel")
        folder_label.grid(row=2, column=0, padx=(0, 8), pady=5, sticky="e")

        self.folder_var = tk.StringVar()
        self.folder_entry = ttk.Entry(frame, textvariable=self.folder_var,
                                      width=50, style="Encrypt0r.TEntry")
        self.folder_entry.grid(row=2, column=1, padx=(0, 8), pady=5, sticky="we")

        self.browse_button = ttk.Button(frame, text="Browse...",
                                        style="Encrypt0r.Secondary.TButton",
                                        command=self.browse_folder)
        self.browse_button.grid(row=2, column=2, pady=5, sticky="we")

        # Password row
        password_label = ttk.Label(frame, text="Password", style="Encrypt0r.TLabel")
        password_label.grid(row=3, column=0, padx=(0, 8), pady=5, sticky="e")

        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(frame, textvariable=self.password_var,
                                        show="*", width=50, style="Encrypt0r.TEntry")
        self.password_entry.grid(row=3, column=1, padx=(0, 8), pady=5, sticky="we")

        # Right side: copy button
        self.copy_password_button = ttk.Button(
            frame,
            text="Copy password",
            style="Encrypt0r.Secondary.TButton",
            command=self.copy_password_to_clipboard
        )
        self.copy_password_button.grid(row=3, column=2, pady=5, sticky="we")

        # Show password toggle
        self.show_password_var = tk.BooleanVar(value=False)
        self.show_password_checkbox = ttk.Checkbutton(
            frame,
            text="Show password",
            style="Encrypt0r.TCheckbutton",
            variable=self.show_password_var,
            command=self.toggle_password_visibility
        )
        self.show_password_checkbox.grid(row=4, column=1, pady=(0, 8), sticky="w")

        # Confirm password
        confirm_label = ttk.Label(frame, text="Confirm password", style="Encrypt0r.TLabel")
        confirm_label.grid(row=5, column=0, padx=(0, 8), pady=5, sticky="e")

        self.confirm_var = tk.StringVar()
        self.confirm_entry = ttk.Entry(frame, textvariable=self.confirm_var,
                                       show="*", width=50, style="Encrypt0r.TEntry")
        self.confirm_entry.grid(row=5, column=1, padx=(0, 8), pady=5, sticky="we")

        # Delete originals option
        self.delete_originals_var = tk.BooleanVar(value=True)
        self.delete_checkbox = ttk.Checkbutton(
            frame,
            text="Delete original files after encryption (recommended)",
            style="Encrypt0r.TCheckbutton",
            variable=self.delete_originals_var
        )
        self.delete_checkbox.grid(row=6, column=1, pady=(0, 12), sticky="w")

        # Buttons row
        buttons_frame = ttk.Frame(frame, style="Encrypt0r.TFrame")
        buttons_frame.grid(row=7, column=0, columnspan=3, pady=(0, 10), sticky="we")

        self.lock_button = ttk.Button(
            buttons_frame,
            text="Lock (Encrypt) Folder",
            style="Encrypt0r.TButton",
            command=self.lock_folder
        )
        self.lock_button.grid(row=0, column=0, padx=(0, 8), pady=5, sticky="w")

        self.unlock_button = ttk.Button(
            buttons_frame,
            text="Unlock (Decrypt) Folder",
            style="Encrypt0r.Secondary.TButton",
            command=self.unlock_folder
        )
        self.unlock_button.grid(row=0, column=1, padx=(0, 0), pady=5, sticky="w")

        # Log area
        log_label = ttk.Label(frame, text="Activity log", style="Encrypt0r.Subtle.TLabel")
        log_label.grid(row=8, column=0, columnspan=3, sticky="w")

        self.log_text = ScrolledText(frame, height=13, width=80)
        self.log_text.grid(row=9, column=0, columnspan=3, padx=0, pady=(4, 0), sticky="nsew")
        self.log_text.configure(
            bg=BG_MAIN,
            fg=FG_SUBTLE,
            insertbackground=FG_TEXT,
            borderwidth=1,
            relief="solid",
            font=("Segoe UI", 9)
        )

        # Layout stretch
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(9, weight=1)

        # Center window a bit (optional quality of life)
        master.update_idletasks()
        w = 780
        h = 520
        sw = master.winfo_screenwidth()
        sh = master.winfo_screenheight()
        x = int((sw - w) / 2)
        y = int((sh - h) / 2)
        master.geometry(f"{w}x{h}+{x}+{y}")

    # ---------- UI helpers ----------

    def log(self, message: str):
        self.log_text.configure(state="normal")
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.configure(state="disabled")
        self.master.update_idletasks()

    def browse_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.folder_var.set(folder)

    def validate_common_inputs(self):
        folder = self.folder_var.get()
        password = self.password_var.get()

        if not folder:
            messagebox.showerror(APP_NAME, "Please select a folder.")
            return None, None
        if not os.path.isdir(folder):
            messagebox.showerror(APP_NAME, "Selected folder does not exist.")
            return None, None
        if not password:
            messagebox.showerror(APP_NAME, "Please enter a password.")
            return None, None

        return folder, password

    def toggle_password_visibility(self):
        show_char = "" if self.show_password_var.get() else "*"
        self.password_entry.config(show=show_char)
        self.confirm_entry.config(show=show_char)

    def copy_password_to_clipboard(self):
        pwd = self.password_var.get()
        if not pwd:
            messagebox.showwarning(APP_NAME, "Password field is empty.")
            return
        self.master.clipboard_clear()
        self.master.clipboard_append(pwd)
        self.master.update()  # keep clipboard after app closes
        messagebox.showinfo(
            APP_NAME,
            "Password copied to clipboard.\n\n"
            "You can now paste it into your password manager."
        )

    # ---------- Actions ----------

    def lock_folder(self):
        folder, password = self.validate_common_inputs()
        if folder is None:
            return

        # Confirm password for encryption
        confirm = self.confirm_var.get()
        if password != confirm:
            messagebox.showerror(APP_NAME, "Passwords do not match.")
            return

        delete_originals = self.delete_originals_var.get()

        if not delete_originals:
            if not messagebox.askyesno(
                APP_NAME,
                "You chose NOT to delete the original files.\n\n"
                "That means the folder will not be truly secure, "
                "because unencrypted copies remain.\n\n"
                "Continue anyway?"
            ):
                return

        self.log("=== Locking (encrypting) folder ===")
        self.log(f"Folder: {folder}")
        self.log(f"Delete originals: {delete_originals}")
        self.log("Do NOT close encrypt0r while processing.\n")

        files_processed = 0
        files_encrypted = 0

        for root, dirs, files in os.walk(folder):
            for name in files:
                full_path = os.path.join(root, name)
                files_processed += 1
                if encrypt_file(full_path, password, delete_originals, self.log):
                    files_encrypted += 1

        self.log(f"\nFinished encrypting. Processed {files_processed} files; "
                 f"successfully encrypted {files_encrypted} files.")
        messagebox.showinfo(APP_NAME, "Folder encryption finished.")

    def unlock_folder(self):
        """
        Decrypt all .locked files in the selected folder (recursively).
        Only works with the correct password; wrong password => decryption fails.
        """
        folder, password = self.validate_common_inputs()
        if folder is None:
            return

        self.log("=== Unlocking (decrypting) folder ===")
        self.log(f"Folder: {folder}")
        self.log("Do NOT close encrypt0r while processing.\n")

        files_found = 0
        files_decrypted = 0

        for root, dirs, files in os.walk(folder):
            for name in files:
                full_path = os.path.join(root, name)
                if full_path.endswith(LOCK_EXTENSION):
                    files_found += 1
                    if decrypt_file(full_path, password, self.log):
                        files_decrypted += 1

        if files_found == 0:
            self.log("No encrypted (.locked) files found in this folder.")
            messagebox.showinfo(APP_NAME, "No encrypted files found in this folder.")
        else:
            self.log(f"\nFinished decrypting. Found {files_found} encrypted files; "
                     f"successfully decrypted {files_decrypted} files.")
            if files_decrypted == 0:
                messagebox.showerror(
                    APP_NAME,
                    "Could not decrypt any files.\n\n"
                    "This usually means the password is incorrect or the files are corrupted."
                )
            else:
                messagebox.showinfo(APP_NAME, "Folder decryption finished.")


# ---------- Single-file mode for .locked double-click ----------

def open_locked_file(file_path: str):
    """
    When encrypt0r.exe is launched with a .locked file directly:
    - Ask password via GUI popup
    - Decrypt file to temp folder
    - Open it with the default associated program
    """
    enable_high_dpi()
    root = tk.Tk()
    root.withdraw()  # hide main window

    if not os.path.exists(file_path):
        messagebox.showerror(APP_NAME, f"File not found:\n{file_path}")
        return

    password = simpledialog.askstring(APP_NAME, "Enter password to decrypt:", show="*")
    if not password:
        return

    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except Exception as e:
        messagebox.showerror(APP_NAME, f"Failed to read file:\n{e}")
        return

    if len(data) < 17:
        messagebox.showerror(APP_NAME, "File is too small or corrupted.")
        return

    salt = data[:16]
    ciphertext = data[16:]

    key = derive_key_from_password(password, salt)
    fernet = Fernet(key)

    try:
        plaintext = fernet.decrypt(ciphertext)
    except Exception:
        messagebox.showerror(APP_NAME, "Incorrect password or corrupted file.")
        return

    # Create a temporary file for viewing
    original_path = file_path[:-len(LOCK_EXTENSION)]  # remove .locked
    file_name = os.path.basename(original_path)
    temp_path = os.path.join(tempfile.gettempdir(), file_name)

    try:
        with open(temp_path, "wb") as f:
            f.write(plaintext)
    except Exception as e:
        messagebox.showerror(APP_NAME, f"Failed to write temporary file:\n{e}")
        return

    # Open with default associated app
    try:
        os.startfile(temp_path)  # Windows-only
    except Exception as e:
        messagebox.showerror(APP_NAME, f"Could not open file:\n{e}")


# ---------- Entrypoint ----------

def run_gui():
    enable_high_dpi()
    root = tk.Tk()
    app = Encrypt0rApp(root)
    root.mainloop()


if __name__ == "__main__":
    # If launched with a single .locked file argument → single-file mode
    if len(sys.argv) == 2 and sys.argv[1].lower().endswith(LOCK_EXTENSION):
        open_locked_file(sys.argv[1])
    else:
        # Normal GUI (folder mode)
        run_gui()
