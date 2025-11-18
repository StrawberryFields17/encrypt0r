import os
import sys
import base64
import secrets
import tempfile
import hashlib
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

# Security timers
AUTO_CLEAR_MINUTES = 5       # clear passwords after X minutes of inactivity
SHOW_PLAIN_SECONDS = 20      # auto-hide password after X seconds shown

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


def build_encrypted_payload(filename: str, file_bytes: bytes, password: str) -> bytes:
    """
    Build the encrypted payload for a file:
    - 16 bytes salt
    - Fernet(ciphertext) of:
      [4 bytes filename_length][filename UTF-8][file data]
    Returns bytes ready to write to disk (without deciding the encrypted filename).
    """
    salt = secrets.token_bytes(16)
    key = derive_key_from_password(password, salt)
    fernet = Fernet(key)

    name_bytes = filename.encode("utf-8")
    name_len = len(name_bytes).to_bytes(4, byteorder="big")
    plaintext_blob = name_len + name_bytes + file_bytes

    ciphertext = fernet.encrypt(plaintext_blob)
    return salt + ciphertext


def decrypt_encrypted_payload(data: bytes, password: str) -> tuple[str, bytes]:
    """
    Reverse of build_encrypted_payload.
    Given raw bytes from an encrypted file and the password, return:
        (original_filename, file_bytes)
    Raises on failure (wrong password/corruption).
    """
    if len(data) < 17:
        raise ValueError("Encrypted file is too small.")

    salt = data[:16]
    ciphertext = data[16:]

    key = derive_key_from_password(password, salt)
    fernet = Fernet(key)
    plaintext_blob = fernet.decrypt(ciphertext)

    if len(plaintext_blob) < 4:
        raise ValueError("Decrypted data is too small for header.")

    name_len = int.from_bytes(plaintext_blob[:4], byteorder="big")
    if len(plaintext_blob) < 4 + name_len:
        raise ValueError("Filename length header is invalid.")

    name_bytes = plaintext_blob[4:4 + name_len]
    filename = name_bytes.decode("utf-8", errors="replace")
    file_bytes = plaintext_blob[4 + name_len:]

    return filename, file_bytes


def encrypt_file(path: str, password: str, delete_original: bool, log_callback):
    """
    Encrypt a single file:
    - Read original bytes
    - Build encrypted payload that includes original filename
    - Store on disk using a hashed filename + .locked extension
    - Copy original timestamps to the .locked file
    - Optionally delete original file
    """
    if path.endswith(LOCK_EXTENSION):
        log_callback(f"Skipping already encrypted file: {path}")
        return False

    # Capture original timestamps before touching the file
    try:
        st = os.stat(path)
        original_atime = st.st_atime
        original_mtime = st.st_mtime
    except Exception as e:
        log_callback(f"Failed to stat {path}: {e}")
        return False

    try:
        with open(path, "rb") as f:
            plaintext = f.read()
    except Exception as e:
        log_callback(f"Failed to read {path}: {e}")
        return False

    original_name = os.path.basename(path)
    log_callback(f"Encrypting: {path}")

    payload = build_encrypted_payload(original_name, plaintext, password)

    # Encrypted filename: hash(original_name + random salt-ish) to hide real name on disk
    hash_input = original_name.encode("utf-8") + payload[:16]
    hashed_name = hashlib.sha256(hash_input).hexdigest()[:32]  # shorten a bit
    dir_name = os.path.dirname(path)
    encrypted_path = os.path.join(dir_name, hashed_name + LOCK_EXTENSION)

    try:
        with open(encrypted_path, "wb") as f:
            f.write(payload)
        # Apply original timestamps to the encrypted file
        try:
            os.utime(encrypted_path, (original_atime, original_mtime))
        except Exception as e:
            log_callback(f"Warning: failed to copy timestamps for {encrypted_path}: {e}")
    except Exception as e:
        log_callback(f"Failed to write encrypted file for {path}: {e}")
        return False

    if delete_original:
        try:
            os.remove(path)
            log_callback(f"Deleted original: {path}")
        except Exception as e:
            log_callback(f"Failed to delete original {path}: {e}")

    log_callback(f"Stored as: {encrypted_path}")
    return True


def decrypt_file(path: str, password: str, log_callback):
    """
    Decrypt a single .locked file:
    - Read raw bytes
    - Decrypt and recover original filename and content
    - Write out using original filename in the same directory
    - Delete encrypted file on success
    - Preserve timestamp from .locked file on restored file
    Returns True if decryption succeeded, False otherwise.
    """
    if not path.endswith(LOCK_EXTENSION):
        log_callback(f"Skipping non-encrypted file: {path}")
        return False

    # Capture timestamps from the encrypted file so we can reuse them
    try:
        st = os.stat(path)
        enc_atime = st.st_atime
        enc_mtime = st.st_mtime
    except Exception as e:
        log_callback(f"Failed to stat encrypted file {path}: {e}")
        return False

    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception as e:
        log_callback(f"Failed to read {path}: {e}")
        return False

    try:
        original_name, file_bytes = decrypt_encrypted_payload(data, password)
    except Exception as e:
        log_callback(f"Failed to decrypt {path}: {e}")
        return False

    out_dir = os.path.dirname(path)
    out_path = os.path.join(out_dir, original_name)

    try:
        with open(out_path, "wb") as f:
            f.write(file_bytes)
        # Restore timestamp from encrypted file
        try:
            os.utime(out_path, (enc_atime, enc_mtime))
        except Exception as e:
            log_callback(f"Warning: failed to copy timestamps to {out_path}: {e}")
    except Exception as e:
        log_callback(f"Failed to write decrypted file for {path}: {e}")
        return False

    try:
        os.remove(path)
        log_callback(f"Removed encrypted file: {path}")
    except Exception as e:
        log_callback(f"Failed to remove encrypted file {path}: {e}")

    log_callback(f"Restored original name: {out_path}")
    return True


# ---------- GUI app (folder + files mode) ----------

class Encrypt0rApp:
    def __init__(self, master):
        self.master = master
        master.title(APP_NAME)

        # Track individually selected files (optional)
        self.selected_files = []

        # Security timers
        self.inactivity_ms = AUTO_CLEAR_MINUTES * 60 * 1000
        self.show_timeout_ms = SHOW_PLAIN_SECONDS * 1000
        self.inactivity_after_id = None
        self.show_timeout_after_id = None

        # Make window larger & resizable
        master.configure(bg=BG_MAIN)
        master.minsize(900, 600)
        master.resizable(True, True)

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
            text="Encrypt and decrypt folders with a single password. Filenames are hidden too.",
            style="Encrypt0r.Subtle.TLabel"
        )
        subtitle_label.grid(row=1, column=0, columnspan=3, sticky="w", pady=(0, 12))

        # Folder / files selection
        folder_label = ttk.Label(frame, text="Folder", style="Encrypt0r.TLabel")
        folder_label.grid(row=2, column=0, padx=(0, 8), pady=5, sticky="e")

        self.folder_var = tk.StringVar()
        self.folder_entry = ttk.Entry(frame, textvariable=self.folder_var,
                                      width=50, style="Encrypt0r.TEntry")
        self.folder_entry.grid(row=2, column=1, padx=(0, 8), pady=5, sticky="we")

        # Right side: folder + files buttons
        folder_btns = ttk.Frame(frame, style="Encrypt0r.TFrame")
        folder_btns.grid(row=2, column=2, pady=5, sticky="nsew")
        folder_btns.columnconfigure(0, weight=1)

        browse_folder_btn = ttk.Button(
            folder_btns,
            text="Browse folder",
            style="Encrypt0r.Secondary.TButton",
            command=self.browse_folder
        )
        browse_folder_btn.grid(row=0, column=0, sticky="ew", pady=(0, 2))

        select_files_btn = ttk.Button(
            folder_btns,
            text="Select files",
            style="Encrypt0r.Secondary.TButton",
            command=self.select_files
        )
        select_files_btn.grid(row=1, column=0, sticky="ew")

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
            text="Lock (Encrypt)",
            style="Encrypt0r.TButton",
            command=self.lock_folder
        )
        self.lock_button.grid(row=0, column=0, padx=(0, 8), pady=5, sticky="w")

        self.unlock_button = ttk.Button(
            buttons_frame,
            text="Unlock (Decrypt)",
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

        # Bind activity for auto-clear (key presses in password fields)
        self.password_entry.bind("<Key>", self.on_user_activity)
        self.confirm_entry.bind("<Key>", self.on_user_activity)

        # Start inactivity timer
        self.reset_inactivity_timer()

    # ---------- Security timers ----------

    def on_user_activity(self, event=None):
        self.reset_inactivity_timer()

    def reset_inactivity_timer(self):
        if self.inactivity_after_id is not None:
            self.master.after_cancel(self.inactivity_after_id)
        self.inactivity_after_id = self.master.after(self.inactivity_ms, self.on_inactivity_timeout)

    def on_inactivity_timeout(self):
        # Only log/clear if there is something to clear
        if self.password_var.get() or self.confirm_var.get():
            self.log("No activity detected. Clearing password fields for security.")
            self.clear_password_fields()
        self.inactivity_after_id = None

    def start_show_timeout(self):
        if self.show_timeout_after_id is not None:
            self.master.after_cancel(self.show_timeout_after_id)
        self.show_timeout_after_id = self.master.after(self.show_timeout_ms, self.on_show_timeout)

    def cancel_show_timeout(self):
        if self.show_timeout_after_id is not None:
            self.master.after_cancel(self.show_timeout_after_id)
            self.show_timeout_after_id = None

    def on_show_timeout(self):
        # If still showing, hide it again
        if self.show_password_var.get():
            self.show_password_var.set(False)
            self.password_entry.config(show="*")
            self.confirm_entry.config(show="*")
            self.log("Password visibility timeout reached; hiding password for security.")
        self.show_timeout_after_id = None

    def clear_password_fields(self):
        self.password_var.set("")
        self.confirm_var.set("")
        self.show_password_var.set(False)
        self.password_entry.config(show="*")
        self.confirm_entry.config(show="*")
        self.cancel_show_timeout()

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
            # Clear selected files when switching back to folder mode
            self.selected_files = []
            self.on_user_activity()

    def select_files(self):
        """Let the user pick individual files to encrypt/decrypt."""
        files = filedialog.askopenfilenames(
            title="Select files to encrypt/decrypt"
        )
        if not files:
            return

        self.selected_files = list(files)

        # Set folder field to the directory of the first selected file (for context)
        first_dir = os.path.dirname(self.selected_files[0])
        if first_dir:
            self.folder_var.set(first_dir)

        self.log(f"Selected {len(self.selected_files)} individual file(s).")
        self.on_user_activity()

    def validate_common_inputs(self):
        folder = self.folder_var.get()
        password = self.password_var.get()

        if not password:
            messagebox.showerror(APP_NAME, "Please enter a password.")
            return None, None

        # If user selected individual files, we don't strictly require a valid folder
        if self.selected_files:
            existing = [f for f in self.selected_files if os.path.isfile(f)]
            if not existing:
                messagebox.showerror(APP_NAME, "Selected files no longer exist.")
                self.selected_files = []
                return None, None
            self.selected_files = existing
            return folder, password

        # Folder mode fallback (no individual files)
        if not folder:
            messagebox.showerror(APP_NAME, "Please select a folder or individual files.")
            return None, None
        if not os.path.isdir(folder):
            messagebox.showerror(APP_NAME, "Selected folder does not exist.")
            return None, None

        return folder, password

    def toggle_password_visibility(self):
        show_char = "" if self.show_password_var.get() else "*"
        self.password_entry.config(show=show_char)
        self.confirm_entry.config(show=show_char)

        if self.show_password_var.get():
            # Just turned "show" ON -> start timeout
            self.start_show_timeout()
        else:
            # Just turned "show" OFF -> cancel timeout
            self.cancel_show_timeout()

        self.on_user_activity()

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
        self.on_user_activity()

    # ---------- Actions ----------

    def lock_folder(self):
        self.on_user_activity()
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

        # Decide what we are encrypting: selected files or all files in folder
        if self.selected_files:
            targets = list(self.selected_files)
            mode_desc = f"{len(targets)} selected file(s)"
        else:
            targets = []
            for root, dirs, files in os.walk(folder):
                for name in files:
                    targets.append(os.path.join(root, name))
            mode_desc = f"all files under: {folder}"

        self.log("=== Locking (encrypting) folder ===")
        self.log(f"Mode: {mode_desc}")
        self.log(f"Delete originals: {delete_originals}")
        self.log("Do NOT close encrypt0r while processing.\n")

        files_processed = 0
        files_encrypted = 0

        for full_path in targets:
            files_processed += 1
            if encrypt_file(full_path, password, delete_originals, self.log):
                files_encrypted += 1

        self.log(f"\nFinished encrypting. Processed {files_processed} files; "
                 f"successfully encrypted {files_encrypted} files.")
        self.clear_password_fields()
        messagebox.showinfo(APP_NAME, "Folder/file encryption finished.")

    def unlock_folder(self):
        """
        Decrypt .locked files in the selected folder or from individually selected files.
        """
        self.on_user_activity()
        folder, password = self.validate_common_inputs()
        if folder is None:
            return

        # Decide what we are decrypting: selected files or all .locked under folder
        if self.selected_files:
            all_candidates = list(self.selected_files)
            targets = [p for p in all_candidates if p.lower().endswith(LOCK_EXTENSION)]
            mode_desc = f"{len(targets)} selected .locked file(s)"
        else:
            targets = []
            for root, dirs, files in os.walk(folder):
                for name in files:
                    full_path = os.path.join(root, name)
                    if full_path.lower().endswith(LOCK_EXTENSION):
                        targets.append(full_path)
            mode_desc = f".locked files under: {folder}"

        self.log("=== Unlocking (decrypting) folder ===")
        self.log(f"Mode: {mode_desc}")
        self.log("Do NOT close encrypt0r while processing.\n")

        files_found = len(targets)
        files_decrypted = 0

        for full_path in targets:
            if decrypt_file(full_path, password, self.log):
                files_decrypted += 1

        if files_found == 0:
            self.log("No encrypted (.locked) files found.")
            messagebox.showinfo(APP_NAME, "No encrypted files found.")
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
                self.clear_password_fields()
                messagebox.showinfo(APP_NAME, "Folder/file decryption finished.")


# ---------- Single-file mode for .locked double-click ----------

def open_locked_file(file_path: str):
    """
    When encrypt0r.exe is launched with a .locked file directly:
    - Ask password via GUI popup
    - Decrypt file to temp folder with original filename
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

    try:
        original_name, file_bytes = decrypt_encrypted_payload(data, password)
    except Exception:
        messagebox.showerror(APP_NAME, "Incorrect password or corrupted file.")
        return

    # Create a temporary file for viewing with the original filename
    file_name = original_name
    temp_path = os.path.join(tempfile.gettempdir(), file_name)

    try:
        with open(temp_path, "wb") as f:
            f.write(file_bytes)
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
        # Normal GUI (folder/files mode)
        run_gui()
