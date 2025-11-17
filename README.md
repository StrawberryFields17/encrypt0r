# encrypt0r 🔐

**encrypt0r** is a simple Windows desktop tool that lets you encrypt and decrypt all files in a folder with a password.

It uses strong, modern cryptography (AES via `cryptography.Fernet`) and a GUI built with Tkinter, so you can lock/unlock folders without touching the command line.

> ⚠️ If you forget your password, **your data cannot be recovered**. There is no backdoor.

---

## Features

- 🔒 Encrypt all files inside a folder (recursively)
- 🔓 Decrypt previously encrypted files with the correct password
- ✅ Optional deletion of original plaintext files after encryption
- 🧾 Log panel that shows what’s happening (which files are processed)
- 💾 Desktop-friendly: can be bundled into a single `encrypt0r.exe`
- 🎨 Custom neon key + safe icon

Encrypted files are given the extension:

```text
filename.ext.locked
