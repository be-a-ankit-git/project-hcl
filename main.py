import ctypes
import hashlib
import os
import stat
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from ctypes import wintypes
from pathlib import Path

MAGIC = b"CFLP1"
MAX_FILE_SIZE = 512 * 1024 * 1024
CRYPTPROTECT_UI_FORBIDDEN = 0x1
ERROR_INVALID_DATA = 13


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def _windows_crypto():
    if os.name != "nt":
        raise OSError("The secure locker currently requires Windows (uses built-in DPAPI).")
    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    crypt.CryptProtectData.argtypes = [
        ctypes.POINTER(DATA_BLOB), wintypes.LPCWSTR, ctypes.POINTER(DATA_BLOB),
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(DATA_BLOB),
    ]
    crypt.CryptProtectData.restype = wintypes.BOOL
    crypt.CryptUnprotectData.argtypes = [
        ctypes.POINTER(DATA_BLOB), ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(DATA_BLOB), ctypes.c_void_p, ctypes.c_void_p,
        wintypes.DWORD, ctypes.POINTER(DATA_BLOB),
    ]
    crypt.CryptUnprotectData.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    return crypt, kernel


def _as_blob(data: bytes):
    # Keep the backing buffer alive until the Windows API returns.
    buf = (ctypes.c_ubyte * max(1, len(data)))()
    if data:
        ctypes.memmove(buf, data, len(data))
    return DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte))), buf


def _dpapi(data: bytes, decrypt: bool) -> bytes:
    crypt, kernel = _windows_crypto()
    source, keepalive = _as_blob(data)
    result = DATA_BLOB()
    if decrypt:
        success = crypt.CryptUnprotectData(
            ctypes.byref(source), None, None, None, None,
            CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(result),
        )
    else:
        success = crypt.CryptProtectData(
            ctypes.byref(source), "Cybersecurity File Toolkit", None, None, None,
            CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(result),
        )
    del keepalive
    if not success:
        code = ctypes.get_last_error()
        if decrypt and code in (ERROR_INVALID_DATA, 0x8009000B & 0xFFFF):
            raise ValueError("Windows could not unlock this file. It may be damaged or belong to another Windows account.")
        raise OSError(code, ctypes.FormatError(code))
    try:
        return ctypes.string_at(result.pbData, result.cbData) if result.cbData else b""
    finally:
        kernel.LocalFree(ctypes.cast(result.pbData, ctypes.c_void_p))


def _read_file(path: Path) -> bytes:
    size = path.stat().st_size
    if size > MAX_FILE_SIZE:
        raise ValueError("For this learning project, files must be no larger than 512 MiB.")
    return path.read_bytes()


def _write_new(path: Path, data: bytes) -> None:
    # Exclusive creation prevents accidentally replacing an existing file.
    with path.open("xb") as file:
        file.write(data)
        file.flush()
        os.fsync(file.fileno())


def secure_locker(path: Path, decrypt: bool) -> Path:
    if decrypt and path.suffix.lower() != ".locked":
        raise ValueError("For safety, choose a file ending in .locked.")
    data = _read_file(path)
    if decrypt:
        if not data.startswith(MAGIC):
            raise ValueError("This is not a supported .locked file.")
        clear = _dpapi(data[len(MAGIC):], decrypt=True)
        output = path.with_suffix("").with_name(path.stem + ".unlocked")
        _write_new(output, clear)
    else:
        protected = _dpapi(data, decrypt=False)
        output = Path(str(path) + ".locked")
        _write_new(output, MAGIC + protected)
    return output


def permission_checker(path: Path) -> str:
    if not path.exists():
        raise FileNotFoundError(f"Path not found: {path}")
    lines = [f"Type: {'Folder' if path.is_dir() else 'File'}"]
    attrs = getattr(path.stat(), "st_file_attributes", 0)
    readonly = bool(attrs & getattr(stat, "FILE_ATTRIBUTE_READONLY", 0x1))
    lines.append(f"Read-only attribute: {'Yes' if readonly else 'No'}")
    lines.append("\nWindows access-control entries:")
    result = subprocess.run(
        ["icacls", str(path)], capture_output=True, text=True, errors="replace", check=False
    )
    if result.returncode != 0:
        raise RuntimeError("Could not read permission entries.")
    lines.append(result.stdout.rstrip())
    lines.append("\nNote: these are ACL rules, not an effective-access calculation for a specific user.")
    return "\n".join(lines)


def integrity_checker(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"SHA-256\n{digest.hexdigest()}\n\nSave this value and compare it with a later calculation."


class ToolkitApp:
    BG = "#0b1220"
    PANEL = "#111c2e"
    PANEL_2 = "#17253a"
    TEXT = "#eef4ff"
    MUTED = "#9aabc2"
    ACCENT = "#57d6b5"
    BLUE = "#5c8dff"

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Sentinel | File Security Toolkit")
        self.root.geometry("850x650")
        self.root.minsize(720, 560)
        self.root.configure(bg=self.BG)
        self.selected_path = tk.StringVar()
        self.status = tk.StringVar(value="Ready · Choose a file to get started")
        self._build()

    def _build(self):
        outer = tk.Frame(self.root, bg=self.BG, padx=28, pady=22)
        outer.pack(fill="both", expand=True)

        header = tk.Frame(outer, bg=self.BG)
        header.pack(fill="x", pady=(0, 20))
        tk.Label(header, text="◈", font=("Segoe UI", 27, "bold"), fg=self.ACCENT, bg=self.BG).pack(side="left", padx=(0, 12))
        title_box = tk.Frame(header, bg=self.BG)
        title_box.pack(side="left", anchor="w")
        tk.Label(title_box, text="SENTINEL", font=("Segoe UI", 19, "bold"), fg=self.TEXT, bg=self.BG).pack(anchor="w")
        tk.Label(title_box, text="FILE SECURITY TOOLKIT", font=("Segoe UI", 9, "bold"), fg=self.MUTED, bg=self.BG).pack(anchor="w")
        tk.Label(header, text="WINDOWS  ·  PYTHON", font=("Segoe UI", 9, "bold"), fg=self.ACCENT, bg=self.BG).pack(side="right", anchor="n", pady=10)

        tk.Label(outer, text="Protect and inspect your files", font=("Segoe UI", 22, "bold"), fg=self.TEXT, bg=self.BG).pack(anchor="w")
        tk.Label(outer, text="Choose a file, then select an action. The original stays untouched when you lock or unlock.", font=("Segoe UI", 10), fg=self.MUTED, bg=self.BG).pack(anchor="w", pady=(5, 18))

        picker = tk.Frame(outer, bg=self.PANEL, padx=16, pady=14)
        picker.pack(fill="x", pady=(0, 16))
        tk.Label(picker, text="SELECT FILE", font=("Segoe UI", 9, "bold"), fg=self.MUTED, bg=self.PANEL).pack(anchor="w", pady=(0, 8))
        row = tk.Frame(picker, bg=self.PANEL)
        row.pack(fill="x")
        self.path_entry = tk.Entry(row, textvariable=self.selected_path, font=("Segoe UI", 10), bg="#0b1423", fg=self.TEXT, insertbackground=self.TEXT, relief="flat", state="readonly", readonlybackground="#0b1423")
        self.path_entry.pack(side="left", fill="x", expand=True, ipady=10, padx=(0, 10))
        self._button(row, "Browse…", self.browse, self.PANEL_2, self.TEXT).pack(side="right", ipady=5)

        cards = tk.Frame(outer, bg=self.BG)
        cards.pack(fill="x", pady=(0, 16))
        cards.columnconfigure((0, 1), weight=1, uniform="card")
        self._action_card(cards, 0, 0, "01", "Secure file locker", "Create a protected .locked copy", "Lock file", lambda: self.run_action("lock"), self.ACCENT)
        self._action_card(cards, 0, 1, "02", "Unlock file", "Restore a file on this Windows account", "Unlock file", lambda: self.run_action("unlock"), self.BLUE)
        self._action_card(cards, 1, 0, "03", "Permission checker", "Review Windows access-control rules", "Check permissions", lambda: self.run_action("permissions"), self.BLUE)
        self._action_card(cards, 1, 1, "04", "Integrity checker", "Calculate a SHA-256 fingerprint", "Calculate hash", lambda: self.run_action("hash"), self.ACCENT)

        results = tk.Frame(outer, bg=self.PANEL, padx=16, pady=12)
        results.pack(fill="both", expand=True)
        top = tk.Frame(results, bg=self.PANEL)
        top.pack(fill="x", pady=(0, 8))
        tk.Label(top, text="ACTIVITY & RESULTS", font=("Segoe UI", 9, "bold"), fg=self.MUTED, bg=self.PANEL).pack(side="left")
        tk.Button(top, text="Copy SHA-256", command=self.copy_hash, font=("Segoe UI", 9, "bold"), bg=self.PANEL_2, fg=self.TEXT, activebackground=self.PANEL_2, activeforeground=self.TEXT, relief="flat", padx=10, pady=5, cursor="hand2").pack(side="right")
        self.output = tk.Text(results, height=8, wrap="word", font=("Consolas", 10), bg="#0b1423", fg=self.TEXT, insertbackground=self.TEXT, relief="flat", padx=12, pady=10, state="disabled")
        self.output.pack(fill="both", expand=True)

        footer = tk.Frame(outer, bg=self.BG)
        footer.pack(fill="x", pady=(10, 0))
        tk.Label(footer, textvariable=self.status, font=("Segoe UI", 9), fg=self.ACCENT, bg=self.BG).pack(side="left")
        tk.Label(footer, text="Built-in Windows protection · No third-party packages", font=("Segoe UI", 9), fg=self.MUTED, bg=self.BG).pack(side="right")
        self._show("Welcome. Select a file above, then choose one of the four actions.\n\nLocker note: Windows protects locked files for the account that created them.")

    def _button(self, parent, label, command, bg, fg):
        return tk.Button(parent, text=label, command=command, font=("Segoe UI", 9, "bold"), bg=bg, fg=fg, activebackground=bg, activeforeground=fg, relief="flat", padx=14, pady=8, cursor="hand2")

    def _action_card(self, parent, row, col, number, title, desc, button, command, color):
        card = tk.Frame(parent, bg=self.PANEL, padx=15, pady=13)
        card.grid(row=row, column=col, sticky="nsew", padx=(0 if col == 0 else 8, 8 if col == 0 else 0), pady=(0 if row == 0 else 8, 8 if row == 0 else 0))
        tk.Label(card, text=number, font=("Segoe UI", 9, "bold"), fg=color, bg=self.PANEL).pack(anchor="w")
        tk.Label(card, text=title, font=("Segoe UI", 13, "bold"), fg=self.TEXT, bg=self.PANEL).pack(anchor="w", pady=(4, 2))
        tk.Label(card, text=desc, font=("Segoe UI", 9), fg=self.MUTED, bg=self.PANEL).pack(anchor="w", pady=(0, 10))
        self._button(card, button, command, color, self.BG).pack(anchor="w")

    def browse(self):
        chosen = filedialog.askopenfilename(title="Choose a file")
        if chosen:
            self.selected_path.set(chosen)
            self.status.set("File selected · Choose an action")
            self._show(f"Selected file:\n{chosen}\n\nChoose an action above to continue.")

    def _show(self, text):
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.insert("1.0", text)
        self.output.configure(state="disabled")

    def run_action(self, action):
        raw = self.selected_path.get()
        if not raw:
            messagebox.showinfo("Select a file", "Browse to choose a file first.", parent=self.root)
            return
        path = Path(raw)
        try:
            if action == "lock":
                output = secure_locker(path, decrypt=False)
                result = f"File locked successfully.\n\nProtected copy:\n{output}\n\nThe original file was left untouched. Keep the locked copy private; it is protected for this Windows account."
                self.status.set("Lock complete")
            elif action == "unlock":
                output = secure_locker(path, decrypt=True)
                result = f"File unlocked successfully.\n\nRestored copy:\n{output}\n\nThe .locked file and original were left untouched."
                self.status.set("Unlock complete")
            elif action == "permissions":
                result = permission_checker(path)
                self.status.set("Permission check complete")
            else:
                result = integrity_checker(path)
                self.status.set("SHA-256 calculated")
            self._show(result)
        except (OSError, ValueError, RuntimeError) as error:
            self.status.set("Action could not be completed")
            self._show(f"Could not complete this action.\n\n{error}")
            messagebox.showerror("Action failed", str(error), parent=self.root)

    def copy_hash(self):
        text = self.output.get("1.0", "end")
        for line in text.splitlines():
            if len(line) == 64 and all(char in "0123456789abcdef" for char in line.lower()):
                self.root.clipboard_clear()
                self.root.clipboard_append(line)
                self.status.set("SHA-256 copied to clipboard")
                return
        messagebox.showinfo("No hash to copy", "Calculate a SHA-256 hash first.", parent=self.root)


def main() -> int:
    if os.name != "nt":
        print("This version is for Windows. Run it with Python on Windows.")
        return 1
    root = tk.Tk()
    ToolkitApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
