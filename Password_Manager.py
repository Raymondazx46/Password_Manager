
import json
import os
import base64
import tkinter as tk
from tkinter import simpledialog, messagebox, ttk
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from getpass import getpass
from pathlib import Path
import secrets

DATA_FILE = Path.home() / '.py_passmgr_store.bin'
SALT_SIZE = 16
NONCE_SIZE = 12
KDF_ITERS = 200_000

# --- Rumus Crypto ---

def derive_key(master_password: str, salt: bytes) -> bytes:
    pwd = master_password.encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERS,
        backend=default_backend()
    )
    return kdf.derive(pwd)


def encrypt_data(master_password: str, data: bytes) -> bytes:
    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key(master_password, salt)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(NONCE_SIZE)
    ct = aesgcm.encrypt(nonce, data, None)
    # store: salt || nonce || ciphertext
    return salt + nonce + ct


def decrypt_data(master_password: str, blob: bytes) -> bytes:
    if len(blob) < SALT_SIZE + NONCE_SIZE:
        raise ValueError('invalid data file')
    salt = blob[:SALT_SIZE]
    nonce = blob[SALT_SIZE:SALT_SIZE+NONCE_SIZE]
    ct = blob[SALT_SIZE+NONCE_SIZE:]
    key = derive_key(master_password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)

# --- Penyimpanan ---

def load_store(master_password: str) -> dict:
    if not DATA_FILE.exists():
        return {}
    blob = DATA_FILE.read_bytes()
    try:
        dec = decrypt_data(master_password, blob)
        return json.loads(dec.decode('utf-8'))
    except Exception as e:
        raise


def save_store(master_password: str, store: dict):
    raw = json.dumps(store, ensure_ascii=False).encode('utf-8')
    blob = encrypt_data(master_password, raw)
    DATA_FILE.write_bytes(blob)

# --- utilities ---

def generate_password(length=16) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

# --- GUI ---

class PasswordManagerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('Password Manager')
        self.geometry('700x420')
        self.resizable(False, False)

        self.master_password = None
        self.store = {}

        self.create_widgets()
        self.ask_master_password()

    def create_widgets(self):
        frame = ttk.Frame(self, padding=10)
        frame.pack(fill='both', expand=True)

        # frame kiri: list
        left = ttk.Frame(frame)
        left.grid(row=0, column=0, sticky='nsw')

        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(left, textvariable=self.search_var)
        search_entry.pack(fill='x', padx=4, pady=4)
        search_entry.bind('<KeyRelease>', lambda e: self.refresh_list())

        self.tree = ttk.Treeview(left, columns=('username','note'), show='headings', height=18)
        self.tree.heading('username', text='Username')
        self.tree.heading('note', text='Note')
        self.tree.column('username', width=200)
        self.tree.column('note', width=240)
        self.tree.pack(side='left', padx=4, pady=4)

        scrollbar = ttk.Scrollbar(left, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side='right', fill='y')

        # frame kanan: controls
        right = ttk.Frame(frame)
        right.grid(row=0, column=1, sticky='nse', padx=10)

        ttk.Button(right, text='Add', command=self.add_entry_dialog).pack(fill='x', pady=6)
        ttk.Button(right, text='View / Copy', command=self.view_selected).pack(fill='x', pady=6)
        ttk.Button(right, text='Edit', command=self.edit_selected).pack(fill='x', pady=6)
        ttk.Button(right, text='Delete', command=self.delete_selected).pack(fill='x', pady=6)
        ttk.Button(right, text='Generate Password', command=self.generate_dialog).pack(fill='x', pady=6)
        ttk.Button(right, text='Change Master Password', command=self.change_master_password).pack(fill='x', pady=6)
        ttk.Button(right, text='Save', command=self.save_store_cmd).pack(fill='x', pady=6)
        ttk.Button(right, text='Exit', command=self.quit).pack(fill='x', pady=6)

        # status
        self.status = tk.StringVar(value='Ready')
        ttk.Label(self, textvariable=self.status).pack(side='bottom', fill='x')

    def ask_master_password(self):
        # if data file exists, ask and try decrypt; otherwise ask to set one
        if DATA_FILE.exists():
            for attempt in range(3):
                mp = simpledialog.askstring('Master Password', 'Enter master password:', show='*', parent=self)
                if mp is None:
                    self.destroy()
                    return
                try:
                    self.store = load_store(mp)
                    self.master_password = mp
                    self.status.set('Unlocked')
                    self.refresh_list()
                    return
                except Exception:
                    messagebox.showerror('Error', 'Wrong master password or corrupted file.')
            messagebox.showerror('Error', 'Too many failed attempts.')
            self.destroy()
        else:
            mp = simpledialog.askstring('Create Master Password', 'Create a new master password:', show='*', parent=self)
            if not mp:
                messagebox.showerror('Error', 'Master password required to create store.')
                self.destroy()
                return
            self.master_password = mp
            self.store = {}
            save_store(self.master_password, self.store)
            messagebox.showinfo('Done', f'Password store created at {DATA_FILE}')
            self.status.set('Unlocked')
            self.refresh_list()

    def refresh_list(self):
        self.tree.delete(*self.tree.get_children())
        q = self.search_var.get().lower()
        for name, item in sorted(self.store.items()):
            if q and q not in name.lower() and q not in item.get('username','').lower():
                continue
            self.tree.insert('', 'end', iid=name, values=(item.get('username',''), item.get('note','')))

    def add_entry_dialog(self):
        d = EntryDialog(self, title='Add Entry')
        if d.result:
            name, username, password, note = d.result
            if name in self.store:
                if not messagebox.askyesno('Overwrite', f'Entry {name} exists. Overwrite?'):
                    return
            self.store[name] = {'username': username, 'password': password, 'note': note}
            self.refresh_list()
            self.status.set('Entry added')

    def view_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo('Info', 'Select an entry first')
            return
        name = sel[0]
        item = self.store.get(name)
        if not item:
            return
        ViewDialog(self, name, item)

    def edit_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo('Info', 'Select an entry first')
            return
        name = sel[0]
        item = self.store.get(name)
        d = EntryDialog(self, title='Edit Entry', preset=(name, item.get('username',''), item.get('password',''), item.get('note','')))
        if d.result:
            n, u, p, no = d.result
            # allow rename
            if n != name:
                self.store.pop(name, None)
            self.store[n] = {'username': u, 'password': p, 'note': no}
            self.refresh_list()
            self.status.set('Entry updated')

    def delete_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo('Info', 'Select an entry first')
            return
        name = sel[0]
        if messagebox.askyesno('Confirm', f'Delete entry {name}?'):
            self.store.pop(name, None)
            self.refresh_list()
            self.status.set('Entry deleted')

    def generate_dialog(self):
        length = simpledialog.askinteger('Generate Password', 'Length (8-64):', initialvalue=16, minvalue=8, maxvalue=64, parent=self)
        if length:
            pw = generate_password(length)
            messagebox.showinfo('Generated Password', pw)

    def change_master_password(self):
        # ask current, then new
        cur = simpledialog.askstring('Current Master', 'Enter current master password:', show='*', parent=self)
        if cur is None:
            return
        try:
            _ = load_store(cur)  # validate
        except Exception:
            messagebox.showerror('Error', 'Current master password is incorrect')
            return
        new = simpledialog.askstring('New Master', 'Enter new master password:', show='*', parent=self)
        if not new:
            return
        # save with new
        save_store(new, self.store)
        self.master_password = new
        messagebox.showinfo('Done', 'Master password changed')

    def save_store_cmd(self):
        if not self.master_password:
            messagebox.showerror('Error', 'No master password set')
            return
        save_store(self.master_password, self.store)
        self.status.set('Saved')

class EntryDialog(simpledialog.Dialog):
    def __init__(self, parent, title=None, preset=None):
        self.preset = preset
        super().__init__(parent, title)

    def body(self, master):
        ttk.Label(master, text='Name (site):').grid(row=0, column=0, sticky='e')
        ttk.Label(master, text='Username:').grid(row=1, column=0, sticky='e')
        ttk.Label(master, text='Password:').grid(row=2, column=0, sticky='e')
        ttk.Label(master, text='Note:').grid(row=3, column=0, sticky='e')

        self.e_name = ttk.Entry(master, width=40)
        self.e_username = ttk.Entry(master, width=40)
        self.e_password = ttk.Entry(master, width=40)
        self.e_note = ttk.Entry(master, width=40)

        self.e_name.grid(row=0, column=1)
        self.e_username.grid(row=1, column=1)
        self.e_password.grid(row=2, column=1)
        self.e_note.grid(row=3, column=1)

        if self.preset:
            n,u,p,no = self.preset
            self.e_name.insert(0, n)
            self.e_username.insert(0, u)
            self.e_password.insert(0, p)
            self.e_note.insert(0, no)

        return self.e_name

    def apply(self):
        name = self.e_name.get().strip()
        username = self.e_username.get().strip()
        password = self.e_password.get()
        note = self.e_note.get().strip()
        if not name:
            messagebox.showerror('Error', 'Name is required')
            self.result = None
            return
        self.result = (name, username, password, note)

class ViewDialog(simpledialog.Dialog):
    def __init__(self, parent, name, item):
        self.name = name
        self.item = item
        super().__init__(parent, title=f'View: {name}')

    def body(self, master):
        ttk.Label(master, text=f'Name: {self.name}').grid(row=0, column=0, sticky='w')
        ttk.Label(master, text=f"Username: {self.item.get('username','')}").grid(row=1, column=0, sticky='w')
        ttk.Label(master, text='Password:').grid(row=2, column=0, sticky='w')
        self.pw_var = tk.StringVar(value='*' * len(self.item.get('password','')))
        self.pw_entry = ttk.Entry(master, textvariable=self.pw_var, width=40)
        self.pw_entry.grid(row=3, column=0)
        ttk.Button(master, text='Show/Hide', command=self.toggle).grid(row=3, column=1)
        ttk.Button(master, text='Copy Password', command=self.copy_pw).grid(row=4, column=0, pady=6)
        ttk.Label(master, text=f"Note: {self.item.get('note','')}").grid(row=5, column=0, sticky='w')

    def toggle(self):
        cur = self.pw_var.get()
        if cur.startswith('*'):
            self.pw_var.set(self.item.get('password',''))
        else:
            self.pw_var.set('*' * len(self.item.get('password','')))

    def copy_pw(self):
        self.clipboard_clear()
        self.clipboard_append(self.item.get('password',''))
        messagebox.showinfo('Copied', 'Password copied to clipboard (short-lived)')

if __name__ == '__main__':
    app = PasswordManagerApp()
    app.mainloop()

