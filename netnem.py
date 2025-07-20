#!/usr/bin/env python3
"""
GhostMesh CLI Tool v1.3 (Idempotent Termux + PtP/Group)
Modes: PtP (peer-to-peer) or Group (multi-client broadcast)
Features:
- Auto-dependency on Android (Termux), Linux, Windows, macOS
- Idempotent Termux setup (won't re-clone or re-chmod)
- IPv4-only network scan
- TCP-based PtP or Group chat over local network
- AES‑EAX encryption + DNA obfuscation
- Save/Load chat in FASTA
- CLI commands: /decode, /save, /load, /exit
"""

import os
import sys
import socket
import threading
import random
import json
import platform
import subprocess
import re
from getpass import getpass

# ---------- DEPENDENCIES ----------
def ensure_python_package(pkg, imp=None):
    try:
        __import__(imp or pkg)
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])

ensure_python_package("pycryptodome", "Crypto.Cipher")
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

# ---------- CONFIG ----------
PORT = 5555
BUFFER_SIZE = 8192
chat_history = []  # list of (user, seed, dna)

# ---------- SETUP & UTILITIES ----------
def initial_setup():
    os_name = platform.system().lower()
    print("=== GhostMesh Setup ===")
    print(f"OS detected: {os_name.capitalize()}")

    # Termux on Android
    if "android" in os_name or (os_name == "linux" and os.path.isdir("/data/data/com.termux")):
        print("[*] Termux environment detected.")
        # Safe to re-run pkg installs
        os.system("pkg update && pkg upgrade -y")
        os.system("pkg install python git -y")
        # Pip install/upgrade
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pycryptodome"])
        # Clone repo if missing
        if not os.path.isdir("netnemesis"):
            print("[*] Cloning GhostMesh repo…")
            subprocess.check_call(["git", "clone", "https://github.com/wizardwithcodehazard/netnemesis.git"])
        else:
            print("[✔] Repo already exists; skipping clone.")
        # Chmod if script present
        nm_path = os.path.join("netnemesis", "netnem.py")
        if os.path.isfile(nm_path):
            os.system(f"chmod +x {nm_path}")
        print("[✔] Termux setup done.\n")
    else:
        print("[✔] Skipping Termux setup.")

    # Ensure Git on non-Android
    if os_name in ("linux", "darwin", "windows"):
        checker = ["where", "git"] if "windows" in os_name else ["which", "git"]
        if subprocess.call(checker, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
            print("[*] Git not found; installing…")
            if "linux" in os_name:
                os.system("sudo apt update && sudo apt install git -y")
            elif "darwin" in os_name:
                os.system("brew install git")
            else:
                print("Please install Git manually: https://git-scm.com/download/win")
        else:
            print("[✔] Git already installed.")

def show_ipv4():
    os_name = platform.system().lower()
    try:
        if "windows" in os_name:
            out = subprocess.check_output("ipconfig", shell=True, text=True)
            ips = re.findall(r"IPv4 Address[^\:]*:\s*([\d\.]+)", out)
        else:
            out = subprocess.check_output("ip addr", shell=True, text=True)
            ips = re.findall(r"\s+inet\s+([\d\.]+)/\d+", out)
        print("Local IPv4 addresses:")
        for ip in sorted(set(ips)):
            print(" -", ip)
    except Exception as e:
        print("IPv4 scan failed:", e)

# ---------- CRYPTO + DNA ----------
def derive_key(passphrase):
    return PBKDF2(passphrase, b"ghostmesh_salt", dkLen=32, count=100000)

NUCS = ['A','T','C','G']
def gen_map(seed):
    random.seed(seed)
    bits = ['00','01','10','11']
    nts = NUCS.copy()
    random.shuffle(nts)
    return {bits[i]: nts[i] for i in range(4)}

def to_dna(data, m):
    dna = ''
    for b in data:
        bits = f"{b:08b}"
        for i in range(0, 8, 2):
            dna += m[bits[i:i+2]]
    return dna

def from_dna(seq, m):
    rev = {v:k for k, v in m.items()}
    bits = ''.join(rev[n] for n in seq)
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))

def encrypt(msg, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(msg.encode())
    return cipher.nonce + tag + ct

def decrypt(blob, key):
    nonce, tag, ct = blob[:16], blob[16:32], blob[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag).decode()

# ---------- PtP HANDLERS ----------
def ptp_server():
    srv = socket.socket()
    srv.bind(("0.0.0.0", PORT))
    srv.listen(1)
    print(f"[PtP] Waiting on port {PORT}…")
    conn, addr = srv.accept()
    print(f"[PtP] Connected: {addr}")
    return conn

def ptp_client(ip):
    cli = socket.socket()
    cli.connect((ip, PORT))
    print(f"[PtP] Connected to {ip}:{PORT}")
    return cli

# ---------- GROUP HANDLERS ----------
group_peers = []
group_lock = threading.Lock()

def group_acceptor():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PORT))
    srv.listen()
    print(f"[Group] Hosting on port {PORT}…")
    while True:
        conn, addr = srv.accept()
        with group_lock:
            group_peers.append(conn)
        threading.Thread(target=group_receiver, args=(conn,), daemon=True).start()

def group_receiver(conn):
    while True:
        try:
            raw = conn.recv(BUFFER_SIZE).decode()
            if not raw:
                break
            # Broadcast to others
            with group_lock:
                for p in group_peers:
                    if p is not conn:
                        p.send(raw.encode())
            header, dna = raw.split("::", 1)
            info = json.loads(header)
            chat_history.append((info['user'], info['seed'], dna))
            print(f"\n[{info['user']}] {dna}\n> ", end="")
        except:
            break
    with group_lock:
        group_peers.remove(conn)
    conn.close()

def group_join(ip):
    cli = socket.socket()
    cli.connect((ip, PORT))
    print(f"[Group] Joined {ip}:{PORT}")
    threading.Thread(target=group_receiver, args=(cli,), daemon=True).start()
    return cli

# ---------- MAIN ----------
if __name__ == "__main__":
    initial_setup()

    print("=== GhostMesh ===")
    username = input("Username: ").strip()
    key = derive_key(getpass("Passphrase: "))

    if input("Scan network? (y/n): ").lower() == 'y':
        show_ipv4()
        print()

    mode = input("Mode? [ptp/group]: ").strip().lower()
    if mode == "ptp":
        role = input("Server or Client? [s/c]: ").strip().lower()
        conn = ptp_server() if role == 's' else ptp_client(input("Server IP: ").strip())
    else:
        role = input("Host or Join? [h/j]: ").strip().lower()
        if role == 'h':
            threading.Thread(target=group_acceptor, daemon=True).start()
            conn = None
        else:
            conn = group_join(input("Host IP: ").strip())

    print("Commands: /decode /save <file> /load <file> /exit")
    while True:
        msg = input("> ").strip()
        if msg == "/exit":
            break
        if msg.startswith("/decode"):
            for i, (u, seed, dna) in enumerate(chat_history, 1):
                if u != username:
                    try:
                        txt = decrypt(from_dna(dna, gen_map(seed)), key)
                        print(f"[Decoded {i} from {u}] {txt}")
                    except Exception as e:
                        print(f"Decode error {i}: {e}")
            continue
        if msg.startswith("/save"):
            fn = msg.split(maxsplit=1)[1] if " " in msg else "chat.fasta"
            with open(fn, "w") as f:
                for i, (u, seed, dna) in enumerate(chat_history, 1):
                    f.write(f">{u}_msg_{i}_seed_{seed}\n{dna}\n")
            print("Saved", fn)
            continue
        if msg.startswith("/load"):
            fn = msg.split(maxsplit=1)[1] if " " in msg else "chat.fasta"
            if not os.path.isfile(fn):
                print("File not found:", fn)
                continue
            lines = [l.strip() for l in open(fn) if l.strip()]
            for i in range(0, len(lines), 2):
                hdr = lines[i][1:]
                u, sd = hdr.rsplit("_seed_", 1)
                chat_history.append((u, int(sd), lines[i+1]))
            print("Loaded entries")
            continue

        # Encrypt & broadcast/send
        blob = encrypt(msg, key)
        seed = random.getrandbits(32)
        dna = to_dna(blob, gen_map(seed))
        payload = json.dumps({"user": username, "seed": seed}) + "::" + dna
        chat_history.append((username, seed, dna))

        if mode == "ptp":
            conn.send(payload.encode())
        else:
            with group_lock:
                for p in group_peers:
                    p.send(payload.encode())

    print("Goodbye.")
