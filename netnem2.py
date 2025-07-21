#!/usr/bin/env python3
"""
GhostMesh CLI Tool v2.1 (PtP + UDP/TCP Group Chat, Termux Safe)
Features:
- Modes: PtP (peer-to-peer TCP) or Group (multi-client UDP broadcast or TCP relay)
- Auto dependency check (Termux/Android/Linux/Windows/macOS)
- IPv4-only network scan
- AES-EAX encryption + DNA obfuscation
- Commands: /decode, /save, /load, /exit
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

# ---------------- CONFIG ----------------
PORT = 5555
BUFFER_SIZE = 8192
NUCS = ['A','T','C','G']
chat_history = []  # list of (user, seed, dna)

group_peers = []
group_lock = threading.Lock()

# ---------- DEPENDENCY CHECK ----------
def ensure_python_package(pkg, imp=None):
    try:
        __import__(imp or pkg)
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])

ensure_python_package = ensure_python_package  # fallback
ensure_python_package("pycryptodome", "Crypto.Cipher")
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

# ---------- SETUP ----------
def initial_setup():
    os_name = platform.system().lower()
    print("=== GhostMesh Setup ===")
    if "android" in os_name or (os_name == "linux" and os.path.isdir("/data/data/com.termux")):
        print("[*] Termux detected. Checking dependencies...")
        os.system("pkg update && pkg upgrade -y")
        os.system("pkg install python git -y")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pycryptodome"])
        print("[✔] Termux setup complete.\n")
    else:
        print("[✔] Non-Termux setup. Skipping pkg installs.")
    checker = ["where","git"] if "windows" in os_name else ["which","git"]
    if subprocess.call(checker, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
        print("[!] Git not found. Install manually if needed.")
    else:
        print("[✔] Git already installed.")

# ---------- UTILITIES ----------
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

def gen_map(seed):
    random.seed(seed)
    bits = ['00','01','10','11']
    nts = NUCS.copy(); random.shuffle(nts)
    return {bits[i]: nts[i] for i in range(4)}

def to_dna(data, m):
    s = ''
    for b in data:
        bits = f"{b:08b}"
        for i in range(0,8,2): s += m[bits[i:i+2]]
    return s

def from_dna(seq, m):
    rev = {v:k for k,v in m.items()}
    bits = ''.join(rev[n] for n in seq)
    return bytes(int(bits[i:i+8],2) for i in range(0,len(bits),8))

def encrypt(msg, key):
    c = AES.new(key, AES.MODE_EAX)
    ct, tag = c.encrypt_and_digest(msg.encode())
    return c.nonce + tag + ct

def decrypt(blob, key):
    n, tag, ct = blob[:16], blob[16:32], blob[32:]
    c = AES.new(key, AES.MODE_EAX, nonce=n)
    return c.decrypt_and_verify(ct, tag).decode()

# ---------- PTP (TCP) ----------
def ptp_server():
    s = socket.socket()
    s.bind(("0.0.0.0", PORT)); s.listen(1)
    print(f"[PtP] Waiting on {PORT}…")
    conn, addr = s.accept(); print(f"[PtP] Connected: {addr}")
    return conn

def ptp_client(ip):
    s = socket.socket(); s.connect((ip, PORT))
    print(f"[PtP] Connected to {ip}:{PORT}")
    return s

def ptp_receiver(conn, username, key):
    while True:
        try:
            raw = conn.recv(BUFFER_SIZE)
            if not raw: break
            header, dna = raw.decode().split("::",1)
            info = json.loads(header)
            chat_history.append((info['user'], info['seed'], dna))
            print(f"\n[{info['user']}] {dna}\n> ", end="")
        except: break

# ---------- GROUP TCP (Relay) ----------
def group_acceptor():
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PORT)); srv.listen()
    print(f"[Group-TCP] Hosting on {PORT}…")
    while True:
        conn, addr = srv.accept()
        with group_lock: group_peers.append(conn)
        threading.Thread(target=group_tcp_receiver, args=(conn,), daemon=True).start()

def group_tcp_receiver(conn):
    while True:
        try:
            raw = conn.recv(BUFFER_SIZE)
            if not raw: break
            with group_lock:
                for p in group_peers:
                    if p is not conn:
                        try: p.send(raw)
                        except: pass
            header, dna = raw.decode().split("::",1)
            info = json.loads(header)
            chat_history.append((info['user'], info['seed'], dna))
            print(f"\n[{info['user']}] {dna}\n> ", end="")
        except: break
    with group_lock: group_peers.remove(conn)
    conn.close()

def group_tcp_join(ip):
    s = socket.socket(); s.connect((ip, PORT))
    print(f"[Group-TCP] Joined {ip}:{PORT}")
    threading.Thread(target=group_tcp_receiver, args=(s,), daemon=True).start()
    return s

# ---------- GROUP UDP (Broadcast) ----------
def setup_udp_sock():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.bind(("0.0.0.0", PORT))
    return s

def udp_listener(sock, username):
    while True:
        try:
            raw, addr = sock.recvfrom(BUFFER_SIZE)
            header, dna = raw.decode().split("::",1)
            info = json.loads(header)
            if info.get('user') == username: continue
            chat_history.append((info['user'], info.get('seed'), dna))
            print(f"\n[{info['user']}] {dna}\n> ", end="")
        except: continue

# ----------------- MAIN -----------------
if __name__ == "__main__":
    initial_setup()
    print("=== GhostMesh ===")
    username = input("Username: ").strip()
    key = derive_key(getpass("Passphrase: "))

    if input("Scan network? (y/n): ").lower() == "y":
        show_ipv4()

    mode = input("Mode? [ptp/group]: ").strip().lower()

    if mode == "ptp":
        role = input("Server or Client? [s/c]: ").strip().lower()
        conn = ptp_server() if role == "s" else ptp_client(input("Server IP: ").strip())
        threading.Thread(target=ptp_receiver, args=(conn, username, key), daemon=True).start()

    else:
        # choose group type
        gtype = input("Group type? [tcp/broadcast]: ").strip().lower()
        if gtype == "tcp":
            sub = input("Host or Join? [h/j]: ").strip().lower()
            if sub == "h":
                threading.Thread(target=group_acceptor, daemon=True).start()
                conn = None
            else:
                conn = group_tcp_join(input("Host IP: ").strip())
        else:
            udp_sock = setup_udp_sock()
            threading.Thread(target=udp_listener, args=(udp_sock, username), daemon=True).start()
            print(f"[Group-UDP] Broadcast on port {PORT}… no explicit join needed.")

    print("Commands: /decode /save <file> /load <file> /exit")
    while True:
        msg = input("> ").strip()
        if msg == "/exit": break

        if msg.startswith("/decode"):
            for i, (u, seed, dna) in enumerate(chat_history, 1):
                if u != username:
                    try:
                        txt = decrypt(from_dna(dna, gen_map(seed)), key)
                        print(f"[Decoded {i} from {u}] {txt}")
                    except Exception as e:
                        print(f"Err {i}: {e}")
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
            if not os.path.isfile(fn): print("No", fn); continue
            lines = [l.strip() for l in open(fn) if l.strip()]
            for i in range(0, len(lines), 2):
                hdr = lines[i][1:]
                u, sd = hdr.rsplit("_seed_",1)
                chat_history.append((u, int(sd), lines[i+1]))
            print("Loaded entries")
            continue

        # encrypt & send
        blob = encrypt(msg, key)
        seed = random.getrandbits(32)
        dna = to_dna(blob, gen_map(seed))
        header = json.dumps({"user": username, "seed": seed})
        payload = f"{header}::{dna}".encode()
        chat_history.append((username, seed, dna))

        if mode == "ptp":
            conn.send(payload)
        else:
            if gtype == "tcp":
                for p in group_peers:
                    try: p.send(payload)
                    except: pass
            else:
                udp_sock.sendto(payload, ('<broadcast>', PORT))

    print("Goodbye.")