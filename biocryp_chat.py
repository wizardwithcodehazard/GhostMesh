#!/usr/bin/env python3
"""
BioCryp CLI Tool v0.2
Features:
- Peer-to-peer encrypted chat over TCP (Wi-Fi) or Bluetooth
- DNA sequence encoding of ciphertext, with mapping seed included
- Per-message mapping via seed ensures correct decode
- Mutate DNA on display is removed (robust decoding)
- Save/Load chat in FASTA format
- CLI commands: /decode, /save <file>, /load <file>, /exit
"""
import socket
import threading
import random
import os
import sys
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Attempt to import Bluetooth; if missing, Bluetooth mode disabled
try:
    from bluetooth import BluetoothSocket, discover_devices, RFCOMM
    BT_AVAILABLE = True
except ImportError:
    BT_AVAILABLE = False

# ---------- CONFIGURATION ----------
PORT = 5555
BUFFER_SIZE = 8192
chat_history = []  # list of (username, seed, dna_seq)

# ---------- DNA ENCODING ----------
NUCLEOTIDES = ['A', 'T', 'C', 'G']

def generate_mapping(seed):
    random.seed(seed)
    bits = ['00', '01', '10', '11']
    nts = NUCLEOTIDES.copy()
    random.shuffle(nts)
    return {bits[i]: nts[i] for i in range(4)}


def encode_to_dna(binary_data, mapping):
    dna = ''
    for b in binary_data:
        bits = f"{b:08b}"
        for i in range(0, 8, 2):
            dna += mapping[bits[i:i+2]]
    return dna


def decode_from_dna(dna_seq, mapping):
    rev_map = {v: k for k, v in mapping.items()}
    bits = ''.join(rev_map[n] for n in dna_seq)
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))

# ---------- CRYPTOGRAPHY (AES placeholder for PQ) ----------
def generate_key():
    return get_random_bytes(32)  # 256-bit key


def encrypt_message(msg: str, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(msg.encode())
    return cipher.nonce + tag + ct


def decrypt_message(data: bytes, key: bytes) -> str:
    nonce = data[:16]
    tag = data[16:32]
    ct = data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag).decode()

# ---------- FASTA UTILITIES ----------
def save_fasta(filename: str):
    with open(filename, 'w') as f:
        for i, (user, seed, dna) in enumerate(chat_history, 1):
            f.write(f">{user}_msg_{i}_seed_{seed}\n")
            f.write(dna + "\n")
    print(f"Chat saved to {filename}")


def load_fasta(filename: str):
    if not os.path.exists(filename):
        print(f"File {filename} not found.")
        return
    entries = []
    with open(filename) as f:
        lines = [l.strip() for l in f if l.strip()]
    for i in range(0, len(lines), 2):
        header = lines[i][1:]
        parts = header.split('_seed_')
        user = parts[0]
        seed = int(parts[1])
        seq = lines[i+1]
        entries.append((user, seed, seq))
    for entry in entries:
        chat_history.append(entry)
    print(f"Loaded {len(entries)} entries from {filename}")

# ---------- CONNECTION HANDLERS ----------

# TCP Mode
def tcp_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", PORT))
    s.listen(1)
    print(f"[TCP] Waiting for connection on port {PORT}...")
    conn, addr = s.accept()
    print(f"[TCP] Connected by {addr}")
    return conn


def tcp_client(ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, PORT))
    print(f"[TCP] Connected to {ip}:{PORT}")
    return s

# Bluetooth Mode
def bt_server():
    if not BT_AVAILABLE:
        print("PyBluez not installed; Bluetooth unavailable.")
        sys.exit(1)
    srv = BluetoothSocket(RFCOMM)
    srv.bind(("", PORT))
    srv.listen(1)
    print(f"[BT] Waiting for BT connection on RFCOMM channel {PORT}...")
    conn, addr = srv.accept()
    print(f"[BT] Connected by {addr}")
    return conn


def bt_client():
    if not BT_AVAILABLE:
        print("PyBluez not installed; Bluetooth unavailable.")
        sys.exit(1)
    devices = discover_devices(lookup_names=True)
    for i, (addr, name) in enumerate(devices, 1):
        print(f"  {i}. {name} [{addr}]")
    sel = int(input("Select device: ")) - 1
    addr = devices[sel][0]
    cli = BluetoothSocket(RFCOMM)
    cli.connect((addr, PORT))
    print(f"[BT] Connected to {addr}:{PORT}")
    return cli

# ---------- RECEIVE LOOP ----------

def receive_loop(conn):
    while True:
        try:
            raw = conn.recv(BUFFER_SIZE).decode()
            if not raw:
                break
            # Expect JSON header + :: + dna
            header, dna = raw.split('::', 1)
            info = json.loads(header)
            user = info['user']
            seed = info['seed']
            chat_history.append((user, seed, dna))
            print(f"\n[{user}] {dna}\n> ", end='')
        except Exception as e:
            print(f"Receive error: {e}")
            break

# ---------- MAIN ----------
if __name__ == '__main__':
    print("=== BioCryp CLI Chat v0.2 ===")
    username = input("Your username: ").strip()
    transport = input("Transport (tcp/bt): ").strip().lower()

    # Establish connection
    if transport == 'tcp':
        mode = input("Mode (server/client): ").strip().lower()
        conn = tcp_server() if mode == 'server' else tcp_client(input("Server IP: ").strip())
    elif transport == 'bt':
        if not BT_AVAILABLE:
            print("Bluetooth support unavailable.")
            sys.exit(1)
        mode = input("Mode (server/client): ").strip().lower()
        conn = bt_server() if mode == 'server' else bt_client()
    else:
        print("Invalid transport mode.")
        sys.exit(1)

    key = generate_key()
    threading.Thread(target=receive_loop, args=(conn,), daemon=True).start()

    print("Type messages. Commands: /decode /save <file> /load <file> /exit")
    while True:
        inp = input("> ").strip()
        if inp == '/exit':
            print("Goodbye.")
            conn.close()
            break
        if inp.startswith('/decode'):
            for i, (user, seed, dna) in enumerate(chat_history):
                if user != username:
                    try:
                        mapping = generate_mapping(seed)
                        data = decode_from_dna(dna, mapping)
                        text = decrypt_message(data, key)
                        print(f"[Decoded {i+1} from {user}] {text}")
                    except Exception as e:
                        print(f"Decode error {i+1}: {e}")
        elif inp.startswith('/save'):
            fname = inp.split(maxsplit=1)[1] if ' ' in inp else 'chat.fasta'
            save_fasta(fname)
        elif inp.startswith('/load'):
            fname = inp.split(maxsplit=1)[1] if ' ' in inp else 'chat.fasta'
            load_fasta(fname)
        else:
            # Send message
            ciphertext = encrypt_message(inp, key)
            seed = random.getrandbits(32)
            mapping = generate_mapping(seed)
            dna = encode_to_dna(ciphertext, mapping)
            # Prepare header
            header = json.dumps({'user': username, 'seed': seed})
            payload = header + '::' + dna
            chat_history.append((username, seed, dna))
            try:
                conn.send(payload.encode())
            except Exception as e:
                print(f"Send error: {e}")
