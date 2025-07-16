#!/usr/bin/env python3
"""
BioCryp CLI Tool v0.1
Features:
- Peer-to-peer encrypted chat over TCP (Wi-Fi) or Bluetooth
- DNA sequence encoding of ciphertext
- Mutation on every /decode
- Save/Load chat in FASTA format
- CLI commands: /decode, /save, /load, /exit
"""
import socket
import threading
import random
import os
import sys
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
BUFFER_SIZE = 4096
chat_history = []  # list of (username, dna_seq)

# ---------- DNA ENCODING ----------
NUCLEOTIDES = ['A', 'T', 'C', 'G']

def generate_mapping(seed=None):
    if seed is not None:
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
    rev = {v: k for k, v in mapping.items()}
    bits = ''.join(rev[n] for n in dna_seq)
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
        for i, (user, dna) in enumerate(chat_history, 1):
            f.write(f">{user}_msg_{i}\n")
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
        seq = lines[i+1]
        entries.append((header, seq))
    print(f"Loaded {len(entries)} entries from {filename}")
    for hdr, dna in entries:
        chat_history.append((hdr, dna))

# ---------- CONNECTION HANDLERS ----------

# Wi-Fi (TCP) Mode

def tcp_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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


def bt_client(bt_addr):
    if not BT_AVAILABLE:
        print("PyBluez not installed; Bluetooth unavailable.")
        sys.exit(1)
    cli = BluetoothSocket(RFCOMM)
    cli.connect((bt_addr, PORT))
    print(f"[BT] Connected to {bt_addr}:{PORT}")
    return cli

# ---------- MESSAGE HANDLER ----------
def receive_loop(conn, peer_name, key, mapping):
    while True:
        try:
            data = conn.recv(BUFFER_SIZE)
            if not data:
                break
            dna = data.decode()
            chat_history.append((peer_name, dna))
            print(f"\n[{peer_name}] {dna}\n> ", end='')
        except Exception as e:
            print(f"Receive error: {e}")
            break

# ---------- MAIN CHAT LOOP ----------
if __name__ == '__main__':
    print("=== BioCryp CLI Chat ===")
    username = input("Your username: ").strip()
    transport = input("Transport (tcp/bt): ").strip().lower()

    # Setup connection
    if transport == 'tcp':
        mode = input("Mode (server/client): ").strip().lower()
        if mode == 'server':
            conn = tcp_server()
        else:
            ip = input("Server IP: ").strip()
            conn = tcp_client(ip)
    elif transport == 'bt':
        if not BT_AVAILABLE:
            print("Bluetooth support not available. Install PyBluez.")
            sys.exit(1)
        mode = input("Mode (server/client): ").strip().lower()
        if mode == 'server':
            conn = bt_server()
        else:
            print("Discovering BT devices...")
            devices = discover_devices(lookup_names=True)
            for i, (addr, name) in enumerate(devices, 1):
                print(f"{i}. {name} [{addr}]")
            sel = int(input("Select device: ")) - 1
            conn = bt_client(devices[sel][0])
    else:
        print("Unknown transport.")
        sys.exit(1)

    # Initialize crypto state
    key = generate_key()
    mapping = generate_mapping()
    peer_name = 'Peer'

    # Start receiver thread
    threading.Thread(target=receive_loop, args=(conn, peer_name, key, mapping), daemon=True).start()

    # Chat input loop
    print("Type messages to send. Commands: /decode /save <file> /load <file> /exit")
    while True:
        inp = input("> ").strip()
        if inp == '/exit':
            print("Exiting...")
            conn.close()
            break
        elif inp.startswith('/decode'):
            # Decode all peer messages
            new_map = generate_mapping()
            for i, (user, dna) in enumerate(chat_history):
                if user == peer_name:
                    try:
                        data = decode_from_dna(dna, mapping)
                        text = decrypt_message(data, key)
                        print(f"[Decoded {i+1}] {text}")
                        # Mutate DNA
                        mapping = new_map
                        new_dna = encode_to_dna(data, mapping)
                        chat_history[i] = (user, new_dna)
                    except Exception as e:
                        print(f"Decode error: {e}")
        elif inp.startswith('/save'):
            parts = inp.split()
            fname = parts[1] if len(parts) > 1 else 'chat.fasta'
            save_fasta(fname)
        elif inp.startswith('/load'):
            parts = inp.split()
            fname = parts[1] if len(parts) > 1 else 'chat.fasta'
            load_fasta(fname)
        else:
            # Regular message: encrypt -> encode -> send
            data = encrypt_message(inp, key)
            mapping = generate_mapping()  # New mapping per message
            dna = encode_to_dna(data, mapping)
            chat_history.append((username, dna))
            try:
                conn.send(dna.encode())
            except Exception as e:
                print(f"Send error: {e}")
