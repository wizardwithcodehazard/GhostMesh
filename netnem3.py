#!/usr/bin/env python3
"""
GhostMesh CLI Tool v5.2 (PtP + Mesh Relay Chat with File Send, Recording & Playback, Termux Safe)

Features:
- Modes: PtP (peer-to-peer TCP) or Mesh (multi-client TCP relay via hotspot)
- Auto dependency check (Termux/Android/Linux/Windows/macOS)
- IPv4-only network scan
- AES-EAX encryption + DNA obfuscation
- Commands: /decode, /send <file>, /record <sec>, /play <file>, /save <file>, /load <file>, /exit

Mesh mode uses the hotspot-connected device as a relay: each client connects to the relay, which forwards all data messages to every other client, forming a star mesh.
Recording uses the system's `arecord` (Linux/Termux) or `rec` (SoX). Playback uses `aplay` or `play`.
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
import time
from getpass import getpass
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

# ---------------- CONFIG ----------------
PORT = 5555
BUFFER_SIZE = 8192
NUCS = ['A','T','C','G']
chat_history = []  # list of (user, seed, dna, type, ext)

mesh_peers = []
mesh_lock = threading.Lock()

# ---------- DEPENDENCY CHECK ----------
def ensure_python_package(pkg, imp=None):
    try:
        __import__(imp or pkg)
    except ImportError:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', pkg])

ensure_python_package('pycryptodome', 'Crypto.Cipher')

# ---------- SETUP ----------
def initial_setup():
    os_name = platform.system().lower()
    print('=== GhostMesh Setup ===')
    if 'android' in os_name or (os_name == 'linux' and os.path.isdir('/data/data/com.termux')):
        os.system('pkg update && pkg upgrade -y && pkg install python git sox -y')
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '--upgrade', 'pycryptodome'])
        print('[✔] Termux setup complete.')
    else:
        print('[✔] Non-Termux setup. Ensure `arecord`/`rec` and `aplay`/`play` are installed.')

# ---------- UTILITIES ----------
def show_ipv4():
    try:
        out = subprocess.check_output('ip addr', shell=True, text=True)
        ips = re.findall(r'\s+inet\s+([\d\.]+)/', out)
        print('Local IPv4 addresses:')
        for ip in set(ips): print(' -', ip)
    except:
        pass

# ---------- CRYPTO + DNA ----------
def derive_key(passphrase):
    return PBKDF2(passphrase, b'ghostmesh_salt', dkLen=32, count=100000)

def gen_map(seed):
    random.seed(seed)
    bits, nts = ['00','01','10','11'], NUCS.copy(); random.shuffle(nts)
    return {bits[i]: nts[i] for i in range(4)}

def to_dna(data, m):
    s = ''
    for b in data:
        bits = f"{b:08b}"
        for i in range(0,8,2): s += m[bits[i:i+2]]
    return s

def from_dna(seq, m):
    rev = {v:k for k,v in m.items()}
    bits = ''.join(rev[c] for c in seq)
    return bytes(int(bits[i:i+8],2) for i in range(0,len(bits),8))

def encrypt(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ct

def decrypt(blob, key):
    nonce, tag, ct = blob[:16], blob[16:32], blob[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)

# ---------- PTP (TCP) ----------
def ptp_server():
    sock = socket.socket()
    sock.bind(('0.0.0.0', PORT)); sock.listen(1)
    print(f'[PtP] Waiting on port {PORT}...')
    conn, addr = sock.accept(); print(f'[PtP] Connected by {addr}')
    return conn

def ptp_client(ip):
    sock = socket.socket(); sock.connect((ip, PORT))
    print(f'[PtP] Connected to {ip}:{PORT}')
    return sock

def ptp_receiver(conn, username, key):
    while True:
        raw = conn.recv(BUFFER_SIZE)
        if not raw: break
        hdr, dna = raw.split(b'::',1)
        info = json.loads(hdr.decode())
        data = decrypt(from_dna(dna.decode(), gen_map(info['seed'])), key)
        if info['type'] == 'msg' and info['user'] != username:
            print(f"\n[{info['user']}] {data.decode()}\n> ", end='')
        else:
            ext = info.get('ext','')
            fname = f"recv_{info['user']}_{info['seed']}.{ext}"
            with open(fname,'wb') as f: f.write(data)
            print(f"\n[{info['user']}] received file saved as {fname}\n> ", end='')

# ---------- MESH MODE ----------
def mesh_relay_host():
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
    srv.bind(('0.0.0.0', PORT)); srv.listen()
    print(f'[Mesh] Relay hosting on port {PORT}')
    while True:
        conn, _ = srv.accept()
        with mesh_lock: mesh_peers.append(conn)
        threading.Thread(target=mesh_relay_receiver, args=(conn,), daemon=True).start()

def mesh_relay_receiver(conn):
    while True:
        raw = conn.recv(BUFFER_SIZE)
        if not raw: break
        with mesh_lock:
            for p in mesh_peers:
                if p is not conn:
                    try: p.send(raw)
                    except: pass
        hdr, dna = raw.split(b'::',1)
        info = json.loads(hdr.decode())
        data = decrypt(from_dna(dna.decode(), gen_map(info['seed'])), key)
        if info['type']=='msg':
            print(f"\n[{info['user']}] {data.decode()}\n> ", end='')
        else:
            ext = info.get('ext','')
            fname = f"recv_{info['user']}_{info['seed']}.{ext}"
            with open(fname,'wb') as f: f.write(data)
            print(f"\n[{info['user']}] received file saved as {fname}\n> ", end='')
    with mesh_lock: mesh_peers.remove(conn)
    conn.close()

def mesh_relay_join(ip):
    sock = socket.socket(); sock.connect((ip, PORT))
    print(f'[Mesh] Joined relay at {ip}:{PORT}')
    threading.Thread(target=mesh_relay_receiver, args=(sock,), daemon=True).start()
    return sock

# ---------- FILE & RECORD ----------
def send_file(filepath, conn, key, username):
    ext = filepath.split('.')[-1]
    data = open(filepath,'rb').read()
    enc = encrypt(data, key)
    seed = random.getrandbits(32)
    dna = to_dna(enc, gen_map(seed))
    info = {'user':username,'seed':seed,'type':'file','ext':ext}
    header = json.dumps(info).encode()
    payload = header + b'::' + dna.encode()
    chat_history.append((username,seed,dna,'file',ext))
    conn.send(payload)
    print(f'Sent file {filepath}')

def record_audio(sec, username):
    fname = f'rec_{username}_{int(time.time())}.wav'
    cmd = ['arecord','-d',sec,'-f','cd',fname]
    if subprocess.call(cmd) !=0:
        subprocess.call(['rec','-q','-c','1',fname,'trim','0',sec])
    print(f'Recorded {sec}s to {fname}')
    return fname

def play_audio(filepath):
    if subprocess.call(['aplay',filepath]) !=0:
        subprocess.call(['play',filepath])

# ----------------- MAIN -----------------
if __name__=='__main__':
    initial_setup()
    username = input('Username: ').strip()
    key = derive_key(getpass('Passphrase: '))
    if input('Scan network? (y/n): ').lower()=='y': show_ipv4()

    mode = input('Mode? [ptp/mesh]: ').strip().lower()
    conn=None
    if mode=='ptp':
        role = input('Server or Client? [s/c]: ').strip().lower()
        conn = ptp_server() if role=='s' else ptp_client(input('Server IP: ').strip())
        threading.Thread(target=ptp_receiver,args=(conn,username,key),daemon=True).start()
    else:
        role = input('Relay host or Join? [h/j]: ').strip().lower()
        if role=='h': threading.Thread(target=mesh_relay_host,daemon=True).start()
        else: conn = mesh_relay_join(input('Relay IP: ').strip())

    print('Commands: /decode /send <file> /record <sec> /play <file> /save <file> /load <file> /exit')
    while True:
        cmd = input('> ').strip()
        if cmd=='/exit': break
        if cmd.startswith('/decode'):
            print('--- History ---')
            for i,(u,seed,dna,typ,ext) in enumerate(chat_history,1):
                if typ=='msg':
                    data=decrypt(from_dna(dna,gen_map(seed)),key)
                    print(f"{i}. [{u}] {data.decode()}")
                else:
                    print(f"{i}. [{u}] sent file .{ext}")
            continue
        if cmd.startswith('/save'):
            fn=cmd.split(maxsplit=1)[1] if ' ' in cmd else 'history.txt'
            with open(fn,'w') as f:
                for u,seed,dna,typ,ext in chat_history:
                    f.write(f">{u}_{typ}_{seed}_{ext}\n{dna}\n")
            print(f'History saved to {fn}')
            continue
        if cmd.startswith('/load'):
            fn=cmd.split(maxsplit=1)[1] if ' ' in cmd else 'history.txt'
            if not os.path.isfile(fn): print(f'Not found: {fn}'); continue
            lines=[l.strip() for l in open(fn) if l.strip()]
            for idx in range(0,len(lines),2):
                hdr=lines[idx][1:].split('_')
                u,typ,seed,ext=hdr
                dna=lines[idx+1]
                chat_history.append((u,int(seed),dna,typ,ext))
            print(f'Loaded from {fn}')
            continue
        if cmd.startswith('/send '):
            fn=cmd.split(maxsplit=1)[1]
            if not os.path.isfile(fn): print(f'Not found: {fn}'); continue
            send_file(fn,conn,key,username)
            continue
        if cmd.startswith('/record '):
            parts=cmd.split()
            sec=parts[1] if len(parts)>1 else '5'
            wf=record_audio(sec,username)
            send_file(wf,conn,key,username)
            continue
        if cmd.startswith('/play '):
            fn=cmd.split(maxsplit=1)[1]
            if not os.path.isfile(fn): print(f'Not found: {fn}'); continue
            print(f'Playing {fn}...')
            play_audio(fn)
            continue
        # text
        data=cmd.encode()
        enc=encrypt(data,key)
        seed=random.getrandbits(32)
        dna=to_dna(enc,gen_map(seed))
        info={'user':username,'seed':seed,'type':'msg'}
        header=json.dumps(info).encode()
        payload=header+b'::'+dna.encode()
        chat_history.append((username,seed,dna,'msg',''))
        if conn: conn.send(payload)
    print('Goodbye.')
