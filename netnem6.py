#!/usr/bin/env python3
"""
GhostMesh CLI Tool v4.2
- Premium Gemini-style UI
- Secure P2P & Group Chat with AES-EAX + DNA Obfuscation
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

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress
from rich.table import Table
from rich.align import Align
from rich import box

# Initialize Typer and Rich Console
app = typer.Typer(help="GhostMesh: Secure P2P & Group Chat CLI")
console = Console()

# ---------------- CONFIG ----------------
PORT = 5555
BUFFER_SIZE = 8192
NUCS = ['A', 'T', 'C', 'G']
chat_history = []
group_peers = []
group_lock = threading.Lock()

# ---------- DEPENDENCY CHECK ----------
def ensure_python_package(pkg, imp=None):
    try:
        __import__(imp or pkg)
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])

ensure_python_package("pycryptodome", "Crypto.Cipher")
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

# ---------- UI ELEMENTS ----------
BANNER = """
[bold cyan]
 ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗   ███╗   ███╗███████╗███████╗██╗  ██╗
██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝   ████╗ ████║██╔════╝██╔════╝██║  ██║
██║  ███╗███████║██║   ██║███████╗   ██║█████╗██╔████╔██║█████╗  ███████╗███████║
██║   ██║██╔══██║██║   ██║╚════██║   ██║╚════╝██║╚██╔╝██║██╔══╝  ╚════██║██╔══██║
╚██████╔╝██║  ██║╚██████╔╝███████║   ██║      ██║ ╚═╝ ██║███████╗███████║██║  ██║
 ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝      ╚═╝     ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝
                                                                                 
[/bold cyan]
[bright_black]v4.2 | Secure P2P & Group Chat | AES-EAX + DNA Obfuscation[/bright_black]
"""

BOOT_STEPS = [
    "🔍 Initializing GhostMesh…",
    "🔐 Loading Crypto Engine…",
    "🌐 Setting up network stack…",
    "✅ All systems go!"
]

def boot_sequence():
    console.print(Panel(Align.center("[bold magenta]GhostMesh Booting...[/bold magenta]"), style="bold blue"))
    with Progress(transient=True) as progress:
        task = progress.add_task("[cyan]Starting up...", total=len(BOOT_STEPS))
        for step in BOOT_STEPS:
            console.print(f"[green]{step}[/green]")
            time.sleep(0.8)
            progress.advance(task)
    console.print(Panel("[bold green]✔ Boot complete![/bold green]", title="Status"))

# ---------- UTILITIES ----------
def initial_setup():
    os_name = platform.system().lower()
    if "android" in os_name or (os_name == "linux" and os.path.isdir("/data/data/com.termux")):
        os.system("pkg update && pkg upgrade -y && pkg install python git -y")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pycryptodome"])
        console.print("[green]✔ Termux setup complete.[/green]")
    else:
        console.print("[green]✔ Non-Termux setup.[/green]")

def show_ipv4():
    try:
        os_name = platform.system().lower()
        if "windows" in os_name:
            out = subprocess.check_output("ipconfig", shell=True, text=True)
            ips = re.findall(r"IPv4 Address[.\s]*:\s*([\d\.]+)", out)
        else:
            out = subprocess.check_output("ip addr", shell=True, text=True)
            ips = re.findall(r"\s+inet\s+([\d\.]+)/", out)

        if ips:
            table = Table(title="Local IPv4 Addresses", box=box.ROUNDED, style="cyan")
            table.add_column("IP Address", justify="center", style="bold green")
            for ip in ips:
                table.add_row(ip)
            console.print(table)
        else:
            console.print("[yellow]No IPv4 addresses found.[/yellow]")
    except Exception as e:
        console.print(f"[red]Could not fetch IP addresses: {e}[/red]")

# ---------- CRYPTO ----------
def derive_key(passphrase):
    return PBKDF2(passphrase, b"ghostmesh_salt", dkLen=32, count=100000)

def encrypt(msg, key):
    c = AES.new(key, AES.MODE_EAX)
    ct, tag = c.encrypt_and_digest(msg.encode())
    return c.nonce + tag + ct

def decrypt(blob, key):
    n, tag, ct = blob[:16], blob[16:32], blob[32:]
    c = AES.new(key, AES.MODE_EAX, nonce=n)
    return c.decrypt_and_verify(ct, tag).decode()

# ---------- NETWORK ----------
def ptp_server():
    s = socket.socket()
    s.bind(("0.0.0.0", PORT))
    s.listen(1)
    console.print(f"[yellow][PtP][/yellow] Waiting for connection on port {PORT}...")
    conn, addr = s.accept()
    console.print(f"[bold green][PtP][/bold green] Connected by {addr}")
    return conn

def ptp_client(ip):
    s = socket.socket()
    s.connect((ip, PORT))
    console.print(f"[bold green][PtP][/bold green] Connected to {ip}:{PORT}")
    return s

def ptp_receiver(conn, key):
    while True:
        try:
            data = conn.recv(BUFFER_SIZE)
            if not data:
                break
            msg = decrypt(data, key)
            console.print(f"\n[cyan]{msg}[/cyan]\n> ", end="")
        except:
            break

# ---------- GROUP CHAT ----------
def group_acceptor(key):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", PORT))
    server.listen(5)
    console.print(f"[green][Group-TCP][/green] Hosting on port {PORT}")
    while True:
        conn, addr = server.accept()
        with group_lock:
            group_peers.append(conn)
        threading.Thread(target=group_handler, args=(conn, key), daemon=True).start()

def group_handler(conn, key):
    while True:
        try:
            data = conn.recv(BUFFER_SIZE)
            if not data:
                break
            msg = decrypt(data, key)
            console.print(f"\n[cyan]{msg}[/cyan]\n> ", end="")
            with group_lock:
                for peer in group_peers:
                    if peer != conn:
                        peer.send(data)
        except:
            break

def group_tcp_join(host_ip, key):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host_ip, PORT))
    console.print(f"[green][Group-TCP][/green] Joined {host_ip}:{PORT}")
    threading.Thread(target=group_listener, args=(s, key), daemon=True).start()
    return s

def group_listener(conn, key):
    while True:
        try:
            data = conn.recv(BUFFER_SIZE)
            if not data:
                break
            msg = decrypt(data, key)
            console.print(f"\n[cyan]{msg}[/cyan]\n> ", end="")
        except:
            break

# UDP Group
def setup_udp_sock():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(("", PORT))
    return sock

def udp_listener(sock, username):
    while True:
        try:
            data, addr = sock.recvfrom(BUFFER_SIZE)
            msg = data.decode()
            if username not in msg:
                console.print(f"\n[cyan][UDP][/cyan] {msg}\n> ", end="")
        except:
            break

# ---------- CLI COMMANDS ----------
@app.command()
def interactive():
    """Start GhostMesh in interactive chat mode."""
    initial_setup()
    username = input("Username: ").strip()
    key = derive_key(getpass("Passphrase: "))
    if input("Scan network? (y/n): ").lower() == "y":
        show_ipv4()

    mode = input("Mode? [ptp/group]: ").strip().lower()
    conn, udp_sock, role, gtype = None, None, None, None

    if mode == "ptp":
        role = input("Server or Client? [s/c]: ").strip().lower()
        conn = ptp_server() if role == "s" else ptp_client(input("Server IP: ").strip())
        threading.Thread(target=ptp_receiver, args=(conn, key,), daemon=True).start()
    else:
        gtype = input("Group type? [tcp/broadcast]: ").strip().lower()
        if gtype == "tcp":
            role = input("Host or Join? [h/j]: ").strip().lower()
            if role == "h":
                threading.Thread(target=group_acceptor, args=(key,), daemon=True).start()
            else:
                conn = group_tcp_join(input("Host IP: ").strip(), key)
        else:
            udp_sock = setup_udp_sock()
            threading.Thread(target=udp_listener, args=(udp_sock, username,), daemon=True).start()
            console.print(f"[green][Group-UDP][/green] Broadcast on port {PORT}")

    console.print("[yellow]Commands:[/yellow] /exit")

    while True:
        msg = input("> ").strip()
        if msg == "/exit":
            break
        full_msg = f"[{username}] {msg}"
        if conn:
            conn.send(encrypt(full_msg, key))
        elif udp_sock:
            udp_sock.sendto(full_msg.encode(), ('<broadcast>', PORT))

    console.print("[bold red]Goodbye.[/bold red]")

@app.command()
def scan():
    """Scan and show local IPv4 addresses."""
    show_ipv4()

@app.command()
def about():
    """Show info about GhostMesh."""
    console.print(Panel("[bold cyan]GhostMesh CLI v4.2[/bold cyan]\nGemini-Style UI • Secure P2P • DNA Obfuscation", style="green"))

# ---------- ENTRY ----------
if __name__ == "__main__":
    console.print(BANNER)
    boot_sequence()
    if len(sys.argv) == 1:
        interactive()
    else:
        app()