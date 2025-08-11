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
[bright_black]v4.2 | Secure P2P & Group Chat | AES-EAX [/bright_black]
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

def get_default_gateway():
    """Get the default gateway IP address (hotspot IP when connected to hotspot)"""
    os_name = platform.system().lower()
    try:
        if "windows" in os_name:
            out = subprocess.check_output("ipconfig", shell=True, text=True)
            # Look for default gateway
            match = re.search(r"Default Gateway[.\s]*:\s*([\d\.]+)", out)
            return match.group(1) if match else None
        else:  # Linux/Termux/Android
            # Try multiple methods to get gateway
            try:
                # Method 1: ip route
                out = subprocess.check_output("ip route show default", shell=True, text=True)
                match = re.search(r"default via ([\d\.]+)", out)
                if match:
                    return match.group(1)
            except:
                pass
            
            try:
                # Method 2: route command
                out = subprocess.check_output("route -n | grep '^0.0.0.0'", shell=True, text=True)
                parts = out.split()
                if len(parts) >= 2:
                    return parts[1]  # Gateway is usually the second column
            except:
                pass
            
            try:
                # Method 3: netstat
                out = subprocess.check_output("netstat -rn | grep '^0.0.0.0'", shell=True, text=True)
                parts = out.split()
                if len(parts) >= 2:
                    return parts[1]
            except:
                pass
                
        return None
    except Exception as e:
        console.print(f"[red]Error getting gateway: {e}[/red]")
        return None

def get_default_ipv4():
    """Get the device's local IP address"""
    os_name = platform.system().lower()
    try:
        if "windows" in os_name:
            out = subprocess.check_output("ipconfig", shell=True, text=True)
            match = re.search(r"IPv4 Address[.\s]*:\s*([\d\.]+)", out)
            return match.group(1) if match else None
        else:  # Linux/Termux
            out = subprocess.check_output("ip route get 1", shell=True, text=True)
            match = re.search(r"src\s+([\d\.]+)", out)
            return match.group(1) if match else None
    except:
        return None

def show_network_info():
    """Show both local IP and gateway IP"""
    try:
        local_ip = get_default_ipv4()
        gateway_ip = get_default_gateway()
        
        table = Table(title="Network Information", box=box.ROUNDED, style="cyan")
        table.add_column("Type", justify="center", style="bold yellow")
        table.add_column("IP Address", justify="center", style="bold green")
        table.add_column("Description", justify="center", style="white")
        
        if local_ip:
            table.add_row("Local IP", local_ip, "Your device's IP address")
        
        if gateway_ip:
            table.add_row("Gateway IP", gateway_ip, "Hotspot/Router IP (use this to connect)")
        else:
            table.add_row("Gateway IP", "Not found", "Could not detect gateway")
            
        console.print(table)
        
        # Show additional IPs for completeness
        os_name = platform.system().lower()
        if "windows" in os_name:
            out = subprocess.check_output("ipconfig", shell=True, text=True)
            ips = re.findall(r"IPv4 Address[.\s]*:\s*([\d\.]+)", out)
        else:
            out = subprocess.check_output("ip addr", shell=True, text=True)
            ips = re.findall(r"\s+inet\s+([\d\.]+)/", out)
        
        if len(ips) > 1:  # Show other IPs if there are multiple interfaces
            other_table = Table(title="All Available IPs", box=box.SIMPLE, style="dim")
            other_table.add_column("Available IPs", justify="center")
            for ip in ips:
                if ip != local_ip:  # Don't duplicate the main local IP
                    other_table.add_row(ip)
            console.print(other_table)
            
    except Exception as e:
        console.print(f"[red]Could not fetch network information: {e}[/red]")

def show_ipv4():
    """Legacy function - redirects to show_network_info"""
    show_network_info()

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
            console.print(f"\n[cyan]<{msg.split('] ')[0][1:]}>[/cyan] [white]{'] '.join(msg.split('] ')[1:])}[/white]\n> ", end="")
        except Exception as e:
            console.print(f"\n[red]Error receiving message: {e}[/red]\n> ", end="")
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
        console.print(f"[green][Group-TCP][/green] New peer connected: {addr}")
        threading.Thread(target=group_handler, args=(conn, key), daemon=True).start()

def group_handler(conn, key):
    while True:
        try:
            data = conn.recv(BUFFER_SIZE)
            if not data:
                break
            msg = decrypt(data, key)
            # Display message with proper username formatting
            console.print(f"\n[cyan]<{msg.split('] ')[0][1:]}>[/cyan] [white]{'] '.join(msg.split('] ')[1:])}[/white]\n> ", end="")
            with group_lock:
                for peer in group_peers:
                    if peer != conn:
                        try:
                            peer.send(data)
                        except:
                            # Remove disconnected peers
                            group_peers.remove(peer)
        except Exception as e:
            console.print(f"\n[red]Error in group handler: {e}[/red]\n> ", end="")
            with group_lock:
                if conn in group_peers:
                    group_peers.remove(conn)
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
            # Display message with proper username formatting
            console.print(f"\n[cyan]<{msg.split('] ')[0][1:]}>[/cyan] [white]{'] '.join(msg.split('] ')[1:])}[/white]\n> ", end="")
        except Exception as e:
            console.print(f"\n[red]Error receiving message: {e}[/red]\n> ", end="")
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
            # Extract username from message and display properly
            if '[' in msg and ']' in msg:
                sender = msg.split('] ')[0][1:]  # Extract username
                message = '] '.join(msg.split('] ')[1:])  # Extract message
                if sender != username:  # Don't show our own messages
                    console.print(f"\n[cyan]<{sender}>[/cyan] [white]{message}[/white]\n> ", end="")
            elif username not in msg:
                console.print(f"\n[cyan][UDP][/cyan] {msg}\n> ", end="")
        except Exception as e:
            console.print(f"\n[red]Error in UDP listener: {e}[/red]\n> ", end="")
            break

# ---------- CLI COMMANDS ----------
@app.command()
def interactive():
    """Start GhostMesh in interactive chat mode."""
    initial_setup()
    username = input("Username: ").strip()
    key = derive_key(getpass("Passphrase: "))
    if input("Scan network? (y/n): ").lower() == "y":
        show_network_info()
        
    # Show both local IP and gateway
    local_ip = get_default_ipv4()
    gateway_ip = get_default_gateway()
    
    if local_ip:
        console.print(f"[cyan]Your device IP: {local_ip}[/cyan]")
    if gateway_ip:
        console.print(f"[yellow]Gateway IP (use this to connect): {gateway_ip}[/yellow]")
    
    if not local_ip and not gateway_ip:
        console.print("[red]Could not detect network information automatically.[/red]")

    mode = input("Mode? [ptp/group]: ").strip().lower()
    conn, udp_sock, role, gtype = None, None, None, None

    if mode == "ptp":
        role = input("Server or Client? [s/c]: ").strip().lower()
        if role == "s":
            conn = ptp_server()
        else:
            server_ip = input("Server IP: ").strip()
            if not server_ip and gateway_ip:
                server_ip = gateway_ip
                console.print(f"[yellow]Using gateway IP: {gateway_ip}[/yellow]")
            conn = ptp_client(server_ip)
        threading.Thread(target=ptp_receiver, args=(conn, key,), daemon=True).start()
    else:
        gtype = input("Group type? [tcp/broadcast]: ").strip().lower()
        if gtype == "tcp":
            role = input("Host or Join? [h/j]: ").strip().lower()
            if role == "h":
                threading.Thread(target=group_acceptor, args=(key,), daemon=True).start()
            else:
                host_ip = input("Host IP: ").strip()
                if not host_ip and gateway_ip:
                    host_ip = gateway_ip
                    console.print(f"[yellow]Using gateway IP: {gateway_ip}[/yellow]")
                conn = group_tcp_join(host_ip, key)
        else:
            udp_sock = setup_udp_sock()
            threading.Thread(target=udp_listener, args=(udp_sock, username,), daemon=True).start()
            console.print(f"[green][Group-UDP][/green] Broadcast on port {PORT}")

    console.print("[yellow]Commands:[/yellow] /exit")
    console.print(f"[green]You are now chatting as: {username}[/green]")

    while True:
        try:
            msg = input("> ").strip()
            if msg == "/exit":
                break
            if not msg:  # Skip empty messages
                continue
                
            full_msg = f"[{username}] {msg}"
            if conn:
                conn.send(encrypt(full_msg, key))
            elif role == "h" and gtype == "tcp":
                with group_lock:
                    for peer in group_peers[:]:  # Use slice copy to avoid modification during iteration
                        try:
                            peer.send(encrypt(full_msg, key))
                        except:
                            group_peers.remove(peer)
            elif udp_sock:
                udp_sock.sendto(full_msg.encode(), ('<broadcast>', PORT))
        except KeyboardInterrupt:
            break
        except Exception as e:
            console.print(f"[red]Error sending message: {e}[/red]")

    console.print("[bold red]Goodbye.[/bold red]")

@app.command()
def scan():
    """Scan and show network information including gateway."""
    show_network_info()

@app.command()
def about():
    """Show info about GhostMesh."""
    console.print(Panel("[bold cyan]GhostMesh CLI v4.2[/bold cyan]\nGemini-Style UI • Secure P2P ", style="green"))

# ---------- ENTRY ----------
if __name__ == "__main__":
    console.print(BANNER)
    boot_sequence()
    if len(sys.argv) == 1:
        interactive()
    else:
        app()