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
def get_broadcast_address():
    """Calculate the broadcast address for the current network"""
    try:
        local_ip = get_default_ipv4()
        if not local_ip:
            return "255.255.255.255"
        
        console.print(f"[yellow]Detecting broadcast for local IP: {local_ip}[/yellow]")
        
        # Get network info using multiple methods
        os_name = platform.system().lower()
        if "windows" not in os_name:
            # Method 1: Try ip addr command
            try:
                # Use more specific grep to find the exact interface
                out = subprocess.check_output(f"ip addr | grep -A 2 -B 2 '{local_ip}'", shell=True, text=True)
                console.print(f"[dim]Network info: {out.strip()}[/dim]")
                
                # Look for CIDR notation
                match = re.search(rf'inet\s+{re.escape(local_ip)}/(\d+)', out)
                if match:
                    prefix_len = int(match.group(1))
                    console.print(f"[yellow]Found network prefix: /{prefix_len}[/yellow]")
                    
                    # Calculate broadcast address
                    ip_parts = [int(x) for x in local_ip.split('.')]
                    
                    # Create subnet mask
                    mask = (0xFFFFFFFF >> (32 - prefix_len)) << (32 - prefix_len)
                    
                    # Calculate network address
                    ip_int = (ip_parts[0] << 24) + (ip_parts[1] << 16) + (ip_parts[2] << 8) + ip_parts[3]
                    network = ip_int & mask
                    broadcast = network | (0xFFFFFFFF >> prefix_len)
                    
                    # Convert back to dotted decimal
                    broadcast_addr = f"{(broadcast >> 24) & 0xFF}.{(broadcast >> 16) & 0xFF}.{(broadcast >> 8) & 0xFF}.{broadcast & 0xFF}"
                    console.print(f"[green]Calculated broadcast: {broadcast_addr}[/green]")
                    return broadcast_addr
            except Exception as e:
                console.print(f"[red]Method 1 failed: {e}[/red]")
            
            # Method 2: Try route command
            try:
                out = subprocess.check_output("route -n", shell=True, text=True)
                # Look for the network that contains our IP
                for line in out.split('\n'):
                    if local_ip in line or 'U' in line:
                        console.print(f"[dim]Route line: {line}[/dim]")
                        # Try to extract network info
                        parts = line.split()
                        if len(parts) >= 3:
                            dest = parts[0]
                            mask = parts[2] if len(parts) > 2 else "255.255.255.0"
                            if dest != "0.0.0.0":
                                # Calculate broadcast from destination and mask
                                console.print(f"[yellow]Found route - Dest: {dest}, Mask: {mask}[/yellow]")
            except Exception as e:
                console.print(f"[red]Method 2 failed: {e}[/red]")
        
        # Method 3: Smart fallback based on IP ranges
        ip_parts = local_ip.split('.')
        first_octet = int(ip_parts[0])
        second_octet = int(ip_parts[1])
        
        console.print(f"[yellow]Using smart fallback for IP range[/yellow]")
        
        # Common network patterns
        if first_octet == 10:
            # Class A private network - could be /8, /16, or /24
            if second_octet in [79]:  # Your case specifically
                broadcast_addr = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.255"
            else:
                broadcast_addr = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.255"  # Assume /24
        elif first_octet == 192 and second_octet == 168:
            # Class C private network - usually /24
            broadcast_addr = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.255"
        elif first_octet == 172 and 16 <= second_octet <= 31:
            # Class B private network - usually /24 in mobile networks
            broadcast_addr = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.255"
        else:
            # Default to /24
            broadcast_addr = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.255"
        
        console.print(f"[green]Fallback broadcast: {broadcast_addr}[/green]")
        return broadcast_addr
        
    except Exception as e:
        console.print(f"[red]Broadcast detection failed: {e}[/red]")
        return "255.255.255.255"

def setup_udp_sock():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Enable broadcast
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # For Android/Termux - try to set additional socket options
    try:
        # Enable port reuse
        if hasattr(socket, 'SO_REUSEPORT'):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except:
        pass
    
    # Try binding with better error handling
    bind_attempts = [
        ("", PORT),  # Bind to all interfaces first
        ("0.0.0.0", PORT),  # Alternative all interfaces
    ]
    
    # Add local IP to attempts if available
    local_ip = get_default_ipv4()
    if local_ip:
        bind_attempts.insert(0, (local_ip, PORT))
    
    bound = False
    for addr in bind_attempts:
        try:
            console.print(f"[yellow]Trying to bind to {addr[0] or 'all interfaces'}:{addr[1]}[/yellow]")
            sock.bind(addr)
            console.print(f"[green]Successfully bound to {addr[0] or 'all interfaces'}:{addr[1]}[/green]")
            bound = True
            break
        except Exception as e:
            console.print(f"[red]Failed to bind to {addr}: {e}[/red]")
            continue
    
    if not bound:
        console.print("[red]Warning: Could not bind socket properly[/red]")
    
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
                    console.print(f"\n[cyan]<{sender}>[/cyan] [white]{message}[/white] [dim]({addr[0]})[/dim]\n> ", end="")
            elif username not in msg:
                console.print(f"\n[cyan][UDP][/cyan] {msg} [dim]({addr[0]})[/dim]\n> ", end="")
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
            broadcast_addr = get_broadcast_address()
            console.print(f"[green][Group-UDP][/green] Broadcast on port {PORT}")
            console.print(f"[yellow]Broadcast address: {broadcast_addr}[/yellow]")
            threading.Thread(target=udp_listener, args=(udp_sock, username,), daemon=True).start()

    console.print("[yellow]Commands:[/yellow] /exit, /peers (UDP only)")
    console.print(f"[green]You are now chatting as: {username}[/green]")

    while True:
        try:
            msg = input("> ").strip()
            if msg == "/exit":
                break
            if msg == "/peers" and udp_sock:
                console.print("[cyan]Sending peer discovery...[/cyan]")
                udp_sock.sendto(f"[SYSTEM] Peer discovery from {username}".encode(), (broadcast_addr, PORT))
                continue
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
                try:
                    # For your network (10.79.179.x), the broadcast should be 10.79.179.255
                    sent = False
                    
                    # Method 1: Use calculated/detected broadcast address
                    try:
                        console.print(f"[yellow]Sending to: {broadcast_addr}[/yellow]")
                        udp_sock.sendto(full_msg.encode(), (broadcast_addr, PORT))
                        sent = True
                        console.print(f"[green]Message sent successfully to {broadcast_addr}[/green]")
                    except Exception as e1:
                        console.print(f"[red]Broadcast method 1 failed ({broadcast_addr}): {e1}[/red]")
                    
                    # Method 2: Try subnet-specific broadcast if method 1 fails
                    if not sent and local_ip:
                        ip_parts = local_ip.split('.')
                        subnet_broadcast = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.255"
                        if subnet_broadcast != broadcast_addr:
                            try:
                                console.print(f"[yellow]Trying subnet broadcast: {subnet_broadcast}[/yellow]")
                                udp_sock.sendto(full_msg.encode(), (subnet_broadcast, PORT))
                                sent = True
                                console.print(f"[green]Message sent via subnet broadcast[/green]")
                            except Exception as e2:
                                console.print(f"[red]Subnet broadcast failed: {e2}[/red]")
                    
                    # Method 3: Try direct multicast to known good addresses
                    if not sent:
                        # Try sending to other devices we've seen messages from
                        console.print("[yellow]Trying alternative broadcast methods...[/yellow]")
                        
                        # Create a new socket for sending if the original has permission issues
                        try:
                            send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                            
                            # Don't bind for sending, just send
                            send_sock.sendto(full_msg.encode(), (broadcast_addr, PORT))
                            send_sock.close()
                            sent = True
                            console.print("[green]Message sent via new socket[/green]")
                        except Exception as e3:
                            console.print(f"[red]New socket method failed: {e3}[/red]")
                    
                    if not sent:
                        console.print("[red]All broadcast methods failed. Check network permissions.[/red]")
                        console.print("[yellow]Try running with different network permissions or check if other devices are on the same subnet[/yellow]")
                        
                except Exception as e:
                    console.print(f"[red]Critical error sending UDP message: {e}[/red]")
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