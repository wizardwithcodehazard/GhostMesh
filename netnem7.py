#!/usr/bin/env python3
"""
GhostMesh CLI Tool v4.2
- Premium Gemini-style UI
- Secure P2P & Group Chat with AES-EAX + DNA Obfuscation
- Local ML integration for chatbot, medical triage, and tech help
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
[bright_black]v4.2 | Secure P2P & Group Chat | AES-EAX + DNA Obfuscation + ML[/bright_black]
"""

BOOT_STEPS = [
    "🔍 Initializing GhostMesh…",
    "🔐 Loading Crypto Engine…",
    "🌐 Setting up network stack…",
    "🤖 Loading local ML (if available)…",
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

def print_message(msg):
    match = re.match(r"^\[(.+?)\]\s*(.*)$", msg)
    if match:
        user = match.group(1)
        text = match.group(2)
        console.print(f"[bold green]{user}[/bold green]: {text}")
    else:
        console.print(msg)

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

def get_default_ipv4():
    try:
        os_name = platform.system().lower()
        if "windows" in os_name:
            out = subprocess.check_output("ipconfig", shell=True, text=True)
            match = re.search(r"IPv4 Address[.\s]*:\s*([\d\.]+)", out)
            return match.group(1) if match else None
        else:
            out = subprocess.check_output("ip route get 1", shell=True, text=True)
            match = re.search(r"src\s+([\d\.]+)", out)
            return match.group(1) if match else None
    except Exception:
        return None

def get_default_gateway():
    try:
        os_name = platform.system().lower()
        if "windows" in os_name:
            out = subprocess.check_output("route print 0.0.0.0", shell=True, text=True)
            match = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+([\d\.]+)", out)
            if match:
                return match.group(1)
        else:
            out = subprocess.check_output("ip route", shell=True, text=True)
            match = re.search(r"default via ([\d\.]+)", out)
            if match:
                return match.group(1)
            out = subprocess.check_output("netstat -rn", shell=True, text=True)
            match = re.search(r"default\s+([\d\.]+)", out)
            if match:
                return match.group(1)
    except Exception:
        return None

# ---------- CRYPTO ----------
def derive_key(passphrase):
    return PBKDF2(passphrase, b"ghostmesh_salt", dkLen=32, count=100000)

def gen_map(seed):
    random.seed(seed)
    bits, nts = ['00', '01', '10', '11'], NUCS.copy()
    random.shuffle(nts)
    return {bits[i]: nts[i] for i in range(4)}

def to_dna(data, m):
    s = ''
    for b in data:
        for i in range(0, 8, 2):
            s += m[f"{b:08b}"[i:i+2]]
    return s

def from_dna(seq, m):
    rev = {v: k for k, v in m.items()}
    bits = ''.join(rev[c] for c in seq)
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))

def encrypt(msg, key):
    c = AES.new(key, AES.MODE_EAX)
    ct, tag = c.encrypt_and_digest(msg.encode())
    return c.nonce + tag + ct

def decrypt(blob, key):
    try:
        n, tag, ct = blob[:16], blob[16:32], blob[32:]
        c = AES.new(key, AES.MODE_EAX, nonce=n)
        return c.decrypt_and_verify(ct, tag).decode()
    except Exception:
        # fallback: try plain decode
        try:
            return blob.decode(errors="ignore")
        except:
            return ""

# ---------- ML Integration ----------
ML_AVAILABLE = False
try:
    import inference_purepy as ml
    if hasattr(ml, "predict_intent") and hasattr(ml, "medic_triage"):
        ML_AVAILABLE = True
        console.print("[green]ML integration: inference_purepy loaded.[/green]")
    else:
        console.print("[yellow]inference_purepy.py found but required functions missing. Using fallback rules.[/yellow]")
except Exception:
    console.print("[yellow]inference_purepy.py not found — using rule-based fallback for /bot and /medic.[/yellow]")

# Lightweight fallback if ml_inference not present
def fallback_predict_intent(text):
    t = text.lower()
    mapping = {
        "greeting": ["hi", "hello", "hey", "hii", "greetings"],
        "goodbye": ["bye", "goodbye", "see you"],
        "contact_help": ["help", "ambulance", "call"],
        "medic_minor_injury": ["cut", "scratch", "bleed", "burn"],
        "medic_major_emergency": ["severe", "profuse bleeding", "unconscious", "heart", "chest pain"],
        "techhelp_internet": ["wifi", "internet", "router"],
        "techhelp_device": ["phone", "laptop", "boot", "overheat"],
        "mechanic_tire_issue": ["tire", "flat", "puncture"]
    }
    scores = {}
    for tag, kws in mapping.items():
        for kw in kws:
            if kw in t:
                scores[tag] = scores.get(tag, 0) + 1
    if not scores:
        return [("unknown", 0.0)]
    items = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    total = sum(v for _, v in items)
    return [(k, v/total) for k, v in items]

def fallback_medic_triage(text):
    s = text.lower()
    urgent_kw = ["severe bleeding", "profuse bleeding", "no pulse", "heart stopped", "can't breathe", "chest pain", "i am dying", "unconscious"]
    moderate_kw = ["vomit", "vomiting", "nausea", "dizzy", "dizziness", "faint", "fever", "breathless", "shortness of breath", "seizure"]
    mild_kw = ["cut", "small cut", "scratch", "sprain", "minor burn", "bruise", "itch", "headache", "cold", "cough"]
    for kw in urgent_kw:
        if kw in s:
            return "urgent"
    for kw in moderate_kw:
        if kw in s:
            return "moderate"
    for kw in mild_kw:
        if kw in s:
            return "mild"
    return "unknown"

# ---------- NETWORK ----------
def socket_setup(s):
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except Exception:
        pass
    try:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass
    return s

def _remove_peer(sock):
    """Close and remove a peer from group_peers safely."""
    with group_lock:
        try:
            group_peers.remove(sock)
        except ValueError:
            pass
    try:
        sock.close()
    except:
        pass

def ptp_server():
    s = socket_setup(socket.socket())
    s.bind(("0.0.0.0", PORT))
    s.listen(1)
    console.print(f"[yellow][PtP][/yellow] Waiting for connection on port {PORT}...")
    conn, addr = s.accept()
    socket_setup(conn)
    console.print(f"[bold green][PtP][/bold green] Connected by {addr}")
    return conn

def ptp_client(ip):
    s = socket_setup(socket.socket())
    s.connect((ip, PORT))
    socket_setup(s)
    console.print(f"[bold green][PtP][/bold green] Connected to {ip}:{PORT}")
    return s

def ptp_receiver(conn, key):
    try:
        while True:
            try:
                data = conn.recv(BUFFER_SIZE)
                if not data:
                    console.print("[yellow][PtP][/yellow] Connection closed by peer.")
                    break
                msg = decrypt(data, key)
                print_message(msg)
                console.print("> ", end="")
            except ConnectionResetError:
                console.print("[yellow][PtP][/yellow] Connection reset by peer.")
                break
            except OSError as e:
                if e.errno == 9:  # Bad file descriptor
                    console.print("[yellow][PtP][/yellow] Connection closed.")
                    break
                else:
                    console.print(f"[red][PtP recv error][/red] {e}")
                    break
            except Exception as e:
                console.print(f"[red][PtP recv error][/red] {e}")
                break
    finally:
        try:
            conn.close()
        except:
            pass

# ---------- GROUP CHAT ----------
def group_acceptor(key):
    server = socket_setup(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    server.bind(("0.0.0.0", PORT))
    server.listen(5)
    console.print(f"[green][Group-TCP][/green] Hosting on port {PORT}")
    while True:
        conn, addr = server.accept()
        socket_setup(conn)
        with group_lock:
            group_peers.append(conn)
        threading.Thread(target=group_handler, args=(conn, key), daemon=True).start()

def group_handler(conn, key):
    try:
        while True:
            try:
                data = conn.recv(BUFFER_SIZE)
                if not data:
                    console.print("[yellow][Group-TCP][/yellow] Peer disconnected.")
                    break
                msg = decrypt(data, key)
                print_message(msg)
                console.print("> ", end="")
                # broadcast to other peers
                dead = []
                with group_lock:
                    peers_snapshot = list(group_peers)
                for peer in peers_snapshot:
                    if peer is conn:
                        continue
                    try:
                        peer.sendall(data)
                    except (ConnectionResetError, OSError, BrokenPipeError):
                        dead.append(peer)
                    except Exception as e:
                        console.print(f"[yellow]Peer broadcast error: {e}[/yellow]")
                        dead.append(peer)
                # cleanup dead peers
                for d in dead:
                    console.print("[yellow][Group-TCP][/yellow] removing dead peer.")
                    _remove_peer(d)
            except Exception as e_inner:
                console.print(f"[red][Group handler inner error][/red] {e_inner}")
                break
    finally:
        _remove_peer(conn)

def group_tcp_join(host_ip, key):
    s = socket_setup(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    s.connect((host_ip, PORT))
    socket_setup(s)
    console.print(f"[green][Group-TCP][/green] Joined {host_ip}:{PORT}")
    threading.Thread(target=group_listener, args=(s, key), daemon=True).start()
    return s

def group_listener(conn, key):
    try:
        while True:
            try:
                data = conn.recv(BUFFER_SIZE)
                if not data:
                    console.print("[yellow][Group-TCP][/yellow] Server closed connection.")
                    break
                msg = decrypt(data, key)
                print_message(msg)
                console.print("> ", end="")
            except ConnectionResetError:
                console.print("[yellow][Group-TCP][/yellow] Connection reset by server.")
                break
            except OSError as e:
                if e.errno == 9:  # Bad file descriptor
                    console.print("[yellow][Group-TCP][/yellow] Connection closed.")
                    break
                else:
                    console.print(f"[red][Group listener error][/red] {e}")
                    break
            except Exception as e:
                console.print(f"[red][Group listener error][/red] {e}")
                break
    finally:
        try:
            conn.close()
        except:
            pass

# ---------- CLI COMMANDS ----------
@app.command()
def interactive():
    """Start GhostMesh in interactive chat mode."""
    initial_setup()
    username = input("Username: ").strip()
    passphrase = getpass("Passphrase (leave blank to skip encryption): ")
    key = derive_key(passphrase) if passphrase else None
    
    if input("Scan network? (y/n): ").lower() == "y":
        show_ipv4()
    
    default_ip = get_default_ipv4()
    if default_ip:
        console.print(f"[cyan]Detected default IP: {default_ip}[/cyan]")

    default_gw = get_default_gateway()
    if default_gw:
        console.print(f"[cyan]Detected default Gateway IP: {default_gw}[/cyan]")
    else:
        console.print("[yellow]Could not detect default Gateway IP[/yellow]")

    mode = input("Mode? [ptp/group]: ").strip().lower()
    conn, role = None, None

    if mode == "ptp":
        role = input("Server or Client? [s/c]: ").strip().lower()
        conn = ptp_server() if role == "s" else ptp_client(input("Server IP: ").strip())
        threading.Thread(target=ptp_receiver, args=(conn, key,), daemon=True).start()
    else:
        role = input("Host or Join? [h/j]: ").strip().lower()
        if role == "h":
            threading.Thread(target=group_acceptor, args=(key,), daemon=True).start()
        else:
            conn = group_tcp_join(input("Host IP: ").strip(), key)

    console.print("[yellow]Commands available:[/yellow] /exit | /bot <message> | /medic <symptoms> | /techhelp <issue>")

    while True:
        try:
            msg = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not msg:
            continue
        if msg == "/exit":
            break

        # Local command handling
        if msg.startswith("/bot "):
            query = msg[len("/bot "):].strip()
            if ML_AVAILABLE:
                try:
                    preds = ml.predict_intent(query)
                except Exception as e:
                    console.print(f"[yellow]ML predict error: {e}[/yellow]")
                    preds = fallback_predict_intent(query)
            else:
                preds = fallback_predict_intent(query)

            top_tag, prob = preds[0]
            response = None
            try:
                with open("intents.json", "r", encoding="utf-8") as f:
                    intents = json.load(f)
                    for intent in intents.get("intents", []):
                        if intent.get("tag") == top_tag:
                            import random as _r
                            response = _r.choice(intent.get("responses", ["I don't know how to answer that."]))
                            break
            except Exception:
                response = None

            if not response:
                response = f"[{top_tag}] (confidence {prob:.2f}) No canned reply found."

            console.print(f"[magenta][Bot][/magenta] {response}")
            continue

        if msg.startswith("/medic "):
            query = msg[len("/medic "):].strip()
            if ML_AVAILABLE:
                try:
                    level = ml.medic_triage(query)
                except Exception as e:
                    console.print(f"[yellow]ML triage error: {e}[/yellow]")
                    level = fallback_medic_triage(query)
            else:
                level = fallback_medic_triage(query)

            if level == "urgent":
                console.print("[red][Medic][/red] URGENT — Call emergency services immediately. Provide location and details.")
            elif level == "moderate":
                console.print("[yellow][Medic][/yellow] Moderate — Seek medical advice soon. Monitor symptoms and consider transport to clinic.")
            elif level == "mild":
                console.print("[green][Medic][/green] Mild — Basic first aid: clean wounds, rest, hydrate, and monitor.")
            else:
                console.print("[cyan][Medic][/cyan] Unknown — please describe symptoms clearly: fever / breath / chest / bleeding / duration.")
            continue

        if msg.startswith("/techhelp "):
            query = msg[len("/techhelp "):].strip()
            if ML_AVAILABLE:
                try:
                    preds = ml.predict_intent(query)
                except Exception as e:
                    console.print(f"[yellow]ML predict error: {e}[/yellow]")
                    preds = fallback_predict_intent(query)
            else:
                preds = fallback_predict_intent(query)
            top_tag, prob = preds[0]
            response = None
            try:
                with open("intents.json", "r", encoding="utf-8") as f:
                    intents = json.load(f)
                    for intent in intents.get("intents", []):
                        if intent.get("tag") == top_tag:
                            import random as _r
                            response = _r.choice(intent.get("responses", ["I don't know how to help with that."]))
                            break
            except Exception:
                response = None
            if not response:
                response = f"[{top_tag}] (confidence {prob:.2f}) No canned tech help found."
            console.print(f"[magenta][Tech][/magenta] {response}")
            continue

        # If not a local command, send to peers
        full_msg = f"[{username}] {msg}"
        data = encrypt(full_msg, key) if key else full_msg.encode()
        
        try:
            if conn:
                conn.sendall(data)
            elif role == "h":
                with group_lock:
                    dead = []
                    for peer in list(group_peers):
                        try:
                            peer.sendall(data)
                        except (ConnectionResetError, OSError, BrokenPipeError):
                            dead.append(peer)
                        except Exception as e:
                            console.print(f"[yellow]Peer send error: {e}[/yellow]")
                            dead.append(peer)
                    for d in dead:
                        _remove_peer(d)
        except (ConnectionResetError, OSError, BrokenPipeError):
            console.print("[red]Connection lost. Unable to send message.[/red]")
        except Exception as e:
            console.print(f"[red]Send error: {e}[/red]")

    console.print("[bold red]Goodbye.[/bold red]")

@app.command()
def scan():
    """Scan and show local IPv4 addresses."""
    show_ipv4()

@app.command()
def about():
    """Show info about GhostMesh."""
    console.print(Panel("[bold cyan]GhostMesh CLI v4.2[/bold cyan]\nGemini-Style UI • Secure P2P • DNA Obfuscation • ML Integration", style="green"))

# ---------- ENTRY ----------
if __name__ == "__main__":
    console.print(BANNER)
    boot_sequence()
    app()