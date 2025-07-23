# 🔥 NetNemesis CLI Tool  
*Secure Offline P2P & Group Chat with AES-EAX Encryption*
<img width="701" height="290" alt="image" src="https://github.com/user-attachments/assets/9c199ce0-9405-4eb5-9fe3-9b6ba8adca01" />
<img width="696" height="266" alt="image" src="https://github.com/user-attachments/assets/efd6f402-d73a-4faa-8c0a-b3f281473230" />

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-orange.svg?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20Termux-brightgreen.svg?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Stable-success.svg?style=for-the-badge)

---

## 📖 Overview  
**is** is a **secure, lightweight CLI tool** designed for **encrypted peer-to-peer (P2P) and group chat** in **offline or internet-restricted environments**. Leveraging **AES-EAX encryption**, it ensures privacy and security for communication over **LAN or mobile hotspot networks**. Ideal for:  
- **No-internet zones** (e.g., remote areas, disaster scenarios)  
- **Private, secure communication**  
- **LAN-based or hotspot-connected devices**

---

## 🔐 Core Features  
- **Peer-to-Peer Chat**: Secure 1-to-1 communication.  
- **Group Chat**: Multi-device encrypted messaging.  
- **AES-EAX Encryption**: Military-grade message security.  
- **IP Detection**: Automatic network discovery.  
- **Cross-Platform**: Runs on Windows, Linux, and Termux (Android).  
- **Offline Support**: No internet required—works on local networks.
- **Range**: Upto 30 meters.

---
## 🔐 Future Features 
- **Multi-Hop Mesh Networking**: Allow nodes to forward messages to others (true mesh).
- **Offline Mode Enhancements**: Build Wi-Fi Direct or Bluetooth support for offline zones.
- **File Sharing Support**: Send files/images/videos using the same AES-encrypted channel.
- **QR Code Handshake**: Generate QR codes for connection setup.
- **Steganography**: Encode encrypted data as DNA nucleotides (A, T, C, G).

---
## 📦 Requirements  
- **Python 3.8+**  
- Required Python packages: `rich`, `typer`, `pycryptodome`  

Install dependencies:  
```bash
pip install -r requirements.txt
```

---

## ⚙ Installation  
1. Clone the repository:  
   ```bash
   git clone https://github.com/wizardwithcodehazard/netnemesis.git
   cd netnemesis
   ```  
2. Install dependencies:  
   ```bash
   pip install -r requirements.txt
   ```

---

## 🚀 Usage  
Run the tool:  
```bash
python netnem4.py
```

### Available Modes  
- **ptp**: Peer-to-Peer secure chat  
- **group**: Multi-user secure chat  

#### Example: P2P Mode  
**Device A (Server/Host):**  
```bash
python netnem4.py
```
Choose:  
```
Mode: ptp
Role: s
```

**Device B (Client):**  
```bash
python netnem4.py
```
Choose:  
```
Mode: ptp
Role: c
Enter Server IP: 192.168.x.x
```

#### Example: Group Mode (TCP)  
**Host:**  
```bash
python netnem4.py
```
Choose:  
```
Mode: group
Group type: tcp
Role: h
```

**Joiners:**  
```bash
python netnem4.py
```
Choose:  
```
Mode: group
Group type: tcp
Role: j
Enter Host IP: 192.1xx.x.x
```

---

## 🌐 Offline Usage  
1. Create a **mobile hotspot** (no internet required).  
2. Connect all devices to the hotspot or LAN.  
3. Run **NetNemesis** and start chatting securely.

---

## 📱 Running on Termux (Android)  
1. Update Termux and install dependencies:  
   ```bash
   pkg update && pkg upgrade -y
   pkg install python git -y
   pip install rich typer pycryptodome
   ```  
2. Clone and run:  
   ```bash
   git clone https://github.com/wizardwithcodehazard/netnemesis.git
   cd netnemesis
   python netnem4.py
   ```

---

## 🛠 Troubleshooting  
- **Port Already in Use**:  
  Change the port in the code:  
  ```python
  PORT = 5556
  ```  

- **Firewall Blocking Connections**:  
  Allow Python through the firewall or run:  
  ```bash
  sudo ufw allow 5555/tcp
  ```  

- **No Devices Found**:  
  Ensure all devices are connected to the same hotspot or LAN.  

---

## 📜 License  
MIT License © 2025 NetNemesis

---

## ⭐ Support the Project  
If you find **NetNemesis** useful, give it a ⭐ on [GitHub](https://github.com/wizardwithcodehazard/netnemesis)!
