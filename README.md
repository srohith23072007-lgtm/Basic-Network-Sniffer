# Basic Network Sniffer

An educational, beginner-friendly network packet sniffer and protocol analyzer built with **Python 3**, **Scapy**, and **Flask**. This application captures network traffic on local interfaces you own or have explicit authorization to inspect, displays packet structures in real time, and helps students and developers understand computer networking concepts.

---

## 1. Project Overview

The **Basic Network Sniffer** provides both an interactive **Web Dashboard** and a standalone **CLI tool** for inspecting network traffic. It unpacks low-level packet data into structured representations, highlighting IP addresses, transport protocols (TCP, UDP, ICMP), port numbers, packet lengths, timestamps, and safe payload previews.

---

## 2. Problem Statement

For beginners learning cybersecurity and computer networking, theoretical textbook diagrams of the OSI model and TCP/IP stack often feel abstract. Tools like Wireshark can be overwhelming due to their vast feature sets. There is a need for a lightweight, transparent, and modular educational tool that clearly demonstrates:
- How raw network frames are captured and structured.
- How IP headers and transport layer ports work in practice.
- How to handle packet data safely without exposing sensitive information or crashing applications.

---

## 3. Objectives

- **Educational Clarity**: Demystify packet structure (Ethernet, IPv4/IPv6, ARP, TCP, UDP, ICMP).
- **Safe Handling**: Sanitize payload previews to prevent script execution (XSS) and truncate data to avoid storing sensitive payloads.
- **Cross-Interface Inspection**: Discover and select network interfaces (Wi-Fi, Ethernet, loopback, virtual adapters).
- **Real-Time Visualization**: Provide an interactive dark-themed dashboard with live statistics, search filtering, and packet dissection.
- **Export Capabilities**: Allow exporting captured session metadata to standard CSV files for offline analysis.

---

## 4. Key Features

- **Interface Discovery**: Automatically enumerates available network adapters with friendly names, descriptions, and IP addresses.
- **Protocol Identification**: Analyzes TCP, UDP, ICMP, ARP, and other IP protocols.
- **Transport Layer Dissection**: Displays source/destination ports, well-known service names (e.g., DNS, HTTP, HTTPS), TCP sequence/acknowledgment numbers, and TCP control flags (`SYN`, `ACK`, `FIN`, `RST`, `PSH`).
- **ICMP Parsing**: Identifies ICMP types and codes (Echo Request, Echo Reply, Destination Unreachable, etc.).
- **Safe Payload Preview**: Converts payload bytes into sanitized ASCII strings with non-printable characters masked as dots (`.`) and HTML tags escaped.
- **Interactive Web Dashboard**:
  - Live packet feed with auto-scroll lock.
  - Real-time protocol metrics (Total packets, TCP/UDP/ICMP distribution %, Data volume in KB/MB, Packet rate).
  - Search bar to filter by IP, port, protocol, or payload text.
  - Packet Inspector Modal showing header details and a hex dump.
- **CSV Export**: One-click export of captured packets saved directly to the `captures/` folder or downloaded through the browser.
- **Robust Error Handling**: Clear notices for missing Npcap drivers, non-administrative shell sessions, or invalid interfaces.
- **Automated Tests**: Unit test suite using synthetic Scapy packets that execute without requiring administrator privileges.

---

## 5. Technologies Used

- **Python 3.10+**: Core programming language.
- **Scapy**: Packet sniffing, dissection, and layer extraction.
- **Flask**: Lightweight REST API backend and static web server.
- **HTML5 & Vanilla CSS**: Modern, glassmorphism-inspired dark dashboard with zero heavyweight front-end build steps.
- **JavaScript (ES6+)**: Real-time polling, safe DOM rendering, and modal interaction.
- **Npcap (Windows)**: Kernel-level packet capture driver for Windows systems.

---

## 6. Folder Structure

```
Basic-Network-Sniffer/
├── captures/
│   └── backend/
│       ├── app.py              # Flask REST API & Web Server
│       ├── sniffer.py          # Background packet sniffer engine & CLI
│       ├── packet_analyzer.py  # Layer dissection, sanitization & CSV logic
│       └── requirements.txt    # Python package dependencies
├── frontend/
│   ├── index.html              # Modern dark-theme web dashboard
│   ├── style.css               # Responsive design, tokens & protocol badges
│   └── script.js               # Polling, table rendering & modal inspector
├── tests/
│   └── test_packet_analyzer.py # Automated unit tests using synthetic packets
├── captures/
│   └── .gitkeep                # Directory for saved CSV captures
├── sniffer.py                  # Root CLI launcher
├── .gitignore                  # Git ignore rules
└── README.md                   # Project documentation
```

---

## 7. Installation & Prerequisites (Windows & VS Code)

### Step 1: Install Python
1. Download Python 3.10 or higher from [python.org](https://www.python.org/downloads/).
2. During installation, make sure to check **"Add python.exe to PATH"**.

### Step 2: Install Npcap (Crucial for Windows Packet Sniffing)
Scapy on Windows requires the **Npcap** packet capture driver:
1. Download the Npcap installer from [npcap.com](https://npcap.com/#download).
2. Run the installer.
3. During setup, check the option: **"Install Npcap in WinPcap API-compatible Mode"**.
4. Complete the installation.

### Step 3: Install Visual Studio Code
1. Download and install [VS Code](https://code.visualstudio.com/).
2. Open VS Code and install the **Python** extension by Microsoft.

### Step 4: Open Project & Create Virtual Environment
Open **PowerShell as Administrator** (required for capturing network packets on Windows):

```powershell
# Navigate to the project folder
cd "c:\Users\srohi\OneDrive\Desktop\Basic-Network-Sniffer"

# Create virtual environment
python -m venv venv

# Activate virtual environment
venv\Scripts\Activate.ps1
```

> **Note on PowerShell Execution Policy**: If you encounter a script execution restriction, run:
> `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`

### Step 5: Install Dependencies
```powershell
python -m pip install --upgrade pip
python -m pip install -r captures/backend/requirements.txt
```

---

## 8. Execution Instructions

### Option A: Running the Web Dashboard (Recommended)

1. Ensure your terminal is running with **Administrator privileges** so Scapy can access the network adapter:
   ```powershell
   python captures/backend/app.py
   ```
2. Open your web browser and navigate to:
   ```
   http://127.0.0.1:5000
   ```
3. In the dashboard:
   - Select your active network adapter (e.g., **Wi-Fi** or **Ethernet** with your local IP address).
   - Choose a capture filter (e.g., **All Protocols**, **TCP**, **UDP**, or **ICMP**).
   - Click **Start Capture**.
   - Generate traffic (e.g., open a website in another tab or ping a server).
   - Click on any packet row to open the detailed **Packet Inspector**.
   - Click **Stop Capture** when finished, and click **Export CSV** to save your session.

---

### Option B: Running in Command-Line (CLI) Mode

You can also run the interactive command-line sniffer directly:

```powershell
python sniffer.py
```

The CLI will prompt you to select an interface index and an optional protocol filter, then stream packet summaries live in your terminal. Press `Ctrl + C` to stop and optionally export to CSV.

---

## 9. Running Automated Tests

The test suite runs against **synthetic Scapy packets** in memory. It verifies packet dissection, port extraction, ICMP parsing, non-IP frames, payload escaping, and CSV formatting without requiring live traffic or administrator rights:

```powershell
python -m unittest tests/test_packet_analyzer.py
```

Expected output:
```text
.........
----------------------------------------------------------------------
Ran 9 tests in 0.015s

OK
```

---

## 10. Sample Output

### Command-Line Output Sample
```text
===== BASIC NETWORK SNIFFER - CLI MODE =====
Available Network Interfaces:
  [0] Wi-Fi (192.168.29.223) - MediaTek Wi-Fi 6E MT7902 Wireless LAN Card
  [1] Ethernet (169.254.120.10) - Realtek PCIe GbE Family Controller

Select interface number [0]: 0
Filter protocol (all / tcp / udp / icmp) [all]: all

Starting packet capture... Press Ctrl+C to stop.
[22:30:12.104] TCP    192.168.29.223:54210 -> 142.250.190.46:443 (HTTPS) [ACK, PSH] Seq=145210 Ack=98412
[22:30:12.188] UDP    192.168.29.223:58102 -> 8.8.8.8:53 (DNS) Len=64
[22:30:12.450] ICMP   192.168.29.223:0     -> 1.1.1.1:0 (Echo Request) (type=8, code=0)
```

### Exported CSV Sample (`captures/capture_1791651835.csv`)
```csv
id,timestamp,protocol,src_ip,src_port,dst_ip,dst_port,length,info,payload_preview
1,22:30:12.104,TCP,192.168.29.223,54210,142.250.190.46,443,66,TCP 54210 -> 443 (HTTPS) [ACK, PSH] Seq=145210 Ack=98412,.....
2,22:30:12.188,UDP,192.168.29.223,58102,8.8.8.8,53,74,UDP 58102 -> 53 (DNS) Len=64,.#..example.com...
3,22:30:12.450,ICMP,192.168.29.223,,1.1.1.1,,84,ICMP Echo Request (type=8, code=0),abcdefghijklmnop
```

---

## 11. Dashboard Interface Preview

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│  📡 BASIC NETWORK SNIFFER                          ● Status: Capturing on Wi-Fi        │
├────────────────────────────────────────────────────────────────────────────────────────┤
│  Interface: [ Wi-Fi (192.168.29.223) ▼ ]  Filter: [ All Protocols ▼ ]                  │
│  [ ▶ Start Capture ]  [ ⏹ Stop Capture ]  [ 🗑 Clear ]  [ ⬇ Export CSV ]               │
├────────────────────────────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐  │
│  │ Total Pkts   │ │ TCP (Stream) │ │ UDP (Datagr) │ │ ICMP (Ctrl)  │ │ Data Volume  │  │
│  │ 1,482        │ │ 1,120 (76%)  │ │ 340 (23%)    │ │ 22 (1%)      │ │ 1.84 MB      │  │
│  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘  │
├────────────────────────────────────────────────────────────────────────────────────────┤
│  Search: [ Filter by IP, port, protocol... ]               [✓] Auto-scroll             │
│                                                                                        │
│  #   Time          Proto  Source                 Destination         Length  Summary   │
│  1   22:30:12.104  TCP    192.168.29.223:54210   142.250.190.46:443  66 B    SYN, ACK  │
│  2   22:30:12.188  UDP    192.168.29.223:58102   8.8.8.8:53          74 B    DNS Query │
│  3   22:30:12.450  ICMP   192.168.29.223         1.1.1.1             84 B    Echo Req  │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 12. Troubleshooting Common Issues

| Issue / Error | Cause | Solution |
| :--- | :--- | :--- |
| `PermissionError: [WinError 10013]` or socket permission error | Packet capture sockets require administrative privileges on Windows. | Open **PowerShell or VS Code as Administrator**, activate your virtual environment, and run the script again. |
| `WARNING: No libpcap provider available ! pcap won't be used` | Npcap is missing or was installed without WinPcap compatibility. | Download and install Npcap from [npcap.com](https://npcap.com/). Ensure **"WinPcap API-compatible Mode"** is checked during setup. |
| No packets appearing when capturing | Selected the wrong network adapter (e.g. inactive virtual loopback or Bluetooth). | In the interface dropdown, select the adapter that displays your active LAN IP address (typically `192.168.x.x` or `10.x.x.x`). |
| `Activate.ps1 cannot be loaded because running scripts is disabled` | PowerShell script execution policy is restricted by default on Windows. | Run `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser` in PowerShell. |

---

## 13. Limitations

- **Encrypted Payloads (TLS/HTTPS)**: The sniffer analyzes transport and network layer headers. Encrypted application payloads (e.g., HTTPS, SSH) remain encrypted by design and cannot be decrypted without endpoint session keys.
- **Wi-Fi Monitor Mode**: Standard Wi-Fi adapters on Windows capture packets addressed to or from your own machine. Capturing promiscuous 802.11 management frames from other devices requires dedicated wireless hardware supporting monitor mode.
- **High-Throughput Packet Drops**: For extremely heavy multi-gigabit workloads, pure Python packet processing may experience buffer drops compared to native C packet processors.

---

## 14. Ethical and Legal Usage Guidelines

> **IMPORTANT NOTICE:**
> Network packet sniffing intercepts communication traversing network interfaces. Capturing traffic on networks without explicit, documented authorization is illegal under computer misuse laws (such as the CFAA in the United States and equivalent computer misuse acts globally).
>
> - **Authorized Use Only**: This project is strictly intended for personal learning, educational labs, network debugging on your own devices, and authorized diagnostics.
> - **No Malicious Intent**: Do not use this software to harvest credentials, eavesdrop on unauthorized communications, or perform unauthorized reconnaissance.
> - **Respect Privacy**: When demonstrating packet capture in classroom or shared settings, only monitor traffic originating from your test machine or dedicated sandbox networks.
