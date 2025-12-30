# 🛡️ Path2Root

**Path2Root** is an advanced penetration testing and Bug Bounty automation platform. Built with Rust for performance and driven by AI for tactical relevance, it enables mapping, analyzing, and exploiting attack vectors on complex infrastructures.

---

[English](README.md) • [Français](README_FR.md)

---

## 🚀 Key Features

- 🔍 **OSINT & Discovery**: Automatic reconnaissance via Shodan, VirusTotal, Censys, and more.
- 📡 **Intelligent Network Scanning**: Nmap integration with dynamic scan parameter adjustment.
- 🧠 **AI Brain**: Real-time vulnerability analysis via LLMs to identify the most critical exploitation paths.
- 🔗 **Pivoting & Tunnels**: Unique auto-pivoting capability to establish SSH tunnels and bounce through the network.
- 💰 **Bug Bounty Automation**: HackerOne report simulation and automatic bounty estimation.
- 🛡️ **Remediation Verification**: Built-in tool to confirm that applied patches are effective.

## 🛠️ Installation

### Prerequisites
- **Rust** (Cargo) 1.70+
- **Node.js** & **npm**
- **Nmap** (required for scanning)
- **SQLite**

### Backend
```bash
cd back
cargo build --release
```

### Frontend
```bash
cd front
npm install
npm run build
```

## 📖 Usage

Run the global startup script:
```bash
chmod +x start.sh
./start.sh
```

The web interface will be accessible at `http://localhost:5173`.

## 📜 License

Distributed under the MIT License. See `LICENSE.md` for more details.

---
*Note: This tool is intended for legal and ethical use only. Do not use Path2Root on infrastructures without prior authorization.*
