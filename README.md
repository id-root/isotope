<p align="center">
  <img src="https://img.shields.io/badge/Made%20with-Rust-black.svg" alt="Made with Rust">
  <img src="https://img.shields.io/badge/version-4.0.0-black.svg" alt="Version 4.0.0">
  <img src="https://img.shields.io/badge/Security-Post--Quantum-blueviolet" alt="Security Status">
  <img src="https://img.shields.io/badge/License-MIT-black.svg" alt="License: MIT">
</p>

# ISOTOPE 
<table>
  <tr>
    <td width="280" align="right">
      <img src="logo.png" width="280" alt="ISOTOPE Logo">
    </td>
    <td>

ISOTOPE is a metadata-resistant, post-quantum secure messaging system designed for **hostile network environments**. It routes all traffic exclusively through **Tor Onion Services** and secures it with a defense-in-depth hybrid cryptographic stack.

Unlike standard secure messengers, ISOTOPE is built for **operational security (OPSEC)**, offering plausible deniability, anti-forensics, encrypted file vaulting, and a TUI designed for rapid situational awareness.
   </td>
  </tr>
</table>

---

## ⚡ Quick Automated Setup (One Command)

ISOTOPE comes with automated setup scripts that configure Tor, system dependencies, the Rust toolchain, and compile the release binary automatically:

### 🐧 Linux & 🍎 macOS
```bash
chmod +x install.sh && ./install.sh
```

### 🪟 Windows (PowerShell as Administrator)
```powershell
Set-ExecutionPolicy Bypass -Scope Process
.\install.ps1
```

The installer will auto-generate convenient quick-start launchers:
* `./start-server.sh` — Launch a Hub (Server)
* `./start-client.sh` — Connect to a Hub with persistent identity
* `./start-ephemeral.sh` — Connect with zero-trace ephemeral identity
* `./check-tor.sh` — Verify Tor SOCKS5 network routing

---

## 🛡️ Security Architecture

### 1. Hybrid Post-Quantum Encryption
ISOTOPE uses a defense-in-depth "hybrid" model to protect against Store-Now-Decrypt-Later (SNDL) quantum attacks:
*   **Layer 1 (Classic):** `Noise_XX_25519_ChaChaPoly_BLAKE2b` (Authenticated Key Exchange).
*   **Layer 2 (Post-Quantum):** `Kyber-1024` Key Encapsulation Mechanism (NIST PQC Winner).
*   **Key Rotation:** Session keys rotate automatically every 100 messages or 5 minutes (Double Ratchet inspired).

### 2. Security Audit Status

| Feature | Status | Implementation Details |
|:---|:---:|:---|
| Noise_XX Handshake | ✅ Implemented | Full `snow` library integration |
| Kyber-1024 PQ KEM | ✅ Implemented | NIST PQC winner via `pqcrypto-kyber` |
| Dual-Slot Identity | ✅ Implemented | Argon2id key derivation with decoy profile |
| Cover Traffic (T1) | ✅ Implemented | Constant-rate dummy packets |
| Protocol Mimicry | ✅ Implemented | HTTP wrapper for DPI evasion |
| Encrypted Vault | ✅ Implemented | XChaCha20Poly1305 block filesystem (`isotope.vault`) |
| Hidden Volumes (A3) | ✅ Implemented | TrueCrypt-style plausible deniability |
| Dead Man's Switch (A2) | ✅ Implemented | Auto-wipe on inactivity with distress broadcast |
| Key Rotation (C2) | ✅ Implemented | Automatic rekey every 100 msgs / 5 min |
| Anomaly Detection (D1) | ✅ Implemented | Behavioral profiling for compromise detection |
| Ring Signatures (C3) | ✅ Implemented | Uniform closed-ring challenge hash verification |
| HSM Integration (Z2) | ⚠️ Trait Only | Software fallback provided; hardware integration planned |
| Multi-Hop Routing (T2) | ✅ Implemented | SOCKS5 proxy chaining |

### 3. Operational Security (OPSEC) & Anti-Forensics
*   **A2: Dead Man's Switch:** Automatic data wiping after **5 minutes of inactivity**. Triggers silent distress signal to all peers before destruction.
*   **A3: Hidden Volumes (TrueCrypt-style):**
    *   **REAL Password:** Unlocks standard operational profile & vault.
    *   **DURESS Password:** Unlocks decoy profile. Mathematically indistinguishable from the outside.
*   **T1: Cover Traffic:** Sends constant-rate dummy packets every 2-8 seconds to mask message timing.
*   **Secure Memory & Wipe:** All sensitive keys and buffers use `zeroize` on drop. The `Ctrl+X` or `/nuke` panic switch instantly shreds local identity files, active vaults, and downloaded buffers.

---

## 💻 Terminal User Interface (TUI)

ISOTOPE features a professional-grade Terminal User Interface (TUI) with a modular tabbed layout (`Ratatui`).

### **Navigation Controls**
| Key | Action |
|:---:|:---|
| `Tab` / `Shift+Tab` | Cycle Panel Focus (**Input** $\rightarrow$ **Chat** $\rightarrow$ **Operatives**) |
| `Alt+1` / `Alt+2` / `Alt+3` | Jump to Tab (`COMMS` / `VAULT` / `INTEL`) |
| `Alt+Right` / `Alt+Left` | Cycle Tabs |
| `?` | Toggle Help Overlay |
| `Esc` | Clear Search / Exit Modal / Safe Quit |
| `Ctrl+X` | **PANIC PROTOCOL** (Instant Data Shred) |

### **Workspaces**
1. **[COMMS] Tab**: Main workspace for direct/group chat, syntax-highlighted code snippets, and operative lists.
2. **[VAULT] Tab**: Encrypted block filesystem manager for secure local storage.
3. **[INTEL] Dashboard (HUD)**: Live telemetry showing cipher state (`KYBER-1024`), uptime, memory usage, and system alerts.

---

## 🛠️ Manual Installation & Build

### Prerequisites
1. **Tor Service** running on port 9050 (or SOCKS proxy):
   * Linux: `sudo apt install tor && sudo systemctl start tor`
   * macOS: `brew install tor && brew services start tor`
2. **Rust Toolchain**: [Install Rust](https://rustup.rs/)

### Build from Source
```bash
git clone https://github.com/rootagi/isotope.git
cd isotope
cargo build --release
```
Binary output: `./target/release/isotope`

---

## 🚀 Manual Usage Guide

### 1. Start Hub (Server)
```bash
./target/release/isotope server --port 7878 --identity server.id
```
* Share the printed **Onion Address** & **Fingerprint** with your team out-of-band.

### 2. Connect Client (Persistent Identity)
```bash
./target/release/isotope client \
  --username "Ghost" \
  --address "onion_address.onion:7878" \
  --peer-fingerprint "SERVER_FINGERPRINT" \
  --identity ghost.id
```

### 3. Connect Client (Zero-Trace Ephemeral Mode)
```bash
./target/release/isotope client \
  --username "Ghost" \
  --address "onion_address.onion:7878" \
  --peer-fingerprint "SERVER_FINGERPRINT" \
  --temp
```

---

## 📖 Command Reference

| Command | Description |
| :--- | :--- |
| `/msg <user> <txt>` | Direct Message (DM). |
| `/search <query>` | Search chat history (`n` / `N` to navigate matches). |
| `/ttl <user> <sec> <txt>` | **Self-Destructing Message**. |
| `/send <file>` | Secure file transfer (encrypted/padded). |
| `/get <id>` | Download offered file. |
| `/browse` | Open interactive file browser for uploads. |
| `/vault_put <file>` | Store file in **Encrypted Vault**. |
| `/vault_get <file>` | Extract file from **Encrypted Vault**. |
| `/vault_list` | List contents of **Encrypted Vault**. |
| `/nuke` | **PANIC PROTOCOL:** Broadcast distress signal & shred local data. |
| `Ctrl+X` | **PANIC PROTOCOL** (Instant hotkey). |
| `Ctrl+C` | Safe Quit. |

---

## 🤝 Contributing

This project is open-source under the MIT License. Contributions and pull requests are welcome!

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/AmazingFeature`).
3. Commit your changes (`git commit -m 'Add AmazingFeature'`).
4. Open a Pull Request.

*Experience cyber sovereignty.*
