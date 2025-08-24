README.md
# Wi-Fi Strength Tester (Python CLI)

A **cross-platform Wi-Fi password strength testing tool** for **ethical security auditing**.  
Works on **Linux** (prefers `nmcli`) and **Windows** (`pywifi`).

⚠️ **Ethical use only**:  
Use this tool **only on networks you own or have explicit permission to test**.  
Unauthorized access is illegal.

---

## Features
- Password **strength analysis** (entropy, character sets, common passwords).
- **Connection testing**:
  - Linux: uses `nmcli` (preferred) or falls back to `pywifi`.
  - Windows: uses `pywifi`.
- Works as a **command-line tool**.

---

## Installation

Clone the repository:
```bash
git clone https://github.com/acunetix/phantomwifi.git
cd wifi-strength-tester


Install dependencies:

pip install -r requirements.txt

🚀 Usage
Check password strength only
python wifi_strength_tester.py --ssid MyWiFi --password "MySecret" --no-connect

Check strength and attempt connection
python wifi_strength_tester.py --ssid MyWiFi --password "MySecret"

Prompt for password securely
python wifi_strength_tester.py --ssid MyWiFi

⚡ Requirements

Python 3.8+

Linux: nmcli (part of NetworkManager) OR pywifi

Windows: pywifi + Administrator rights

🛡️ Legal Disclaimer

This project is for educational and authorized security testing only.
The author is not responsible for misuse or illegal activities.

📄 License

MIT License


---

## ✅ `LICENSE` (MIT Example)

```txt
MIT License

Copyright (c) 2025 YOUR NAME

Permission is hereby granted, free of charge, to any person obtaining a copy...