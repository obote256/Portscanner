# Advanced Port Scanner

A simple, concurrent TCP port scanner written in Python 3.  
Designed for educational and authorized security-testing use only.

**Repository / Contact**
- GitHub: https://www.github.com/Obote256  
- YouTube: https://www.youtube.com/rootgearlab  
- LinkedIn: https://www.linkedin.com/in/obote-tonny

> ⚠️ Legal: Scanning systems you do not own or do not have explicit permission to test is illegal in many jurisdictions. Only scan hosts/networks you own or have written permission to audit.

---

## Features

- Accepts single IPs, CIDR ranges (e.g. `192.168.1.0/24`) and comma-separated targets.
- Port input supports:
  - Single port (e.g. `22`)
  - Comma-separated ports (e.g. `22,80,443`)
  - Ranges (e.g. `1-1024`)
  - Mixed tokens (e.g. `22,80,1000-2000`)
- Concurrent scanning using threads for speed.
- Optional banner grab (attempts to read service banner from open TCP port).
- Save results to a file.

---

## Requirements

- Python 3.8+ (Python 3 recommended)
- See `requirements.txt` for Python package dependencies.

---

## Installation

1. Clone or copy the scanner script to your machine (e.g. `scanner.py`).
2. Create and activate a virtual environment (recommended):

```bash
python3 -m venv venv
source venv/bin/activate   # macOS / Linux
venv\Scripts\activate      # Windows (PowerShell)
