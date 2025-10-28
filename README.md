# Website Security Scanner 🔍

A complete website security scanner tool written in C++.

## Features
- Port Scanning with Nmap
- Service Detection  
- Web Vulnerability Scanning
- Security Headers Check
- Comprehensive Reporting

## Installation

### Kali Linux
```bash
sudo apt update
sudo apt install nmap g++
g++ -o webscan webscan.cpp -pthread


Users can now use:

  # 1. Repository clone করুন
git clone https://github.com/jahid131475/website-scanner.git
cd website-scanner

# 2. ইন্সটল করুন
chmod +x install.sh
./install.sh

# 3. ব্যবহার করুন
./webscan example.com
