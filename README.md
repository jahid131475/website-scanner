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
