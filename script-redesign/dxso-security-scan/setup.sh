#!/bin/bash
# DXSO MSME Assessment - Kali Linux Setup Wizard
# Ensure you run this with 'sudo ./setup.sh'

echo "[========= DXSO Framework Initial Setup =========]"
echo "[*] Updating repositories..."
apt-get update -y

echo "\n[*] Installing Phase 1 Tools (Network Discovery)..."
apt-get install -y nmap arp-scan netdiscover arping

echo "\n[*] Installing Phase 2 Tools (Endpoint Audit / PsExec)..."
apt-get install -y impacket-scripts python3-impacket

echo "\n[*] Installing Phase 3 Tools (Wireless Assessment)..."
apt-get install -y kismet aircrack-ng tshark john

echo "\n[*] Installing Phase 4 Tools (Traffic Analysis)..."
apt-get install -y zeek

echo "\n[*] Installing Python-based Tools (OSINT & Excel Matrices)..."
apt-get install -y urlcrazy dnsrecon theharvester
pip install openpyxl --break-system-packages 2>/dev/null || pip install openpyxl

echo "\n[*] Installing Phase 7 Tools (Vulnerability Assessment)..."
apt-get install -y whatweb nikto nuclei gvm metasploit-framework

echo "\n[========= Setup Complete =========]"
echo "You can now run 'python3 wrapper.py'!"
