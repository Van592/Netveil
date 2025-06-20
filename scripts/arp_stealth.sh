#!/bin/bash
echo "[*] Running stealth ARP scan..."
arp-scan --localnet -I wlan0
