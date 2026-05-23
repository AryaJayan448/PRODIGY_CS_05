# PRODIGY_CS_05 - Network Packet Analyzer

![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat&logo=python)
![Internship](https://img.shields.io/badge/Prodigy%20InfoTech-Internship-purple?style=flat)
![Task](https://img.shields.io/badge/Task-05-orange?style=flat)
![Status](https://img.shields.io/badge/Status-Completed-brightgreen?style=flat)

## Disclaimer
This tool is built strictly for educational purposes
as part of the Prodigy InfoTech Cybersecurity Internship.
Only use on networks you own or have explicit permission
to monitor. Unauthorized packet sniffing is illegal.

## Task Overview
A network packet sniffer that captures and analyzes
live network traffic. Displays source and destination
IP addresses, protocols, port numbers, service names,
and payload data previews.

## Features
- Captures live network packets in real time
- Shows source and destination IP addresses
- Identifies TCP, UDP, and ICMP protocols
- Detects well known services like HTTP, HTTPS, DNS, SSH
- Shows payload data preview
- Saves all captured packets to a log file
- Option to view and clear the log file

## Tech Stack
- Language: Python 3.x
- Library: Scapy
- Concepts: Network protocols, Packet analysis, File I/O

## How to Run
pip install scapy
python packet_sniffer.py

Note: Must be run as Administrator on Windows.
Right-click Command Prompt and choose Run as Administrator.

## Sample Output
Packet number  : 1
Captured at    : 2026-05-20 22:34:00
Source IP      : 192.168.1.5
Destination IP : 142.250.180.46
Protocol       : TCP
Source port    : 52341
Dest port      : 443
Likely service : HTTPS - secure web browsing

## Author
Arya Jayan
GitHub: https://github.com/AryaJayan448

## Internship
Prodigy InfoTech - Cybersecurity Internship - May 2026
