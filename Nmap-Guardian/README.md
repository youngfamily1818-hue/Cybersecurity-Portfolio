# Nmap Guardian

## Authorized Network Security Scanner

Nmap Guardian is a Python-based cybersecurity tool designed
for authorized network discovery, port scanning, service
identification, and security exposure assessments.

## Features

- Network host discovery
- TCP port scanning
- Service and version identification
- Security exposure classification
- Scan history
- Graphical user interface
- Windows network security auditing

## Technologies

- Python
- Nmap
- Windows PowerShell
- TCP/IP Networking
- Windows Defender Firewall

## Security Testing

During local network testing, Nmap Guardian identified
the following listening ports:

| Port | Service | Risk |
|------|---------|------|
| 135 | Microsoft RPC | Medium |
| 139 | NetBIOS | Medium |
| 445 | SMB | Medium |

These risk classifications indicate potential exposure,
not confirmed vulnerabilities.

## Security Hardening

Testing included:

- Reviewing Windows Firewall configurations
- Checking SMB protocol settings
- Verifying SMBv1 was disabled
- Investigating Windows RPC services
- Reviewing Remote Assistance settings
- Disabling Remote Assistance through Windows configuration
- Identifying listening network services

## Purpose

Developed as a hands-on cybersecurity portfolio project
demonstrating network reconnaissance, security assessment,
and Windows system hardening.

Only scan networks you own or have authorization to assess.

## Developer

Brandonn Young

B.S. Information Systems & Cybersecurity
Columbia Southern University
