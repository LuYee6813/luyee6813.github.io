---
title: "Welcome to HTB Style Blog"
date: 2025-07-24
categories: [security-tools]
tags: [hack-the-box, demo, style]
ShowToc: true
TocOpen: true
---

# 🔐 Welcome to Hack The Box Style Blog

歡迎來到我的 **Hack The Box** 風格資安博客！這裡專注於：

## 💀 Penetration Testing

深入探討滲透測試技術和方法論：

- Network scanning 與 reconnaissance
- Web application security testing
- Binary exploitation 和 reverse engineering
- Privilege escalation techniques

### Network Reconnaissance

使用 `nmap` 進行目標偵察：

```bash
# HTB 風格的網路掃描
nmap -sC -sV -oA scan_results 10.10.10.xxx

# 深度 UDP 掃描
sudo nmap -sU --top-ports 1000 10.10.10.xxx
```

## 🏆 CTF Writeups

分享各種 CTF 挑戰的解法：

### Binary Exploitation

```python
# 典型的 buffer overflow exploit
import struct

def p32(val):
    return struct.pack('<I', val)

payload = b'A' * 140
payload += p32(0xdeadbeef)  # EIP override
payload += p32(0xcafebabe)  # Shell address

print(payload)
```

## 🛠️ Security Tools

介紹各種滲透測試工具：

| Tool       | Category         | Description          |
| ---------- | ---------------- | -------------------- |
| Burp Suite | Web Security     | 網頁應用程式測試平台 |
| Metasploit | Exploitation     | 漏洞利用框架         |
| Wireshark  | Network Analysis | 網路封包分析工具     |

## 🎯 Lab Environment

設置你的 HTB 實驗環境：

> **提示**: 使用 Kali Linux 或 Parrot OS 作為主要攻擊平台

### Essential Tools Setup

```bash
# 更新系統
sudo apt update && sudo apt upgrade -y

# 安裝必要工具
sudo apt install -y gobuster dirbuster sqlmap john hashcat

# 安裝 Docker 用於容器化測試
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
```

## 📚 Learning Resources

推薦的學習資源：

- [Hack The Box](https://www.hackthebox.eu/) - 實戰練習平台
- [TryHackMe](https://tryhackme.com/) - 入門友善的學習平台
- [OverTheWire](https://overthewire.org/) - Wargames 挑戰

---

_Happy Hacking! 🚀_
