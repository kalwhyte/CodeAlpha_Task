# 🛡️ CodeAlpha Network Packet Sniffer

A full-featured network packet sniffer built with **Python** and **Scapy**, designed for **CodeAlpha's Cybersecurity Internship**.

---

## 🔧 Features

- ✅ Real-time packet capture using Scapy
- ✅ Parses IP, TCP, UDP, and DNS packets
- ✅ Extracts payload data from DNS queries
- ✅ Logs output to `log.txt` (readable) and `log.json` (structured)
- ✅ Displays source/destination IPs, ports, protocols, and queries
- ✅ Filters by protocol via CLI (`--protocol TCP` or `UDP`)
- ✅ Summarizes total captured packets per protocol
- ✅ Uses threading to ensure non-blocking execution

---

## 🚀 How to Run

1. **Install dependencies:**

    pip install scapy

## Run the sniffer:

    sudo python capy.py
        or
    sudo scap/bin/python3 capy.py

## ➕ Optional: Filter by Protocol

# Only capture TCP packets
    sudo python capy.py --protocol TCP

# Only capture UDP packets
    sudo python capy.py --protocol UDP

## 📁 Output Files
    log.txt — Easy-to-read, timestamped packet summaries

    log.json — Structured packet details for data processing or analysis

## 🧠 What You’ll Learn
    🔍 How data flows through a network in real-time

    📡 The structure of TCP/IP, UDP, and DNS packets

    🛠️ How to dissect traffic with Scapy

    ⚔️ The basics of ethical monitoring in cybersecurity

## 📊 Example Output (log.json)

    [
    {
        "timestamp": "2025-08-04 06:48:08",
        "src_ip": "172.20.91.88",
        "dst_ip": "172.20.80.1",
        "protocol": "UDP",
        "src_port": 56912,
        "dst_port": 53,
        "dns_query": "telemetry.individual.githubcopilot.com."
    },
    {
        "timestamp": "2025-08-04 06:48:08",
        "src_ip": "172.20.80.1",
        "dst_ip": "172.20.91.88",
        "protocol": "UDP",
        "src_port": 53,
        "dst_port": 56912,
        "dns_query": "telemetry.individual.githubcopilot.com."
    },
    ]

## 🔒 **License & Credits**
    🔧 Built with 💻 by Whyte Emmanuel for CodeAlpha

    📚 Scapy Docs: https://scapy.readthedocs.io/

    “Know the traffic. Know the threats.”
    — Your friendly terminal ninja 🥷

## 👨‍💻 Author
    - Ejiofor Emmanuel Whyte
    - Cybersecurity Intern @ CodeAlpha
    - Email: superkalel55@gmail.com
