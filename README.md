# packet-sniffer
Simple Python tool to capture and log network packets with IPs, ports, and protocols. trying to learn about packet sniffing and other similar concepts

A lightweight Python tool that captures and logs network packets on your machine. It shows IP addresses, ports, protocols, and TTL — useful for learning how network traffic works.


Important Notes: to keep you safe got this from chat gpt
The program generates a CSV log file (packetlog.csv) containing captured packet data, including IP addresses and ports.

Do NOT upload or share your CSV log file publicly — it may contain sensitive information about your network and devices.

This repository includes only the source code, which does NOT contain any private data.

To avoid accidentally committing log files, you can add packetlog.csv to your .gitignore.


Features
Supports TCP and UDP packet parsing

Logs packet info to a CSV file

Works on Windows with raw sockets

How to Use
Run the script with your IP address:

bash
python sniffer.py --ip 192.168.1.10

Sources & Inspiration
Python Socket Programming Tutorial: Low Level Networking 101: Python Network Sniffer by Hack the Clown
GeeksforGeeks
Stack Overflow 
ChatGPT (for coding help and explanations)
