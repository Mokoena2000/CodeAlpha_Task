# CodeAlpha_Task
Task for my code alpha cybersecurity  

🛡️ Python Network Packet Sniffer
This project is a simple yet powerful network packet sniffer built using Python and the scapy library. It captures live network traffic and extracts key information to help understand how data flows through a network and how protocols operate at a low level.
📌 Features
- Real-time packet sniffing from the default network interface
- Captures IP-layer packets and displays:
- Source IP address
- Destination IP address
- Protocol number
- Raw payload data (if available)
- Easy to extend with filters or support for other protocols (e.g., TCP, UDP)
🧠 How It Works
The script uses scapy's sniff() function to passively monitor all packets on the interface. Each packet is processed by a custom callback function that extracts and prints relevant data from the IP and Raw layers.
from scapy.all import sniff, IP


- packet_callback(packet): A function to process each packet
- Checks for an IP layer and optionally a Raw layer (payload)
- Prints key insights about the packet
🚀 Getting Started
Prerequisites
- Python 3.x
- scapy library installed (pip install scapy)
- Administrative privileges (may require running with sudo on Linux/Mac or as Administrator on Windows)
Run the Sniffer
python packet_sniffer.py


You'll start seeing live traffic details appear in your terminal. Press Ctrl + C to stop sniffing.
🔍 Example Output
Source: 192.168.1.10 -> Destination: 172.217.3.110 | Protocol: 6
Payload: b'GET / HTTP/1.1\r\nHost: google.com\r\n...'
--------------------------------------------------------------------------------


📚 Learn More
This project is ideal for exploring:
- IP addressing and protocols like TCP, UDP, ICMP
- How raw data is transmitted over the wire
- Network security and intrusion detection basics
