# Packet Sniffer (`pktsniffer`)

## **Introduction**
`pktsniffer` is a network packet analyzer that reads packets from a `.pcap` file and produces a detailed summary of those packets, including Ethernet, IP, and encapsulated headers.

This tool is useful for analyzing network traffic and debugging packet-level communications.

## **Features**
- Parses packets from `.pcap` files.
- Extracts and displays Ethernet, IP, TCP, UDP, and ICMP headers.
- Supports filtering by:
  - Host IP
  - Port
  - Protocol (TCP, UDP, ICMP)
  - Network (CIDR notation)

## **Installation**
### **Prerequisites**
- Python 3.x
- Wireshark (to generate `.pcap` files)
- Install dependencies:
  ```sh
  pip install -r requirements.txt

## **How to Run**
- python pktsniffer.py -r <pcap_file>
Limit Number of Packets
- python pktsniffer.py -r example.pcap -c 10
Filter by Host IP
- python pktsniffer.py -r example.pcap --host 192.168.1.1
Filter by Port
- python pktsniffer.py -r example.pcap --port 80
Filter by Network
- python pktsniffer.py -r example.pcap --net 192.168.1.0/24
Filter by Protocol
- python pktsniffer.py -r example.pcap --filter tcp/udp/icmp



