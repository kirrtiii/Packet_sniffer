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
