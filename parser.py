import dpkt
import socket
from utils import format_mac, format_ip

# Protocol number to name mapping
PROTOCOL_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6 Encapsulation",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    132: "SCTP"
}

def parse_pcap(filename):
    packets = []
    with open(filename, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        packet_number = 1

        for timestamp, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            eth_type = eth.type

            # Extract MAC addresses
            src_mac = format_mac(eth.src)
            dst_mac = format_mac(eth.dst)

            # Initialize packet details
            packet = {
                "packet_number": packet_number,
                "timestamp": timestamp,
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "eth_type": eth_type,
                "src_ip": None,
                "dst_ip": None,
                "protocol": None,
                "src_port": None,
                "dst_port": None
            }

            # IPv4 Handling
            if eth_type == dpkt.ethernet.ETH_TYPE_IP:
                ip = eth.data
                packet["src_ip"] = format_ip(ip.src)
                packet["dst_ip"] = format_ip(ip.dst)
                packet["protocol"] = PROTOCOL_NAMES.get(ip.p, f"Unknown ({ip.p})")

                # TCP/UDP ports
                if isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data
                    packet["src_port"] = tcp.sport
                    packet["dst_port"] = tcp.dport
                elif isinstance(ip.data, dpkt.udp.UDP):
                    udp = ip.data
                    packet["src_port"] = udp.sport
                    packet["dst_port"] = udp.dport

            # IPv6 Handling
            elif eth_type == dpkt.ethernet.ETH_TYPE_IP6:
                ip6 = eth.data
                packet["src_ip"] = socket.inet_ntop(socket.AF_INET6, ip6.src)
                packet["dst_ip"] = socket.inet_ntop(socket.AF_INET6, ip6.dst)
                packet["protocol"] = PROTOCOL_NAMES.get(ip6.nxt, f"Unknown ({ip6.nxt})")

                # TCP/UDP ports
                if isinstance(ip6.data, dpkt.tcp.TCP):
                    tcp = ip6.data
                    packet["src_port"] = tcp.sport
                    packet["dst_port"] = tcp.dport
                elif isinstance(ip6.data, dpkt.udp.UDP):
                    udp = ip6.data
                    packet["src_port"] = udp.sport
                    packet["dst_port"] = udp.dport

            packets.append(packet)
            packet_number += 1

    return packets
