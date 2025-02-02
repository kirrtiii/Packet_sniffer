import dpkt
import socket
from utils import format_mac, format_ip

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

            # Extract Ethernet header details
            src_mac = format_mac(eth.src)
            dst_mac = format_mac(eth.dst)

            packet = {
                "packet_number": packet_number,
                "timestamp": timestamp,
                "packet_size": len(buf),
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "eth_type": eth_type,
                "ip_version": None,
                "header_length": None,
                "tos": None,
                "total_length": None,
                "identification": None,
                "flags": None,
                "fragment_offset": None,
                "ttl": None,
                "protocol": None,
                "header_checksum": None,
                "src_ip": None,
                "dst_ip": None,
                "src_port": None,
                "dst_port": None
            }

            # IPv4 Handling
            if eth_type == dpkt.ethernet.ETH_TYPE_IP:
                ip = eth.data
                packet.update({
                    "ip_version": ip.v,
                    "header_length": ip.hl * 4,
                    "tos": ip.tos,
                    "total_length": ip.len,
                    "identification": ip.id,
                    "flags": ip.df,
                    "fragment_offset": ip.offset,
                    "ttl": ip.ttl,
                    "protocol": PROTOCOL_NAMES.get(ip.p, f"Unknown ({ip.p})"),
                    "header_checksum": ip.sum,
                    "src_ip": format_ip(ip.src),
                    "dst_ip": format_ip(ip.dst),
                })

                # TCP/UDP Ports
                if isinstance(ip.data, dpkt.tcp.TCP):
                    packet.update({
                        "src_port": ip.data.sport,
                        "dst_port": ip.data.dport
                    })
                elif isinstance(ip.data, dpkt.udp.UDP):
                    packet.update({
                        "src_port": ip.data.sport,
                        "dst_port": ip.data.dport
                    })

            # IPv6 Handling
            elif eth_type == dpkt.ethernet.ETH_TYPE_IP6:
                ip6 = eth.data
                packet.update({
                    "ip_version": 6,
                    "total_length": len(ip6),
                    "ttl": ip6.hlim,
                    "protocol": PROTOCOL_NAMES.get(ip6.nxt, f"Unknown ({ip6.nxt})"),
                    "src_ip": socket.inet_ntop(socket.AF_INET6, ip6.src),
                    "dst_ip": socket.inet_ntop(socket.AF_INET6, ip6.dst),
                })

                # TCP/UDP Ports
                if isinstance(ip6.data, dpkt.tcp.TCP):
                    packet.update({
                        "src_port": ip6.data.sport,
                        "dst_port": ip6.data.dport
                    })
                elif isinstance(ip6.data, dpkt.udp.UDP):
                    packet.update({
                        "src_port": ip6.data.sport,
                        "dst_port": ip6.data.dport
                    })

            packets.append(packet)
            packet_number += 1

    return packets
