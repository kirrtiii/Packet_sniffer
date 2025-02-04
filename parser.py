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
    """
    Parses a pcap (Packet Capture) file and extracts Ethernet, IPv4, and IPv6 header details 
    along with transport layer information (TCP/UDP). 

    The function reads packets from a given pcap file, processes each packet's Ethernet, 
    IP (IPv4 or IPv6), and transport layer (TCP/UDP) headers, and returns a list of dictionaries 
    with the parsed packet details.

    Parameters:
    -----------
    filename : str
        The name of the pcap file to be parsed. The file should be in binary format.

    Returns:
    --------
    List[dict]
        A list of dictionaries, where each dictionary contains the following key-value pairs for a single packet:
        
        - "packet_number" (int): The packet number in the pcap file.
        - "timestamp" (float): The timestamp of the packet.
        - "packet_size" (int): The size of the packet in bytes.
        - "src_mac" (str): The source MAC address in the format "xx:xx:xx:xx:xx:xx".
        - "dst_mac" (str): The destination MAC address in the format "xx:xx:xx:xx:xx:xx".
        - "eth_type" (int): The Ethernet type field (e.g., 0x0800 for IPv4, 0x86dd for IPv6).
        - "ip_version" (int or None): The IP version (4 for IPv4, 6 for IPv6), or None if not applicable.
        - "header_length" (int or None): The IP header length in bytes, or None if not applicable.
        - "tos" (int or None): The Type of Service field in the IPv4 header, or None if not applicable.
        - "total_length" (int or None): The total length of the IP packet, or None if not applicable.
        - "identification" (int or None): The IP identification field, or None if not applicable.
        - "flags" (int or None): The flags field in the IP header, or None if not applicable.
        - "fragment_offset" (int or None): The fragment offset field in the IP header, or None if not applicable.
        - "ttl" (int or None): The Time to Live (TTL) field in the IP header, or None if not applicable.
        - "protocol" (str): The protocol used at the transport layer (e.g., "TCP", "UDP", "ICMP"), or a descriptive string 
          for unknown protocols.
        - "header_checksum" (int or None): The checksum of the IP header, or None if not applicable.
        - "src_ip" (str or None): The source IP address (in IPv4 or IPv6 format), or None if not applicable.
        - "dst_ip" (str or None): The destination IP address (in IPv4 or IPv6 format), or None if not applicable.
        - "src_port" (int or None): The source port for TCP/UDP packets, or None if not applicable.
        - "dst_port" (int or None): The destination port for TCP/UDP packets, or None if not applicable.

    Notes:
    ------
    - For Ethernet frames, the function assumes that the packets are either IPv4 or IPv6 packets.
    - For IPv4 packets, both TCP and UDP transport layer protocols are supported.
    - For IPv6 packets, only the transport layer protocols that are commonly used (TCP/UDP) are considered.
    - The packet data for IPv4 and IPv6 is processed and the associated transport layer data is extracted when applicable.
    - If the packet is not an IPv4 or IPv6 packet, the relevant IP-specific fields (such as `ip_version`, `src_ip`, `dst_ip`, etc.) 
      will be set to `None`.

    Example:
    --------
    >>> parse_pcap("capture.pcap")
    [{'packet_number': 1, 'timestamp': 1619190374.123456, 'packet_size': 84, 'src_mac': '00:14:22:01:23:45', 
        'dst_mac': '00:14:22:67:89:ab', 'eth_type': 2048, 'ip_version': 4, 'header_length': 20, 
        'tos': 0, 'total_length': 60, 'identification': 12345, 'flags': 2, 'fragment_offset': 0, 
        'ttl': 64, 'protocol': 'TCP', 'header_checksum': 0x1234, 'src_ip': '192.168.1.1', 
        'dst_ip': '192.168.1.2', 'src_port': 80, 'dst_port': 12345}, 
    ... ]
    """
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
