import argparse
from parser import parse_pcap
from filters import apply_filters
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

def print_packet_details(packet):
    """
    This function takes a packet (represented as a dictionary) and displays its details in a human-readable format, 
    including Ethernet, IP, and transport layer information (TCP/UDP/ICMP). The packet's number, timestamp, 
    MAC addresses, protocol details, and other header information are printed for easy inspection.

    Parameters:
    -----------
    packet : dict
        A dictionary containing the parsed details of a network packet, including the following keys:
        
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
        - "protocol" (str): The protocol used at the transport layer (e.g., "TCP", "UDP", "ICMP").
        - "header_checksum" (int or None): The checksum of the IP header, or None if not applicable.
        - "src_ip" (str or None): The source IP address (in IPv4 or IPv6 format), or None if not applicable.
        - "dst_ip" (str or None): The destination IP address (in IPv4 or IPv6 format), or None if not applicable.
        - "src_port" (int or None): The source port for TCP/UDP packets, or None if not applicable.
        - "dst_port" (int or None): The destination port for TCP/UDP packets, or None if not applicable.

    Example:
    --------
    >>> packet = {
            'packet_number': 1, 'timestamp': 1619190374.123456, 'packet_size': 84,
            'src_mac': '00:14:22:01:23:45', 'dst_mac': '00:14:22:67:89:ab', 'eth_type': 2048,
            'ip_version': 4, 'header_length': 20, 'tos': 0, 'total_length': 60, 'identification': 12345,
            'flags': 2, 'fragment_offset': 0, 'ttl': 64, 'protocol': 'TCP', 'header_checksum': 0x1234,
            'src_ip': '192.168.1.1', 'dst_ip': '192.168.1.2', 'src_port': 80, 'dst_port': 12345
        }
    >>> print_packet_details(packet)
    """
    print(f"\nPacket #{packet['packet_number']}")
    print("-" * 50)
    print(f"Timestamp: {packet['timestamp']}")
    
    # Ethernet Header
    print(f"Packet Size: {packet['packet_size']} bytes")
    print(f"Source MAC: {packet['src_mac']}")
    print(f"Destination MAC: {packet['dst_mac']}")
    print(f"Ethertype: {hex(packet['eth_type'])}")

    # IP Header
    if packet["src_ip"] and packet["dst_ip"]:
        print("\nIP Header:")
        print(f"Version: {packet['ip_version']}")
        print(f"Header Length: {packet['header_length']} bytes")
        print(f"Type of Service: {packet['tos']}")
        print(f"Total Length: {packet['total_length']} bytes")
        print(f"Identification: {packet['identification']}")
        print(f"Flags: {packet['flags']}")
        print(f"Fragment Offset: {packet['fragment_offset']}")
        print(f"Time to Live: {packet['ttl']}")
        print(f"Protocol: {packet['protocol']}")
        print(f"Header Checksum: {packet['header_checksum']}")
        print(f"Source IP: {packet['src_ip']}")
        print(f"Destination IP: {packet['dst_ip']}")

    # Transport Layer (TCP/UDP/ICMP)
    if packet['src_port'] and packet['dst_port']:
        print("\nEncapsulated Packet:")
        print(f"Source Port: {packet['src_port']}")
        print(f"Destination Port: {packet['dst_port']}")

    print("-" * 50)


def main():
    # command-line arguments
    parser = argparse.ArgumentParser(description="Packet Sniffer")
    parser.add_argument("-r", "--read", help="Read a .pcap file", required=True)
    parser.add_argument("-c", "--count", type=int, help="Limit number of packets analyzed", default=None)

    # Filters for host, port, and IP
    parser.add_argument("--host", help="Host IP to filter packets by", default=None)
    parser.add_argument("--port", help="Port number to filter packets by", default=None)
    parser.add_argument("--ip", help="IP address to filter packets by", default=None)

    # Protocol filters using --filter on the basis of TCP, UDP and icmp
    parser.add_argument("--filter", choices=["tcp", "udp", "icmp"], help="Filter packets by protocol", default=None)

    # Network filter
    parser.add_argument("--net", help="Filter network packets by network address", default=None)

    args = parser.parse_args()

    packets = parse_pcap(args.read)

    filtered_packets = packets

    # Host Filter
    if args.host:
        filtered_packets = apply_filters(filtered_packets, "host", args.host)
    
    # Port Filter
    if args.port:
        filtered_packets = apply_filters(filtered_packets, "port", args.port)
    
    # IP Filter
    if args.ip:
        filtered_packets = apply_filters(filtered_packets, "ip", args.ip)

    # Protocol Filter (TCP, UDP, ICMPv6)
    if args.filter:
        filtered_packets = apply_filters(filtered_packets, "protocol", args.filter)
    
    # Network Filter
    if args.net:
        filtered_packets = apply_filters(filtered_packets, "net", args.net)

    # Limit packets if specified (-c)
    if args.count:
        filtered_packets = filtered_packets[:args.count]

    # Print the filtered or all packets (no -c filter)
    if filtered_packets:
        for packet in filtered_packets:
            print_packet_details(packet)
    else:
        print("No packets found matching the filter criteria.")

if __name__ == "__main__":
    main()
