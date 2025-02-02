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
    """Pretty print the details of a single packet."""
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
    # Setup argparse for command-line arguments
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

    # Protocol Filter (TCP, UDP, ICMP)
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
