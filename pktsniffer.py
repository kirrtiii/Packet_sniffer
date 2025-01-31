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
    print(f"Packet #{packet['packet_number']}")
    print("-" * 40)
    print(f"Timestamp: {packet['timestamp']}")
    print(f"Source MAC: {packet['src_mac']}")
    print(f"Destination MAC: {packet['dst_mac']}")
    print(f"Source IP: {packet['src_ip']}")
    print(f"Destination IP: {packet['dst_ip']}")
    print(f"Protocol: {packet['protocol']}")
    print(f"Source Port: {packet.get('src_port', 'N/A')}")
    print(f"Destination Port: {packet.get('dst_port', 'N/A')}")
    print("-" * 40)

def main():
    # Setup argparse for command-line arguments
    parser = argparse.ArgumentParser(description="Packet Sniffer")
    parser.add_argument("-r", "--read", help="Read a .pcap file", required=True)
    parser.add_argument("-c", "--count", type=int, help="Limit number of packets analyzed", default=None)

    # Filters for host, port, and IP
    parser.add_argument("--host", help="Host IP to filter packets by", default=None)
    parser.add_argument("--port", help="Port number to filter packets by", default=None)
    parser.add_argument("--ip", help="IP address to filter packets by", default=None)

    # Protocol filters using --filter
    parser.add_argument("--filter", choices=["tcp", "udp", "icmp"], help="Filter packets by protocol", default=None)

    # Network filter
    parser.add_argument("--net", help="Filter network packets by network address", default=None)

    args = parser.parse_args()

    # Parse the pcap file
    packets = parse_pcap(args.read)

    # Apply filters based on the arguments provided
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

    # Limit packets if specified
    if args.count:
        filtered_packets = filtered_packets[:args.count]

    # Print the filtered or all packets
    if filtered_packets:
        for packet in filtered_packets:
            print_packet_details(packet)
    else:
        print("No packets found matching the filter criteria.")

if __name__ == "__main__":
    main()
