from dpkt.utils import inet_to_str
import socket
import ipaddress

def apply_filters(packets, filter_type, value):
    """
    Apply filters to the list of packets based on the filter type and value.

    Args:
        packets (list): List of packet dictionaries.
        filter_type (str): Type of filter ('host', 'port', 'ip', 'protocol', 'net').
        value (str): Filter value to apply.

    Returns:
        list: Filtered list of packets.
    """
    if filter_type == "host":
        return [pkt for pkt in packets if value in (pkt['src_ip'], pkt['dst_ip'])]
    elif filter_type == "port":
        return [pkt for pkt in packets if value in (str(pkt['src_port']), str(pkt['dst_port']))]
    elif filter_type == "ip":
        return [pkt for pkt in packets if value in (pkt['src_ip'], pkt['dst_ip'])]
    elif filter_type == "protocol":
        if value == "tcp":
            return [pkt for pkt in packets if pkt['protocol'] == 'TCP']
        elif value == "udp":
            return [pkt for pkt in packets if pkt['protocol'] == 'UDP']
        elif value == "icmp":
            return [pkt for pkt in packets if pkt['protocol'] in ('ICMP', 'ICMPv6')]
        else:
            # other protocols
            return [pkt for pkt in packets if pkt['protocol'] == value]
    elif filter_type == "net":
        try:
            net = ipaddress.ip_network(value, strict=False)
            return [
                pkt for pkt in packets 
                if pkt.get('src_ip') and pkt.get('dst_ip') and
                (ipaddress.ip_address(pkt['src_ip']) in net or ipaddress.ip_address(pkt['dst_ip']) in net)
            ]
        except ValueError as e:
            print(f"Invalid network address: {value} - {e}")
            return []




