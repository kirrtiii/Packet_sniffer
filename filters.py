from dpkt.utils import inet_to_str
import socket
import ipaddress

def apply_filters(packets, filter_type, value):
    """Apply filters to the list of packets based on the filter type and value."""
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
            return [pkt for pkt in packets if pkt['protocol'] == 'ICMP']
        else:
            # other protocols
            return [pkt for pkt in packets if pkt['protocol'] == value]
    elif filter_type == "net":
        # check if the IP is within a specific network range
        net = ipaddress.IPv4Network(value)
        return [pkt for pkt in packets if ipaddress.IPv4Address(pkt['src_ip']) in net or ipaddress.IPv4Address(pkt['dst_ip']) in net]
    else:
        return packets
