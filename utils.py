import socket

def format_mac(address):
    """Convert a MAC address to a readable format."""
    return ':'.join('%02x' % b for b in address)

def format_ip(address):
    """Convert an IP address to a readable format."""
    return socket.inet_ntoa(address)
