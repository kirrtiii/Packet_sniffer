import socket

def format_mac(address):
    """
    Convert a MAC address to a readable format.

    This function takes a MAC address as a byte sequence and returns a string 
    representation of the address in the standard "xx:xx:xx:xx:xx:xx" format, 
    where "xx" represents a two-digit hexadecimal value for each byte.

    Parameters:
    -----------
    address : bytes
        The MAC address as a sequence of 6 bytes.

    Returns:
    --------
    str
        The MAC address as a formatted string, e.g., "00:1a:2b:3c:4d:5e".

    Example:
    --------
    >>> format_mac(b'\x00\x1a\x2b\x3c\x4d\x5e')
    '00:1a:2b:3c:4d:5e'
    """
    return ':'.join('%02x' % b for b in address)

def format_ip(address):
    """
    Convert an IP address to a readable format.

    This function takes an IP address as a byte sequence (in IPv4 format) and 
    returns a string representation of the address in the standard "xxx.xxx.xxx.xxx" format.

    Parameters:
    -----------
    address : bytes
        The IP address as a sequence of 4 bytes.

    Returns:
    --------
    str
        The IP address as a formatted string, e.g., "192.168.1.1".

    Example:
    --------
    >>> format_ip(b'\xc0\xa8\x01\x01')
    '192.168.1.1'
    """
    return socket.inet_ntoa(address)
