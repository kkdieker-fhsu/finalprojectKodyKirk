import dpkt
from dpkt.compat import compat_ord
import socket
import datetime
from datetime import timezone
from django.utils import timezone

### sample function from dpkt docs for converting information into readable strings
def mac_addr(address):
    """Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)

### sample function from dpkt docs for converting information into readable strings
def inet_to_str(inet):
    """Convert inet object to a string

        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

#parsing function to pull wanted data from pcap
def parse_pcap(file):
    try:
        pcap = dpkt.pcap.Reader(file)
    except:
        try:
            pcap = dpkt.pcapng.Reader(file)
        except:
            print('Invalid file. Bad format?')

    try:
        known_ip = {}
        traffic = {}
        for timestamp, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            ip = eth.data
            if inet_to_str(ip.src) not in known_ip or known_ip[inet_to_str(ip.src)][1] < datetime.datetime.fromtimestamp(timestamp, timezone.get_current_timezone()):
                addition = {inet_to_str(ip.src): (mac_addr(eth.src), datetime.datetime.fromtimestamp(timestamp, timezone.get_current_timezone()))}
                known_ip.update(addition)

            if (inet_to_str(ip.src), inet_to_str(ip.dst)) not in traffic:
                new_traffic = {(inet_to_str(ip.src), inet_to_str(ip.dst)): len(ip.data.data)}
                traffic.update(new_traffic)

            else:
                traffic[(inet_to_str(ip.src), inet_to_str(ip.dst))] += len(ip.data.data)

        traffic_data = {}
        for pairs in traffic:
            try:
                traffic_data[pairs] = (traffic[pairs], traffic[pairs[::-1]])

            except:
                traffic_data[pairs] = (traffic[pairs], 0)

        return known_ip, traffic_data

    except:
        return None, None