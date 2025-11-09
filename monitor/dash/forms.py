from django import forms
import dpkt
from dpkt.compat import compat_ord
import socket
import datetime
from datetime import timezone
from .models import Endpoints, TrafficLog
from django.utils import timezone


class registerendpoint(forms.ModelForm):
    class Meta:
        model = Endpoints
        fields = ['ip_address', 'mac_address', 'hostname']

class uploadpcap(forms.Form):
    title = forms.CharField(max_length=50)
    file = forms.FileField()

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
    pcap = dpkt.pcap.Reader(file)
    known_ip = {}
    for timestamp, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if not isinstance(eth.data, dpkt.ip.IP):
            #print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
            continue
        ip = eth.data
        if inet_to_str(ip.src) not in known_ip or known_ip[inet_to_str(ip.src)][1] < datetime.datetime.fromtimestamp(timestamp, timezone.get_current_timezone()):
            addition = {inet_to_str(ip.src): (mac_addr(eth.src), datetime.datetime.fromtimestamp(timestamp, timezone.get_current_timezone()))}
            known_ip.update(addition)
    print(known_ip)