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
        #attempts to read the file as a standard .pcap
        pcap = dpkt.pcap.Reader(file)
    except:
        #if that fails, it rewinds the file and tries to read as .pcapng
        try:
            file.seek(0)
            pcap = dpkt.pcapng.Reader(file)
        except:
            #if both fail, print an error and return None
            print('Invalid file. Bad format?')
            return None, None

    known_ip = {}
    traffic = {}

    #iterates over every packet in the file
    for i, (timestamp, buf) in enumerate(pcap, start=1):
        try:
            #parse the packet's ethernet frame
            eth = dpkt.ethernet.Ethernet(buf)

            #check if the packet is IPv4
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                ip_len = ip.len
                protocol = ip.get_proto(ip.p).__name__

            #check if the packet is IPv6
            elif isinstance(eth.data, dpkt.ip6.IP6):
                ip = eth.data
                ip_len = eth.data.plen + 40
                protocol = ip.get_proto(ip.nxt).__name__

            #if it's not IP, skip this packet
            else:
                continue
        #if the packet is malformed, print the error and continue
        except Exception as e:
            print(f'Packet {i}: Bad packet: {e.__class__.__name__}: {e}')
            continue

        try:
            #attempts to convert the timestamp as-is
            ts = datetime.datetime.fromtimestamp(timestamp, timezone.get_current_timezone())
        except Exception as e:
            print(f'Packet {i}: Bad timestamp: {e.__class__.__name__}: {e}, attempting conversion')
            try:
                #assume timestamp is in milliseconds and convert to seconds
                timestamp = timestamp/1000
                ts = datetime.datetime.fromtimestamp(timestamp, timezone.get_current_timezone())
                print(f'Packet {i}: conversion successful')
            except:
                #if conversion still fails, skip the packet
                print(f'Packet {i}: Timestamp conversion failed')
                continue

        #if the ip hasnt been seen before or its timestamp is newer, add it to the known_ip dictionary
        if inet_to_str(ip.src) not in known_ip or known_ip[inet_to_str(ip.src)][1] < ts:
            #the value is a tuple: (mac_address, last_seen_timestamp)
            addition = {inet_to_str(ip.src): (mac_addr(eth.src), ts)}
            known_ip.update(addition)

        if (inet_to_str(ip.src), inet_to_str(ip.dst)) not in traffic:
            #unique pair is the key, values are length of the packet, total number of packets, and the protocol
            new_traffic = {(inet_to_str(ip.src), inet_to_str(ip.dst)): [ip_len, 1, [protocol]]}
            traffic.update(new_traffic)

        else:
            #if the pair exists, increment its data
            traffic[(inet_to_str(ip.src), inet_to_str(ip.dst))][0] += ip_len
            traffic[(inet_to_str(ip.src), inet_to_str(ip.dst))][1] += 1
            if protocol not in traffic[(inet_to_str(ip.src), inet_to_str(ip.dst))][2]:
                traffic[(inet_to_str(ip.src), inet_to_str(ip.dst))][2].append(protocol)

    traffic_data = {}
    for pairs in traffic:
        try:
            #find the reverse pair (B->A) to get 'data_in'
            traffic_data[pairs] = (traffic[pairs][0], traffic[pairs[::-1]][0], traffic[pairs][1] + traffic[pairs[::-1]][1], traffic[pairs][2])

        except:
            #if there is no reverse, set 'data_in' to 0 and only use the packet count from the forward direction
            traffic_data[pairs] = (traffic[pairs][0], 0, traffic[pairs][1], traffic[pairs][2])

    return known_ip, traffic_data
