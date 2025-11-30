import re
import ipaddress
import signal
import dpkt
from django.db import transaction
from django.db.models import F
from dpkt.compat import compat_ord
import socket
import datetime
from datetime import timezone
from django.utils import timezone
import time
import logging
import json
from .models import Endpoints, TrafficLog

logger = logging.getLogger(__name__)

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

        if inet_to_str(ip.dst) not in known_ip or known_ip[inet_to_str(ip.dst)][1] < ts:
            addition = {inet_to_str(ip.dst): (mac_addr(eth.dst), ts)}
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

class packet_receiver:
    def __init__(self, udp_ip="127.0.0.1", udp_port=9999, flush_interval=10, batch_size=2048):
        self.udp_ip = udp_ip
        self.udp_port = udp_port
        self.flush_interval = flush_interval
        self.batch_size = batch_size

        self.buffer = []
        self.last_flush = time.time()
        self.running = False

        self.arp_regex = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})\s+is\s+at\s+([0-9a-fA-F:]{11,20})", re.IGNORECASE)

    def start(self):
        signal.signal(signal.SIGTERM, self.handle_signal)
        signal.signal(signal.SIGINT, self.handle_signal)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self.udp_ip, self.udp_port))
        sock.settimeout(1)

        print(f'Receiver listening on {self.udp_ip}:{self.udp_port}')

        self.running = True

        try:
            while self.running:
                try:
                    data, addr = sock.recvfrom(65535)
                    self.process_packet(data)

                except socket.timeout:
                    pass

                except Exception as e:
                    logger.error(f'Receiver error: {e}')

                self.check_flush()

        except KeyboardInterrupt:
            print('Stopping receiver...')

        finally:
            self.flush_buffer()
            sock.close()

    def handle_signal(self, signum, frame):
        print('Stopping receiver...')
        self.running = False

    def process_packet(self, data):
        try:
            packet_json = data.decode('utf-8')
            packet_data = json.loads(packet_json)
            self.buffer.append(packet_data)
        except json.JSONDecodeError:
            logger.error('Failed to decode JSON')

    def flush_buffer(self):
        if not self.buffer:
            return

        count = len(self.buffer)
        print(f'Flushing {count} packets...')

        try:
            with transaction.atomic():
                self.process_arp()
                self.process_traffic()

            self.buffer = []
            self.last_flush = time.time()
            print('Update complete.')

        except Exception as e:
            logger.error(f'Update error: {e}')
            self.buffer=[]

    def check_flush(self):
        current_time = time.time()
        time_diff = current_time - self.last_flush

        if len(self.buffer) >= self.batch_size or (time_diff >= self.flush_interval and self.buffer):
            self.flush_buffer()

    def process_arp(self):
        for packet in self.buffer:
            if packet.get('protocol') == 'ARP':
                desc = packet.get('description', '')
                match = self.arp_regex.search(desc)
                if match:
                    ip_address = match.group(1)
                    mac_address = match.group(2)

                    Endpoints.objects.update_or_create(ip_address=ip_address,
                                                       defaults={'mac_address': mac_address,
                                                                 'last_seen': timezone.now()})

    def process_traffic(self):
        known_ips = set(Endpoints.objects.values_list('ip_address', flat=True))
        traffic_map = {}

        for packet in self.buffer:
            if packet.get('protocol') == 'ARP':
                continue

            ip_src = packet.get('src_ip')
            ip_dst = packet.get('dst_ip')
            length = packet.get('length', 0)

            if not ip_src or not ip_dst:
                continue

            for ip in [ip_src, ip_dst]:
                if ip not in known_ips:
                    try:
                        ip_object = ipaddress.ip_address(ip)
                        if ip_object.is_private or ip_object.is_loopback:
                            Endpoints.objects.get_or_create(ip_address=ip,
                                                            defaults={'mac_address': 'Unknown',
                                                                      'last_seen': timezone.now()})
                            known_ips.add(ip)
                    except ValueError:
                        continue

            if ip_src in known_ips:
                key = (ip_src, ip_dst)
                self.update_map(traffic_map, key, direction='out', protocol=packet.get('protocol'), length=length)

            if ip_dst in known_ips:
                key = (ip_dst, ip_src)
                self.update_map(traffic_map, key, direction='in', protocol=packet.get('protocol'), length=length)

        for (endpoint_ip, remote_ip), stats in traffic_map.items():
            endpoint = Endpoints.objects.get(ip_address=endpoint_ip)
            protocol_str = ", ".join(stats['protocol'])

            log, created = TrafficLog.objects.get_or_create(ip_src=endpoint,
                                                            ip_dst=remote_ip,
                                                            defaults={'data_in': stats['in'],
                                                                      'data_out': stats['out'],
                                                                      'total_packets': stats['packets'],
                                                                      'protocol': protocol_str})

            if not created:
                log.data_in = F('data_in') + stats['in']
                log.data_out = F('data_out') + stats['out']
                log.total_packets = F('total_packets') + stats['packets']

                current_protocols = log.protocol or ''
                current_protocols = set(p.strip() for p in current_protocols.split(',') if p.strip())
                current_protocols.update(stats['protocol'])
                log.protocol = ', '.join(current_protocols)

                log.save()

            endpoint.last_seen = timezone.now()
            endpoint.save()

    def update_map(self, map, key, direction, protocol, length):
        if key not in map:
            map[key] = {'in': 0, 'out': 0, 'packets': 0, 'protocol': set()}

        map[key]['packets'] += 1
        map[key]['protocol'].add(protocol)

        if direction == 'in':
            map[key]['in'] += length
        else:
            map[key]['out'] += length

def run_receiver():
    receiver = packet_receiver()
    receiver.start()