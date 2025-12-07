import subprocess
import sys
import re
import os
import logging
import shutil
import socket
import json
import threading
import time
from datetime import datetime

# ==========================================
#    sudo nft add table arp filter
#    sudo nft 'add chain arp filter input { type filter hook input priority 0; }'
#    sudo nft 'add chain arp filter output { type filter hook output priority 0; }'
#    sudo nft add rule arp filter input log group 1
#    sudo nft add rule arp filter output log group 1
#    sudo iptables -I FORWARD 1 -j NFLOG --nflog-group 1
#    sudo iptables -I OUTPUT 1 -j NFLOG --nflog-group 1
#    sudo iptables -I INPUT 1 -j NFLOG --nflog-group 1
# ==========================================

logging.basicConfig(format='%(message)s', level=logging.INFO)

DEBUG_MODE = False
#defaulting to off as tshark saves packets in pcapng in /tmp; it fills up over long periods of time
USE_TSHARK = False

UDP_IP = "127.0.0.1"
UDP_PORT = 9999
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#this is a list that holds packets to be sent in a batch to avoid locking up the db
packet_buffer = []
#using a thread lock prevents multiple threads from trying to access the buffer at the same time
buffer_lock = threading.Lock()
#tracks when the last time the buffer was flushed so that it can be flushed if it sits too long
last_flush_time = time.time()

#the number of packets to hold before sending
BATCH_SIZE = 300
#the time in seconds to wait before flushing the buffer if it hasn't reached the batch size
FLUSH_INTERVAL = 2.0

#sends any packets currently in the buffer
def flush_buffer():
    global packet_buffer, last_flush_time

    #locking the buffer prevents other threads from modifying it while we are reading/clearing it
    with buffer_lock:
        if not packet_buffer:
            return
        try:
            message = json.dumps(packet_buffer)
            sock.sendto(message.encode('utf-8'), (UDP_IP, UDP_PORT))
            if DEBUG_MODE:
                logging.info(f"Flushed {len(packet_buffer)} packets.")
        except Exception as e:
            logging.error(f"Flush Error: {e}")

        #clearing the buffer and resetting the timer
        packet_buffer = []
        last_flush_time = time.time()

#a background thread that checks if the buffer has been sitting too long
def auto_flush_worker():
    global packet_buffer, last_flush_time

    while True:
        #checking every half second is frequent enough without being resource intensive
        time.sleep(0.5)

        #checking the time without locking first is faster
        if time.time() - last_flush_time > FLUSH_INTERVAL:
            #lock to check and flush
            with buffer_lock:
                if packet_buffer and (time.time() - last_flush_time > FLUSH_INTERVAL):
                    try:
                        message = json.dumps(packet_buffer)
                        sock.sendto(message.encode('utf-8'), (UDP_IP, UDP_PORT))
                        if DEBUG_MODE:
                            logging.info(f"Auto-flushed {len(packet_buffer)} packets.")
                    except Exception as e:
                        logging.error(f"Auto-Flush Error: {e}")

                    packet_buffer = []
                    last_flush_time = time.time()

#adds a packet to the buffer and sends it if the batch size is reached
def send_packet_data(data_dict):
    global packet_buffer, last_flush_time
    try:
        if 'timestamp' not in data_dict:
            data_dict['timestamp'] = datetime.now().isoformat()

        with buffer_lock:
            packet_buffer.append(data_dict)

            if len(packet_buffer) >= BATCH_SIZE:
                message = json.dumps(packet_buffer)
                sock.sendto(message.encode('utf-8'), (UDP_IP, UDP_PORT))
                packet_buffer = []
                last_flush_time = time.time()

    except OSError as e:
        if DEBUG_MODE:
            logging.error(f"UDP Batch Error: {e}")
        with buffer_lock:
            packet_buffer = []
    except Exception as e:
        if DEBUG_MODE:
            logging.error(f"General Send Error: {e}")
        with buffer_lock:
            packet_buffer = []

#parses a line of output from the capture tool
def parse_packet_line(line):
    try:
        line = line.strip()
        if not line:
            return

        if DEBUG_MODE:
            logging.info(f"[DEBUG RAW] {line}")

        line_lower = line.lower()

        if "error" in line_lower or "permission denied" in line_lower or "command not found" in line_lower:
            logging.error(f"[!] TOOL ERROR: {line}")
            return
        if "capturing on" in line_lower or "running as user" in line_lower:
            return

        #parsing arp packets
        if "arp" in line_lower or "who-has" in line_lower or "is-at" in line_lower:
            length = 0
            if "arp" in line_lower:
                match = re.search(r'arp\s+(\d+)?\s*(.*)', line, re.IGNORECASE)
                if match:
                    length_str = match.group(1)
                    length = int(length_str) if length_str else 0
                    info = match.group(2).strip()
                else:
                    info = line
            else:
                info = line

            data = {
                "protocol": "ARP",
                "src_ip": "",
                "dst_ip": "",
                "length": length,
                "description": info
            }
            send_packet_data(data)
            return

        #skipping raw headers that sometimes appear in tcpdump output
        if "family unknown (3)" in line_lower:
            return

        #parsing tshark output if enabled
        match_tshark = re.search(r'([a-fA-F0-9:.]+)\s+(?:→|->)\s+([a-fA-F0-9:.]+)\s+([A-Za-z0-9v.]+)\s+(\d+)', line)
        if match_tshark and USE_TSHARK:
            src_ip = match_tshark.group(1)
            dst_ip = match_tshark.group(2)
            proto = match_tshark.group(3)
            length = int(match_tshark.group(4))

            if proto == "UDP" and "quic" in line_lower:
                proto = "QUIC"

            ports = re.search(r'\s+(\d+)\s+(?:→|->)\s+(\d+)', line)
            src_port = ports.group(1) if ports else "0"
            dst_port = ports.group(2) if ports else "0"

            #preventing a feedback loop by ignoring traffic on the udp port we are using
            if str(UDP_PORT) == src_port or str(UDP_PORT) == dst_port:
                return

            data = {
                "protocol": proto,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "length": length
            }
            send_packet_data(data)
            return

        #parsing tcpdump output
        match_ip4 = re.search(
            r'IP\s+(\d{1,3}(?:\.\d{1,3}){3})(?:\.(\d+))?\s+>\s+(\d{1,3}(?:\.\d{1,3}){3})(?:\.(\d+))?:', line)
        if match_ip4:
            src_ip = match_ip4.group(1)
            #defaulting to 0 if no port is found, like with icmp
            src_port = match_ip4.group(2) or "0"
            dst_ip = match_ip4.group(3)
            dst_port = match_ip4.group(4) or "0"

            if str(UDP_PORT) == src_port or str(UDP_PORT) == dst_port:
                return

            if "ICMP" in line:
                proto = "ICMP"
            elif "Flags" in line or "seq" in line:
                proto = "TCP"
            elif "UDP" in line:
                proto = "UDP"
            else:
                proto = "IP"

            if proto == "UDP" and "quic" in line_lower:
                proto = "QUIC"

            len_match = re.search(r'length\s+(\d+)', line)
            length = int(len_match.group(1)) if len_match else 0

            data = {
                "protocol": proto,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "length": length
            }
            send_packet_data(data)
            return

        logging.info(f"[UNKNOWN LINE] {line}")

    except Exception as e:
        logging.error(f"Error parsing line: {e}")


def main():
    #the nflog group id must match what was set in iptables
    group_num = 1

    if os.geteuid() != 0:
        print("Error: Must run as root (sudo).")
        sys.exit(1)

    capture_tool = 'tshark' if USE_TSHARK else 'tcpdump'

    if not shutil.which(capture_tool):
        print(f"Error: '{capture_tool}' not found.")
        sys.exit(1)

    print(f"[*] Monitoring NFLOG group {group_num} using {capture_tool}...")
    print(f"[*] Broadcasting JSON batches (Size {BATCH_SIZE}) to UDP {UDP_IP}:{UDP_PORT}")
    print(f"[*] Ignoring internal loopback on port {UDP_PORT}")
    print(f"[*] Auto-flush interval: {FLUSH_INTERVAL}s")

    #starting the background thread to handle flushing during low traffic
    flush_thread = threading.Thread(target=auto_flush_worker, daemon=True)
    flush_thread.start()

    #building the command line arguments for the capture tool
    if USE_TSHARK:
        cmd = ['tshark', '-i', f'nflog:{group_num}', '-n', '-l']
    else:
        cmd = ['tcpdump', '-i', f'nflog:{group_num}', '-n', '-l']

    process = None
    try:
        #starting the subprocess and piping its output so we can read it
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        #reading the output line by line
        for line in process.stdout:
            parse_packet_line(line)

    except KeyboardInterrupt:
        print("\n[*] Exiting...")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        #ensuring any remaining data is sent before exiting
        flush_buffer()
        if process:
            if process.poll() is None:
                process.terminate()

            rc = process.wait()
            if rc != 0:
                print(f"\n[!] Tool exited prematurely with Code {rc}.")
            else:
                print(f"\n[*] Tool exited cleanly (Code 0).")

if __name__ == "__main__":
    main()