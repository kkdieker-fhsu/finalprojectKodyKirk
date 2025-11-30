import subprocess
import sys
import re
import os
import logging
import shutil
import socket
import json
from datetime import datetime

# ==========================================
#    sudo nft add table arp filter

#    sudo nft 'add chain arp filter input { type filter hook input priority 0; }'
#    sudo nft 'add chain arp filter output { type filter hook output priority 0; }'

#    sudo nft add rule arp filter input log group 1
#    sudo nft add rule arp filter output log group 1
# ==========================================

logging.basicConfig(format='%(message)s', level=logging.INFO)

DEBUG_MODE = False
USE_TSHARK = True

UDP_IP = "127.0.0.1"
UDP_PORT = 9999
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def send_packet_data(data_dict):
    try:
        if 'timestamp' not in data_dict:
            data_dict['timestamp'] = datetime.now().isoformat()

        message = json.dumps(data_dict)
        sock.sendto(message.encode('utf-8'), (UDP_IP, UDP_PORT))
    except Exception as e:
        if DEBUG_MODE:
            logging.error(f"UDP Send Error: {e}")

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

        if "arp" in line_lower or "who-has" in line_lower or "is-at" in line_lower:
            if "arp" in line_lower:
                match = re.search(r'arp\s+(?:\d+\s+)?(.*)', line, re.IGNORECASE)
                info = match.group(1).strip() if match else line
            else:
                info = line

            data = {
                "protocol": "ARP",
                "src_ip": "",
                "dst_ip": "",
                "description": info
            }
            send_packet_data(data)
            logging.info(f"CAPTURED: [ARP] {info}")
            return

        if "family unknown (3)" in line_lower:
            logging.info(f"CAPTURED: [ARP] (Raw Header) Payload not decoded.")
            return

        match_tshark = re.search(r'([a-fA-F0-9:.]+)\s+(?:→|->)\s+([a-fA-F0-9:.]+)\s+([A-Za-z0-9v.]+)', line)
        if match_tshark and USE_TSHARK:
            src_ip = match_tshark.group(1)
            dst_ip = match_tshark.group(2)
            proto = match_tshark.group(3)

            if proto == "UDP" and "quic" in line_lower:
                proto = "QUIC"

            ports = re.search(r'\s+(\d+)\s+(?:→|->)\s+(\d+)', line)
            src_port = ports.group(1) if ports else "0"
            dst_port = ports.group(2) if ports else "0"

            if str(UDP_PORT) == src_port or str(UDP_PORT) == dst_port:
                return

            data = {
                "protocol": proto,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port
            }
            send_packet_data(data)
            logging.info(f"CAPTURED: [IP/{proto}] {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            return

        match_ip4 = re.search(r'IP\s+([\d\.]+)(?:\.(\d+))?\s+>\s+([\d\.]+)(?:\.(\d+))?:', line)
        if match_ip4:
            src_ip = match_ip4.group(1)
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

            data = {
                "protocol": proto,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port
            }
            send_packet_data(data)
            logging.info(f"CAPTURED: [IPv4/{proto}] {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            return

        logging.info(f"[UNKNOWN LINE] {line}")

    except Exception as e:
        logging.error(f"Error parsing line: {e}")


def main():
    group_num = 1

    if os.geteuid() != 0:
        print("Error: Must run as root (sudo).")
        sys.exit(1)

    capture_tool = 'tshark' if USE_TSHARK else 'tcpdump'

    if not shutil.which(capture_tool):
        print(f"Error: '{capture_tool}' not found.")
        sys.exit(1)

    print(f"[*] Monitoring NFLOG group {group_num} using {capture_tool}...")
    print(f"[*] Broadcasting JSON to UDP {UDP_IP}:{UDP_PORT}")
    print(f"[*] Ignoring internal loopback on port {UDP_PORT}")

    if USE_TSHARK:
        cmd = ['tshark', '-i', f'nflog:{group_num}', '-n', '-l']
    else:
        cmd = ['tcpdump', '-i', f'nflog:{group_num}', '-n', '-l']

    process = None
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        for line in process.stdout:
            parse_packet_line(line)

    except KeyboardInterrupt:
        print("\n[*] Exiting...")
    except Exception as e:
        print(f"Error: {e}")
    finally:
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
