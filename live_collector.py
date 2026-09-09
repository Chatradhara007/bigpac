import os
import sys
import time
import csv
from scapy.all import sniff, IP, UDP

# Windows console colors
import ctypes
kernel32 = ctypes.windll.kernel32
kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)

class Colors:
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

MAX_PACKETS = 15
DATA_FILE = 'data/live_training_data.csv'

# Ensure data directory exists
os.makedirs('data', exist_ok=True)

# Write CSV header if file doesn't exist
if not os.path.exists(DATA_FILE):
    with open(DATA_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        header = ['label']
        for i in range(MAX_PACKETS):
            header.extend([f'pkt_size_{i}', f'pkt_dir_{i}', f'pkt_iat_{i}'])
        writer.writerow(header)

flows = {}
captured_count = 0
TARGET_LABEL = ""

def get_flow_key(packet):
    if not packet.haslayer(IP) or not packet.haslayer(UDP):
        return None, None
        
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = packet[UDP].sport
    dst_port = packet[UDP].dport
    
    if src_port != 443 and dst_port != 443:
        return None, None
        
    if dst_port == 443:
        return (src_ip, src_port, dst_ip, dst_port), 1
    else:
        return (dst_ip, dst_port, src_ip, src_port), -1

def process_packet(packet):
    global captured_count
    flow_key, direction = get_flow_key(packet)
    
    if not flow_key:
        return
        
    if flow_key not in flows:
        flows[flow_key] = {
            'packets': [],
            'last_time': packet.time,
            'processed': False
        }
        
    flow = flows[flow_key]
    
    if flow['processed']:
        return
        
    current_time = packet.time
    iat = (current_time - flow['last_time']) * 1000 
    
    if len(flow['packets']) == 0:
        iat = 0.0
        
    flow['last_time'] = current_time
    size = len(packet[IP])
    
    flow['packets'].append({
        'size': size,
        'dir': direction,
        'iat': iat
    })
    
    if len(flow['packets']) == MAX_PACKETS:
        flow['processed'] = True
        save_flow(flow)
        captured_count += 1
        print(f"{Colors.GREEN}[+] Captured connection #{captured_count} for {TARGET_LABEL}{Colors.ENDC}")

def save_flow(flow):
    row = [TARGET_LABEL]
    for p in flow['packets']:
        row.extend([p['size'], p['dir'], p['iat']])
        
    with open(DATA_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(row)

def get_active_interface():
    from scapy.all import get_if_list
    print(f"{Colors.YELLOW}[*] Auto-detecting active network interface...{Colors.ENDC}")
    for i in get_if_list():
        try:
            # Sniff 1 packet. If it succeeds, this interface is active!
            if len(sniff(iface=i, count=1, timeout=0.5)) > 0:
                print(f"{Colors.GREEN}[+] Found active interface: {i}{Colors.ENDC}")
                return i
        except:
            pass
    return None

if __name__ == "__main__":
    print(f"{Colors.BOLD}--- Live Training Data Collector ---{Colors.ENDC}")
    print("This script will record your live network traffic to build a custom dataset.")
    print("Example apps: youtube, discord, spotify, facebook")
    
    TARGET_LABEL = input(f"{Colors.CYAN}Enter the app you are about to use: {Colors.ENDC}").strip().lower()
    
    if not TARGET_LABEL:
        print(f"{Colors.RED}App name cannot be empty.{Colors.ENDC}")
        sys.exit(1)
        
    active_iface = get_active_interface()
    
    print(f"\n{Colors.YELLOW}[*] Listening for traffic...{Colors.ENDC}")
    print(f"{Colors.YELLOW}[*] Go use {TARGET_LABEL} now! Press Ctrl+C when you are done collecting.{Colors.ENDC}\n")
    
    try:
        if active_iface:
            sniff(iface=active_iface, filter="udp port 443", prn=process_packet, store=False)
        else:
            print(f"{Colors.RED}[!] Could not auto-detect interface. Falling back to default.{Colors.ENDC}")
            sniff(filter="udp port 443", prn=process_packet, store=False)
    except KeyboardInterrupt:
        print(f"\n{Colors.GREEN}[*] Collection stopped. Total captured: {captured_count}{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.RED}[!] Sniffing failed: {e}{Colors.ENDC}")
