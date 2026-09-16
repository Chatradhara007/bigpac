import os
import sys
import time
import numpy as np
import joblib
from scapy.all import sniff, IP, UDP, TCP
import warnings
warnings.filterwarnings('ignore', category=UserWarning)

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

# Prefer the custom live-trained model if it exists
if os.path.exists('models/my_custom_model.joblib'):
    MODEL_PATH = 'models/my_custom_model.joblib'
    print(f"{Colors.YELLOW}[*] Found Custom Live Model! Using my_custom_model.joblib{Colors.ENDC}")
else:
    MODEL_PATH = 'models/rf_model_n15.joblib'
    print(f"{Colors.YELLOW}[*] Using default CESNET model: rf_model_n15.joblib{Colors.ENDC}")

print(f"{Colors.CYAN}[*] Loading Random Forest Model...{Colors.ENDC}")
try:
    model = joblib.load(MODEL_PATH)
    print(f"{Colors.GREEN}[+] Model loaded successfully!{Colors.ENDC}")
except Exception as e:
    print(f"{Colors.RED}[!] Error loading model: {e}{Colors.ENDC}")
    sys.exit(1)

# Dictionary to hold connection state
flows = {}
last_seen_ip = {}

def get_flow_key(packet):
    if not packet.haslayer(IP) or not packet.haslayer(UDP):
        return None, None
        
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = packet[UDP].sport
    dst_port = packet[UDP].dport
    
    # We strictly care about QUIC traffic (UDP port 443)
    if src_port != 443 and dst_port != 443:
        return None, None
        
    # The client is usually the one NOT on port 443
    if dst_port == 443:
        return (src_ip, src_port, dst_ip, dst_port), 1
    else:
        return (dst_ip, dst_port, src_ip, src_port), -1

MIN_TRIGGER_PACKETS = 10  # Classify faster! Don't wait for all 15

def process_packet(packet):
    flow_key, direction = get_flow_key(packet)
    
    if not flow_key:
        return
        
    if flow_key not in flows:
        flows[flow_key] = {
            'packets': [],
            'last_time': packet.time,
            'processed': False,
            'server_ip': flow_key[2]
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
    
    # Fast trigger: Once we have enough packets (10), classify immediately!
    if len(flow['packets']) >= MIN_TRIGGER_PACKETS and not flow['processed']:
        flow['processed'] = True
        analyze_flow(flow_key, flow)

def analyze_flow(flow_key, flow):
    client_ip = flow_key[0]
    server_ip = flow_key[2]

    features = []
    for p in flow['packets'][:MAX_PACKETS]:
        features.extend([p['size'], p['dir'], p['iat']])
        
    # Zero-pad remaining packets if triggered early (e.g., at 10 packets)
    while len(features) < MAX_PACKETS * 3:
        features.extend([0, 0, 0.0])
        
    X = np.array(features).reshape(1, -1)
    
    prediction = model.predict(X)[0]
    probabilities = model.predict_proba(X)[0]
    
    # Get confidence
    top_prob = float(np.max(probabilities)) * 100
    top_idx = np.argmax(probabilities)
    
    # Sort classes by probability to see runner-up
    sorted_indices = np.argsort(probabilities)[::-1]
    second_prob = float(probabilities[sorted_indices[1]]) * 100 if len(sorted_indices) > 1 else 0
    second_class = model.classes_[sorted_indices[1]] if len(sorted_indices) > 1 else ""
    
    # Debounce: Don't spam the exact same server IP repeatedly within 2 seconds
    current_time = time.time()
    if server_ip in last_seen_ip and (current_time - last_seen_ip[server_ip]) < 2.0:
        return
        
    last_seen_ip[server_ip] = current_time
    
    # Print prediction (threshold >= 30%)
    if top_prob >= 30.0:
        print(f"\n{Colors.BOLD}--- Live Connection Captured ---{Colors.ENDC}")
        print(f"Target Server : {server_ip}")
        print(f"Prediction    : {Colors.YELLOW}{prediction.upper()}{Colors.ENDC} ({top_prob:.1f}%)")
        if second_prob > 15.0:
            print(f"Runner-up     : {second_class.upper()} ({second_prob:.1f}%)")
        print(f"---------------------------------------")

def get_active_interface():
    from scapy.all import get_if_list, get_if_addr
    import socket
    print(f"{Colors.YELLOW}[*] Auto-detecting active network interface...{Colors.ENDC}")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        
        for iface in get_if_list():
            try:
                if get_if_addr(iface) == local_ip:
                    print(f"{Colors.GREEN}[+] Found active interface: {iface} (IP: {local_ip}){Colors.ENDC}")
                    return iface
            except:
                pass
    except Exception as e:
        print(f"Error finding route: {e}")
    return None

if __name__ == "__main__":
    print(f"{Colors.BLUE}[*] Starting packet capture...{Colors.ENDC}")
    print(f"{Colors.BLUE}[*] Make sure you are running this terminal as Administrator!{Colors.ENDC}")
    print(f"{Colors.BLUE}[*] Open your browser and go to YouTube, Spotify, or Discord.{Colors.ENDC}\n")
    
    active_iface = get_active_interface()
    
    try:
        if active_iface:
            sniff(iface=active_iface, filter="udp port 443", prn=process_packet, store=False)
        else:
            print(f"{Colors.RED}[!] Could not auto-detect interface. Falling back to default.{Colors.ENDC}")
            sniff(filter="udp port 443", prn=process_packet, store=False)
    except Exception as e:
        print(f"{Colors.RED}[!] Sniffing failed. Do you have Npcap/Wireshark installed?{Colors.ENDC}")
        print(f"Error: {e}")
