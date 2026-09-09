import os
import sys
import time
import numpy as np
import joblib
from scapy.all import sniff, IP, UDP
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
# Key: (Client IP, Client Port, Server IP, Server Port)
# Value: { 'packets': [], 'last_time': float, 'processed': bool }
flows = {}

def get_flow_key(packet):
    if not packet.haslayer(IP) or not packet.haslayer(UDP):
        return None, None
        
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = packet[UDP].sport
    dst_port = packet[UDP].dport
    
    # We only care about QUIC traffic (port 443)
    if src_port != 443 and dst_port != 443:
        return None, None
        
    # The client is usually the one NOT on port 443
    if dst_port == 443:
        # Outbound (Client -> Server)
        return (src_ip, src_port, dst_ip, dst_port), 1
    else:
        # Inbound (Server -> Client)
        return (dst_ip, dst_port, src_ip, src_port), -1

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
    
    # If we already classified this connection, ignore it to save CPU
    if flow['processed']:
        return
        
    # Calculate IAT in milliseconds
    current_time = packet.time
    iat = (current_time - flow['last_time']) * 1000 
    
    # Very first packet has 0 IAT
    if len(flow['packets']) == 0:
        iat = 0.0
        
    flow['last_time'] = current_time
    
    # Get IP total length
    size = len(packet[IP])
    
    # Save packet info
    flow['packets'].append({
        'size': size,
        'dir': direction,
        'iat': iat
    })
    
    # If we hit 15 packets, run the classification!
    if len(flow['packets']) == MAX_PACKETS:
        flow['processed'] = True
        analyze_flow(flow_key, flow)

def analyze_flow(flow_key, flow):
    features = []
    for p in flow['packets']:
        features.extend([p['size'], p['dir'], p['iat']])
        
    X = np.array(features).reshape(1, -1)
    
    prediction = model.predict(X)[0]
    probabilities = model.predict_proba(X)[0]
    
    # Get confidence
    top_prob = float(np.max(probabilities)) * 100
    
    # FILTER NOISE: Only print if confidence is reasonably high
    if top_prob > 60.0:
        client_ip = flow_key[0]
        server_ip = flow_key[2]
        
        print(f"\n{Colors.BOLD}--- Live QUIC Connection Captured ---{Colors.ENDC}")
        print(f"Target Server : {server_ip}")
        print(f"Prediction    : {Colors.YELLOW}{prediction.upper()}{Colors.ENDC}")
        print(f"Confidence    : {top_prob:.1f}%")
        print(f"---------------------------------------")

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
