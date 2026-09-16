import os
import sys
import time
import socket
from collections import deque, Counter
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
IDLE_RESET_SECONDS = 3.5  # Reset connection after 3.5s idle to catch new media bursts (e.g. video starting)

# Choose between the 192k-sample CESNET model (default) or the custom live model
models_by_n = {}
use_custom = "--custom" in sys.argv

if use_custom and os.path.exists('models/my_custom_model.joblib'):
    print(f"{Colors.YELLOW}[*] Mode: Custom Live-Trained Model (models/my_custom_model.joblib){Colors.ENDC}")
    try:
        models_by_n[MAX_PACKETS] = joblib.load('models/my_custom_model.joblib')
    except Exception as e:
        print(f"{Colors.RED}[!] Error loading custom model: {e}{Colors.ENDC}")
        sys.exit(1)
else:
    print(f"{Colors.GREEN}[*] Mode: 192k-Sample Month-Long CESNET Model (10 classes){Colors.ENDC}")
    for n in (10, 15):
        path = f'models/rf_model_n{n}.joblib'
        if os.path.exists(path):
            models_by_n[n] = joblib.load(path)
            print(f"{Colors.GREEN}[+] Loaded {path}{Colors.ENDC}")
    if os.path.exists('models/my_custom_model.joblib'):
        print(f"{Colors.CYAN}[*] Tip: Run 'python live_capture.py --custom' to use your custom self-trained model.{Colors.ENDC}")

if not models_by_n:
    print(f"{Colors.RED}[!] No models found in models/. Run model_pipeline.py first.{Colors.ENDC}")
    sys.exit(1)

TRIGGER_LEVELS = sorted(models_by_n.keys())      # e.g. [10, 15] or [15]
FINAL_LEVEL = TRIGGER_LEVELS[-1]

print(f"{Colors.GREEN}[+] Classifier Ready. Evaluates at: {TRIGGER_LEVELS} packets{Colors.ENDC}")

# Dictionary to hold connection state
flows = {}
last_seen_ip = {}
dns_cache = {}

# Rolling window of recent final-level predictions for session smoothing
RECENT_WINDOW_SECONDS = 3.0
recent_predictions = deque()  # (timestamp, prediction, confidence)

tcp_fallback_count = 0
quic_flow_count = 0

def resolve_hostname(ip):
    if ip in dns_cache:
        return dns_cache[ip]
    try:
        host = socket.gethostbyaddr(ip)[0]
        if "1e100.net" in host:
            dns_cache[ip] = f"{host} [Google/YouTube]"
        elif "cloudflare" in host:
            dns_cache[ip] = f"{host} [Cloudflare/Discord]"
        elif "googleusercontent" in host:
            dns_cache[ip] = f"{host} [Google Cloud/Snapchat]"
        else:
            dns_cache[ip] = host
    except Exception:
        dns_cache[ip] = ip
    return dns_cache[ip]

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
        
    if dst_port == 443:
        return (src_ip, src_port, dst_ip, dst_port), 1
    else:
        return (dst_ip, dst_port, src_ip, src_port), -1

def process_packet(packet):
    global quic_flow_count
    flow_key, direction = get_flow_key(packet)
    
    if not flow_key:
        return
        
    quic_flow_count += 1
    current_time = packet.time
    
    if flow_key not in flows:
        flows[flow_key] = {
            'packets': [],
            'last_time': current_time,
            'processed': False,
            'triggered_levels': set(),
            'server_ip': flow_key[2]
        }
        
    flow = flows[flow_key]
    
    # FLOW IDLE RESET:
    # In HTTP/3 QUIC, Chrome keeps connections open for minutes. When you search,
    # it completes 15 packets. When you then click a video 4 seconds later, Chrome
    # reuses the SAME connection. If we don't reset idle flows, the video stream
    # would be permanently ignored.
    if current_time - flow['last_time'] > IDLE_RESET_SECONDS:
        flow['packets'] = []
        flow['processed'] = False
        flow['triggered_levels'] = set()
    
    if flow['processed']:
        return
        
    iat = (current_time - flow['last_time']) * 1000 
    if len(flow['packets']) == 0:
        iat = 0.0
        
    flow['last_time'] = current_time
    
    # Measure transport payload size (matches CESNET PPI definition)
    if packet.haslayer(UDP):
        size = len(bytes(packet[UDP].payload))
    else:
        size = len(packet[IP].payload)
    
    flow['packets'].append({
        'size': size,
        'dir': direction,
        'iat': iat
    })
    
    count = len(flow['packets'])
    
    # Trigger prediction for each configured packet depth (e.g. 10, then 15)
    for level in TRIGGER_LEVELS:
        if count == level and level not in flow['triggered_levels']:
            flow['triggered_levels'].add(level)
            analyze_flow(flow_key, flow, level)
    
    if count >= FINAL_LEVEL:
        flow['processed'] = True

def analyze_flow(flow_key, flow, n_packets):
    server_ip = flow_key[2]
    hostname = resolve_hostname(server_ip)
    model = models_by_n[n_packets]

    features = []
    for p in flow['packets'][:n_packets]:
        features.extend([p['size'], p['dir'], p['iat']])
        
    X = np.array(features).reshape(1, -1)
    
    prediction = model.predict(X)[0]
    probabilities = model.predict_proba(X)[0]
    
    top_prob = float(np.max(probabilities)) * 100
    sorted_indices = np.argsort(probabilities)[::-1]
    second_prob = float(probabilities[sorted_indices[1]]) * 100 if len(sorted_indices) > 1 else 0
    second_class = model.classes_[sorted_indices[1]] if len(sorted_indices) > 1 else ""
    
    # Debounce: Don't spam the exact same server IP repeatedly within 2.0s
    current_time = time.time()
    if server_ip in last_seen_ip and (current_time - last_seen_ip[server_ip]) < 2.0:
        return
    last_seen_ip[server_ip] = current_time
    
    tag = f"early @ {n_packets}pkt" if n_packets != FINAL_LEVEL else f"final @ {n_packets}pkt"
    
    # CONFIDENCE ROUTING:
    # If confidence is under 50%, flag as UNCERTAIN / BACKGROUND rather than misleadingly
    # presenting a weak 35% guess as a confident classification.
    if top_prob >= 50.0:
        color = Colors.GREEN if top_prob >= 70.0 else Colors.YELLOW
        print(f"\n{Colors.BOLD}--- Live QUIC Connection Captured ({tag}) ---{Colors.ENDC}")
        print(f"Target Server : {server_ip} ({hostname})")
        print(f"Prediction    : {color}{prediction.upper()}{Colors.ENDC} ({top_prob:.1f}%)")
        if second_prob > 15.0:
            print(f"Runner-up     : {second_class.upper()} ({second_prob:.1f}%)")
    elif top_prob >= 30.0:
        # Informative note for ambiguous background handshakes
        print(f"\n{Colors.BOLD}--- Live QUIC Connection Captured ({tag}) ---{Colors.ENDC}")
        print(f"Target Server : {server_ip} ({hostname})")
        print(f"Prediction    : {Colors.CYAN}UNCERTAIN / BACKGROUND{Colors.ENDC} (Top Guess: {prediction.upper()} {top_prob:.1f}%, Runner-up: {second_class.upper()} {second_prob:.1f}%)")
        print(f"Note          : Handshake pattern is generic; awaiting media streaming burst.")

    # Only feed FINAL_LEVEL confident predictions into the session consensus
    if n_packets == FINAL_LEVEL and top_prob >= 50.0:
        recent_predictions.append((current_time, prediction, top_prob))
        while recent_predictions and current_time - recent_predictions[0][0] > RECENT_WINDOW_SECONDS:
            recent_predictions.popleft()

        if len(recent_predictions) >= 2:
            votes = Counter(p for _, p, _ in recent_predictions)
            consensus, vote_count = votes.most_common(1)[0]
            avg_conf = np.mean([c for _, p, c in recent_predictions if p == consensus])
            print(f"Session view  : {Colors.CYAN}{consensus.upper()}{Colors.ENDC} "
                  f"({vote_count}/{len(recent_predictions)} parallel flows agree, avg {avg_conf:.1f}%)")
    print(f"---------------------------------------")

def get_active_interface():
    from scapy.all import get_if_list, get_if_addr
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
            except Exception:
                pass
    except Exception as e:
        print(f"Error finding route: {e}")
    return None

def note_tcp_fallback(packet):
    global tcp_fallback_count
    tcp_fallback_count += 1

if __name__ == "__main__":
    print(f"{Colors.BLUE}[*] Starting packet capture...{Colors.ENDC}")
    print(f"{Colors.BLUE}[*] Make sure you are running this terminal as Administrator!{Colors.ENDC}")
    print(f"{Colors.BLUE}[*] Open your browser and go to YouTube, Spotify, or Discord.{Colors.ENDC}\n")
    
    active_iface = get_active_interface()

    def dispatch(packet):
        if packet.haslayer(UDP):
            process_packet(packet)
        elif packet.haslayer(TCP):
            note_tcp_fallback(packet)

    try:
        sniff_kwargs = dict(filter="tcp port 443 or udp port 443", prn=dispatch, store=False)
        if active_iface:
            sniff(iface=active_iface, **sniff_kwargs)
        else:
            print(f"{Colors.RED}[!] Could not auto-detect interface. Falling back to default.{Colors.ENDC}")
            sniff(**sniff_kwargs)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"{Colors.RED}[!] Sniffing failed. Do you have Npcap/Wireshark installed?{Colors.ENDC}")
        print(f"Error: {e}")
    finally:
        if tcp_fallback_count > 0 and quic_flow_count == 0:
            print(f"\n{Colors.YELLOW}[*] Saw {tcp_fallback_count} TCP:443 packets and 0 usable QUIC flows on this "
                  f"network — this network is likely blocking/downgrading QUIC, which is why nothing classifies "
                  f"here. This tool only understands QUIC traffic; it would need a separate TCP/TLS-trained model "
                  f"to work on this network.{Colors.ENDC}")
