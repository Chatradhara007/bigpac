import sys
from scapy.all import sniff, get_if_list, conf

print("--- Scapy Network Diagnostic ---")
print("1. Available Scapy Interfaces:")
for iface in get_if_list():
    print(f" - {iface}")

print(f"\n2. Scapy's Default Interface: {conf.iface}")

print("\n3. Testing packet capture (Listening for ANY 5 packets...)")
try:
    packets = sniff(count=5, timeout=10)
    if len(packets) == 0:
        print("\n[!] FAILURE: Scapy did not capture any packets within 10 seconds.")
        print("[!] This usually means Scapy is bound to the wrong network adapter (e.g., a disconnected VirtualBox adapter instead of your Wi-Fi).")
    else:
        print(f"\n[+] SUCCESS: Captured {len(packets)} packets!")
        for p in packets:
            print(f"    - {p.summary()}")
            
except Exception as e:
    print(f"\n[!] Error during capture: {e}")
