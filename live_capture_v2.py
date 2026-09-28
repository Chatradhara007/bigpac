"""
BigPAC live classifier (v2). Classifies each new QUIC connection on your network
as one of the 10 apps, "other" (none of them) or UNKNOWN (not confident).

  python live_capture_v2.py                      # live, auto-detects Wi-Fi (run as Administrator)
  python live_capture_v2.py --iface "Wi-Fi"      # live, chosen interface
  python live_capture_v2.py --list-ifaces        # show interface names
  python live_capture_v2.py --pcap file.pcapng   # replay a saved capture (no admin needed)
  python live_capture_v2.py --hybrid             # final answer from the server name when visible

Each line shows the MODEL's prediction (packet sizes/timing only) and, when the
server name (SNI) is readable from the QUIC Initial, the true app with a tick or
cross, plus the running model accuracy. With --hybrid the FINAL answer uses the
server name when visible and the model only when it is hidden (e.g. ECH).
Every prediction is appended to results/live_log.csv (--log).
Uses features.py, exactly like training (train_v2.py).
"""
import argparse
import csv
import os
import socket
import sys
from collections import Counter, deque
from datetime import datetime

import joblib
import sklearn

import features as F
from pcap_to_dataset import sni_to_app

try:
    from quic_sni import SniCollector
except ImportError:          # cryptography not installed: run without SNI
    SniCollector = None

if os.name == "nt":  # enable ANSI colours in the Windows console
    try:
        import ctypes
        k = ctypes.windll.kernel32
        k.SetConsoleMode(k.GetStdHandle(-11), 7)
    except Exception:
        pass

G, Y, R, C, D, B, E = ("\033[92m", "\033[93m", "\033[91m", "\033[96m",
                       "\033[90m", "\033[1m", "\033[0m")
IDLE_EXPIRE = 60.0          # forget flows silent for this long (seconds)
SUMMARY_WINDOW = 30.0       # "apps seen recently" window (seconds)
QUIC_V2 = 0x6B3343CF


def is_client_initial(payload):
    """True if the UDP payload starts with a QUIC long-header Initial packet."""
    if len(payload) < 7 or not payload[0] & 0x80:
        return False
    version = int.from_bytes(payload[1:5], "big")
    if version == 0:                      # version negotiation
        return False
    ptype = (payload[0] & 0x30) >> 4
    return ptype == (1 if version == QUIC_V2 else 0)


class Classifier:
    def __init__(self, bundle_path, log_path, hybrid=False):
        self.hybrid = hybrid
        if SniCollector is None:
            print(f"{Y}[!] 'cryptography' not installed: server names cannot be read "
                  f"(pip install cryptography). Showing model predictions only.{E}")
            self.hybrid = False
        if not os.path.exists(bundle_path):
            sys.exit(f"{R}Model not found: {bundle_path}. Run: python train_v2.py{E}")
        b = joblib.load(bundle_path)
        self.model, self.classes = b["model"], b["classes"]
        self.threshold, self.use_iat = b["threshold"], b["use_iat"]
        if b["feature_version"] != F.FEATURE_VERSION:
            sys.exit(f"{R}Model uses features {b['feature_version']}, code has {F.FEATURE_VERSION}{E}")
        if b["sklearn_version"] != sklearn.__version__:
            print(f"{Y}[!] Model trained with scikit-learn {b['sklearn_version']}, "
                  f"you have {sklearn.__version__}. Retrain or match versions.{E}")
        print(f"{G}[+] Model {bundle_path}: {b['candidate']}, threshold {self.threshold:.2f}, "
              f"trained {b['trained']}{E}")
        self.flows = {}
        self.recent = deque()
        self.stats = Counter()
        self.last_expire = 0.0
        self.log = None
        if log_path:
            os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)
            new = not os.path.exists(log_path)
            self.log_f = open(log_path, "a", newline="", encoding="utf-8")
            self.log = csv.writer(self.log_f)
            if new:
                self.log.writerow(["time", "ip_version", "client", "server", "model_prediction",
                                   "confidence", "top3", "n_client_before_server", "sni",
                                   "sni_app", "final", "final_source"])

    def packet(self, t, src, dst, sport, dport, payload, ipv):
        if dport == 443:
            key, d = (src, sport, dst, dport), 1
        elif sport == 443:
            key, d = (dst, dport, src, sport), -1
        else:
            return
        self.stats["udp443_packets"] += 1
        f = self.flows.get(key)
        if f is None:
            if d != 1 or len(payload) < 1150 or not is_client_initial(payload):
                return                                   # mid-stream: ignore
            f = self.flows[key] = {"pkts": [], "last": t, "done": False, "ipv": ipv,
                                   "sni": SniCollector() if SniCollector else None}
            self.stats["flows_started"] += 1
        if d == 1 and f["sni"] is not None and not f["sni"].done and len(f["pkts"]) < 6:
            f["sni"].add(payload)
        iat = 0.0 if not f["pkts"] else (t - f["last"]) * 1000.0
        f["last"] = t
        if f["done"]:
            return
        f["pkts"].append((len(payload), d, iat))
        if F.ready(f["pkts"]) or len(f["pkts"]) >= F.MAX_PKTS:
            f["done"] = True
            self.classify(key, f, t)
        if t - self.last_expire > 5.0:
            self.last_expire = t
            for k in [k for k, v in self.flows.items() if t - v["last"] > IDLE_EXPIRE]:
                del self.flows[k]

    def classify(self, key, f, t):
        x = F.features_from_packets(f["pkts"], self.use_iat)
        p = self.model.predict_proba(x)[0]
        order = p.argsort()[::-1]
        top, conf = self.classes[order[0]], float(p[order[0]])
        pred = top if conf >= self.threshold else "UNKNOWN"
        top3 = ", ".join(f"{self.classes[i]} {p[i]:.0%}" for i in order[:3])
        n_before = int(x[0][F.feature_names(self.use_iat).index("n_client_before_server")])
        self.stats["classified"] += 1
        sni = f["sni"].sni if f["sni"] is not None else None
        truth = sni_to_app(sni) if sni else None          # None: name hidden (ECH) or unreadable
        if self.hybrid and truth:
            final, source = truth, "sni"
        else:
            final, source = pred, "model"
        when = datetime.fromtimestamp(t).strftime("%H:%M:%S")
        server = f"[{key[2]}]:{key[3]}" if f["ipv"] == 6 else f"{key[2]}:{key[3]}"
        colour = G if final not in ("other", "UNKNOWN") else (D if final == "other" else Y)
        check = ""
        if truth:
            ok = pred == truth or (pred == "UNKNOWN" and truth == "other")
            self.stats["labelled"] += 1
            self.stats["model_correct"] += ok
            if truth != "other":
                self.stats["labelled_apps"] += 1
                self.stats["model_correct_apps"] += ok
            check = (f"{G}✓{E}" if ok else f"{R}✗{E}") + f" true: {truth}"
        elif sni:
            check = f"{D}name hidden ({sni}){E}"
        head = f"{when} IPv{f['ipv']} {server:<40} "
        if self.hybrid:
            print(f"{head}{colour}{B}{final:<16}{E} [{source}]  model: {pred} {conf:.0%}  {check}")
        else:
            print(f"{head}{colour}{B}{pred:<16}{E} {conf:4.0%}  {check}   {D}{top3}{E}")
        if sni:
            print(f"   {D}server name: {sni}{E}")
        st = self.stats
        if st["labelled"] and st["labelled"] % 10 == 0:
            apps = (f", apps only {st['model_correct_apps']}/{st['labelled_apps']}"
                    if st["labelled_apps"] else "")
            print(f"   {C}model accuracy so far: {st['model_correct']}/{st['labelled']}{apps}{E}")
        if self.log:
            self.log.writerow([datetime.fromtimestamp(t).isoformat(timespec="seconds"), f["ipv"],
                               f"{key[0]}:{key[1]}", f"{key[2]}:{key[3]}", pred,
                               round(conf, 4), top3, n_before, sni or "", truth or "",
                               final, source])
            self.log_f.flush()
        pred = final
        self.recent.append((t, pred))
        while self.recent and t - self.recent[0][0] > SUMMARY_WINDOW:
            self.recent.popleft()
        apps = Counter(p for _, p in self.recent if p not in ("other", "UNKNOWN"))
        if apps:
            print(f"   {C}apps in last {SUMMARY_WINDOW:.0f}s: " +
                  ", ".join(f"{a} x{n}" for a, n in apps.most_common()) + E)


def handle(clf, pkt, IP, IPv6, UDP):
    if not pkt.haslayer(UDP):
        clf.stats["tcp443_packets"] += 1
        return
    if pkt.haslayer(IP):
        ip, ipv = pkt[IP], 4
    elif pkt.haslayer(IPv6):
        ip, ipv = pkt[IPv6], 6
    else:
        return
    u = pkt[UDP]
    clf.packet(float(pkt.time), ip.src, ip.dst, u.sport, u.dport, bytes(u.payload), ipv)


def active_iface(get_if_list, get_if_addr):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        for iface in get_if_list():
            try:
                if get_if_addr(iface) == local_ip:
                    return iface
            except Exception:
                pass
    except Exception:
        pass
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--model", default="models/bigpac_v2.joblib")
    ap.add_argument("--iface")
    ap.add_argument("--pcap", help="replay a capture file instead of sniffing live")
    ap.add_argument("--hybrid", action="store_true",
                    help="final answer = app from the server name when visible, model otherwise")
    ap.add_argument("--log", default="results/live_log.csv",
                    help="CSV of predictions ('' to disable)")
    ap.add_argument("--list-ifaces", action="store_true")
    args = ap.parse_args()

    from scapy.all import IP, IPv6, UDP, conf, get_if_addr, get_if_list, sniff
    if args.list_ifaces:
        for i in get_if_list():
            print(i)
        try:
            conf.ifaces.show()
        except Exception:
            pass
        return

    clf = Classifier(args.model, args.log or None, hybrid=args.hybrid)
    kw = dict(filter="udp port 443 or tcp port 443", store=False,
              prn=lambda p: handle(clf, p, IP, IPv6, UDP))
    mode = "HYBRID (server name first, model if hidden)" if clf.hybrid else "MODEL ONLY (packets only)"
    print(f"{C}[*] Mode: {mode}{E}")
    try:
        if args.pcap:
            kw.pop("filter")        # ports are checked in code; avoids needing tcpdump
            sniff(offline=args.pcap, **kw)
        else:
            iface = args.iface or active_iface(get_if_list, get_if_addr)
            print(f"{C}[*] Sniffing on {iface or 'default interface'} - open YouTube, Instagram, "
                  f"Spotify... (Ctrl+C to stop){E}")
            sniff(iface=iface, **kw) if iface else sniff(**kw)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"{R}[!] Capture failed: {e}\n    Live mode needs Npcap and an Administrator terminal.{E}")
    s = clf.stats
    print(f"\n{C}summary: {s['flows_started']} QUIC connections started, "
          f"{s['classified']} classified, {s['udp443_packets']} QUIC packets, "
          f"{s['tcp443_packets']} TCP:443 packets{E}")
    if s["labelled"]:
        apps = (f"; on app connections {s['model_correct_apps']}/{s['labelled_apps']} = "
                f"{s['model_correct_apps'] / s['labelled_apps']:.1%}" if s["labelled_apps"] else "")
        print(f"{C}model accuracy vs server names: {s['model_correct']}/{s['labelled']} = "
              f"{s['model_correct'] / s['labelled']:.1%}{apps}{E}")
    if s["tcp443_packets"] and not s["udp443_packets"]:
        print(f"{Y}[!] Only TCP traffic seen: this network probably blocks QUIC, "
              f"so there is nothing for BigPAC to classify here.{E}")


if __name__ == "__main__":
    main()
