"""
Stage 1: turn QUIC packet captures into an SNI-labelled live dataset.

Every QUIC flow that starts with a client Initial packet is turned into the
same 30-packet [size, dir, iat] layout as data/processed_data.parquet and
labelled from the server name (SNI) that tshark decrypts from the Initial
packets. The label is ground truth for evaluation only; SNI is never a
model feature.

Usage
  python pcap_to_dataset.py convert data/captures/*.pcapng --network home
  python pcap_to_dataset.py report  [--csv data/live_labelled.csv]

Requires tshark (Wireshark) >= 3.6 on PATH, or pass --tshark PATH.
Validated with TShark 4.2.2 (see IMPLEMENTATION_STATUS.md, Stage 1).
"""
import argparse
import csv
import glob
import hashlib
import os
import shutil
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone

CONVERTER_VERSION = "stage1-v1"
MAX_PKTS = 30
DEFAULT_CSV = os.path.join("data", "live_labelled.csv")

# ---------------------------------------------------------------------------
# SNI -> app rules. A rule matches the exact domain or any subdomain of it.
# Extend these as new domains show up in `report` under "top 'other' SNIs".
# ---------------------------------------------------------------------------
APP_RULES = [
    ("youtube", ("googlevideo.com", "youtube.com", "ytimg.com",
                 "youtubei.googleapis.com", "youtube-nocookie.com")),
    ("google-play", ("play.googleapis.com", "play-lh.googleusercontent.com",
                     "play-fe.googleapis.com", "play.google.com")),
    ("instagram", ("instagram.com", "cdninstagram.com")),
    ("facebook-web", ("facebook.com", "fbcdn.net", "facebook.net")),
    ("whatsapp", ("whatsapp.net", "whatsapp.com")),
    ("discord", ("discord.com", "discord.gg", "discordapp.com",
                 "discordapp.net", "discord.media")),
    ("spotify", ("spotify.com", "scdn.co", "spotifycdn.com")),
    ("snapchat", ("snapchat.com", "sc-cdn.net")),
    ("tiktok", ("tiktok.com", "tiktokcdn.com", "tiktokv.com",
                "byteoversea.com", "ibytedtos.com")),
    ("microsoft-outlook", ("outlook.office.com", "outlook.office365.com",
                           "outlook.live.com")),
]

# Outer SNIs used by Encrypted Client Hello. The real destination is hidden,
# so these flows cannot be labelled and are skipped (counted, not written).
ECH_OUTER_NAMES = ("cloudflare-ech.com",)

QUIC_V2 = 0x6B3343CF

TSHARK_FIELDS = [
    "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
    "udp.srcport", "udp.dstport", "udp.length",
    "quic.version", "quic.long.packet_type", "quic.long.packet_type_v2",
    "tls.handshake.extensions_server_name",
]

META_COLS = ["label", "sni", "network", "capture_day", "flow_start_utc",
             "source", "source_sha256", "ip_version", "server_ip",
             "quic_version", "n_client_initials", "n_pkts",
             "converter_version"]
FEATURE_COLS = [f"pkt_{k}_{i}" for i in range(MAX_PKTS)
                for k in ("size", "dir", "iat")]
HEADER = META_COLS + FEATURE_COLS


def sni_to_app(sni):
    """Map a server name to one of the 10 apps, 'other', or None for ECH."""
    s = sni.strip().lower().rstrip(".")
    if any(s == x or s.endswith("." + x) for x in ECH_OUTER_NAMES):
        return None
    for app, suffixes in APP_RULES:
        if any(s == x or s.endswith("." + x) for x in suffixes):
            return app
    return "other"


# ---------------------------------------------------------------------------
# Reading packets with tshark
# ---------------------------------------------------------------------------
def find_tshark(explicit=None):
    if explicit:
        return explicit
    found = shutil.which("tshark")
    if found:
        return found
    win_default = r"C:\Program Files\Wireshark\tshark.exe"
    if os.path.exists(win_default):
        return win_default
    sys.exit("tshark not found. Install Wireshark or pass --tshark PATH.")


def _int(x, default=None):
    try:
        return int(x, 0)
    except (TypeError, ValueError):
        return default


def read_packets(pcap, tshark):
    """Yield one dict per UDP:443 datagram, in capture order.

    ICMP/ICMPv6 errors that quote a UDP:443 header are excluded; otherwise
    their embedded header would be read as a real packet.
    """
    cmd = [tshark, "-r", pcap, "-n",
           "-Y", "udp.port==443 && !icmp && !icmpv6",
           "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f"]
    for f in TSHARK_FIELDS:
        cmd += ["-e", f]
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    if proc.returncode != 0:
        raise RuntimeError(f"tshark failed on {pcap}:\n{proc.stderr.strip()}")
    for line in proc.stdout.splitlines():
        v = (line.split("\t") + [""] * len(TSHARK_FIELDS))[:len(TSHARK_FIELDS)]
        (t, s4, s6, d4, d6, sp, dp, ulen, ver, ptype, ptype2, sni) = v
        version = _int(ver)
        if version == QUIC_V2:
            is_initial = _int(ptype2) == 1
        else:
            is_initial = _int(ptype) == 0
        yield {
            "t": float(t),
            "src": s4 or s6, "dst": d4 or d6,
            "ipv": 4 if s4 else 6,
            "sport": int(sp), "dport": int(dp),
            "size": int(ulen) - 8,          # UDP payload bytes (CESNET PPI)
            "version": version,
            "is_initial": is_initial,
            "sni": sni,
        }


# ---------------------------------------------------------------------------
# Flow building (pure Python, unit-tested in tests/test_pcap_to_dataset.py)
# ---------------------------------------------------------------------------
def build_flows(packets, idle=30.0, min_start_size=1150, stats=None):
    """Group datagrams into flows that start at a client Initial.

    A flow starts only on a client->server datagram of >= min_start_size
    bytes whose first QUIC packet is a long-header Initial (this is stricter
    than live_capture.py, which checks size only). Datagrams on unknown
    4-tuples that are not flow starts are dropped as mid-stream. A flow ends
    after `idle` seconds without packets.
    """
    stats = stats if stats is not None else Counter()
    flows, done = {}, []
    for p in packets:
        stats["datagrams"] += 1
        if p["dport"] == 443:
            key, d = (p["src"], p["sport"], p["dst"], p["dport"]), 1
        elif p["sport"] == 443:
            key, d = (p["dst"], p["dport"], p["src"], p["sport"]), -1
        else:
            continue
        f = flows.get(key)
        if f and p["t"] - f["last"] > idle:
            done.append(flows.pop(key))
            f = None
        if f is None:
            if d != 1 or p["size"] < min_start_size:
                stats["dropped_midstream"] += 1
                continue
            if not p["is_initial"]:
                stats["rejected_large_non_initial"] += 1
                continue
            f = flows[key] = {"pkts": [], "last": p["t"], "start": p["t"],
                              "sni": "", "server_ip": key[2],
                              "ipv": p["ipv"], "version": p["version"],
                              "client_initials": 0, "seen_server": False}
        if p["sni"] and not f["sni"]:
            f["sni"] = p["sni"]
        if d == -1:
            f["seen_server"] = True
        elif p["is_initial"] and not f["seen_server"]:
            f["client_initials"] += 1
        iat = 0.0 if not f["pkts"] else (p["t"] - f["last"]) * 1000.0
        f["last"] = p["t"]
        if len(f["pkts"]) < MAX_PKTS:
            f["pkts"].append((p["size"], d, round(iat, 3)))
    return done + list(flows.values())


def flow_to_row(f, label, network, source, sha):
    pk = f["pkts"] + [(0, 0, 0.0)] * (MAX_PKTS - len(f["pkts"]))
    start = datetime.fromtimestamp(f["start"], tz=timezone.utc)
    local_day = datetime.fromtimestamp(f["start"]).strftime("%Y-%m-%d")
    meta = [label, f["sni"], network, local_day,
            start.isoformat(timespec="milliseconds"), source, sha,
            f["ipv"], f["server_ip"],
            f"0x{f['version']:08x}" if f["version"] is not None else "",
            f["client_initials"], len(f["pkts"]), CONVERTER_VERSION]
    return meta + [v for p in pk for v in p]


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
def sha256_16(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()[:16]


def existing_hashes(csv_path):
    if not os.path.exists(csv_path):
        return set()
    with open(csv_path, newline="", encoding="utf-8") as fh:
        r = csv.DictReader(fh)
        if r.fieldnames != HEADER:
            sys.exit(f"{csv_path} has a different header (older converter?). "
                     "Write to a new file with --out.")
        return {row["source_sha256"] for row in r}


def cmd_convert(args):
    tshark = find_tshark(args.tshark)
    pcaps = sorted({p for pat in args.pcaps for p in glob.glob(pat)})
    if not pcaps:
        sys.exit("No capture files matched.")
    seen = existing_hashes(args.out)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    new_file = not os.path.exists(args.out)
    total = Counter()
    with open(args.out, "a", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        if new_file:
            w.writerow(HEADER)
        for pcap in pcaps:
            sha = sha256_16(pcap)
            if sha in seen and not args.force:
                print(f"skip {pcap}: already in {args.out} (use --force)")
                continue
            stats = Counter()
            flows = build_flows(read_packets(pcap, tshark), idle=args.idle,
                                stats=stats)
            labels = Counter()
            for f in flows:
                stats["flows"] += 1
                if not f["sni"]:
                    stats["skip_no_sni"] += 1
                    continue
                label = sni_to_app(f["sni"])
                if label is None:
                    stats["skip_ech_hidden"] += 1
                    continue
                if len(f["pkts"]) < args.min_pkts:
                    stats["skip_short"] += 1
                    continue
                w.writerow(flow_to_row(f, label, args.network,
                                       os.path.basename(pcap), sha))
                labels[label] += 1
                stats["written"] += 1
            seen.add(sha)
            total.update(stats)
            print(f"{os.path.basename(pcap)} [{sha}]: " +
                  ", ".join(f"{k}={v}" for k, v in sorted(stats.items())))
            if labels:
                print("   labels: " + ", ".join(
                    f"{k}={v}" for k, v in labels.most_common()))
    if not total:
        print("nothing new to convert")
        return
    print("\nTOTAL: " + ", ".join(f"{k}={v}" for k, v in sorted(total.items())))
    print(f"appended {total['written']} flows to {args.out}")


def cmd_report(args):
    if not os.path.exists(args.csv):
        sys.exit(f"{args.csv} does not exist yet.")
    with open(args.csv, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    apps = [a for a, _ in APP_RULES]
    by_app = Counter(r["label"] for r in rows)
    print(f"{len(rows)} flows in {args.csv}")
    print(f"captures: {len({r['source_sha256'] for r in rows})}, "
          f"days: {sorted({r['capture_day'] for r in rows})}, "
          f"networks: {sorted({r['network'] for r in rows})}\n")
    print(f"{'app':<20}{'flows':>7}{'days':>6}{'nets':>6}"
          f"{'ipv6':>6}{'2+ Init':>9}  target {args.target}")
    for app in apps + ["other"]:
        sub = [r for r in rows if r["label"] == app]
        days = len({r["capture_day"] for r in sub})
        nets = len({r["network"] for r in sub})
        v6 = sum(r["ip_version"] == "6" for r in sub)
        multi = sum(int(r["n_client_initials"]) >= 2 for r in sub)
        ok = "" if app == "other" else (
            "OK" if by_app[app] >= args.target else "short")
        print(f"{app:<20}{by_app[app]:>7}{days:>6}{nets:>6}"
              f"{v6:>6}{multi:>9}  {ok}")
    others = Counter(r["sni"] for r in rows if r["label"] == "other")
    print("\ntop 'other' SNIs (candidates for APP_RULES):")
    for sni, n in others.most_common(args.top):
        print(f"  {n:>5}  {sni}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawTextHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("convert", help="append labelled flows from captures")
    c.add_argument("pcaps", nargs="+", help="capture files or glob patterns")
    c.add_argument("--network", required=True,
                   help="where it was captured, e.g. home, campus, mobile")
    c.add_argument("--out", default=DEFAULT_CSV)
    c.add_argument("--min-pkts", type=int, default=15)
    c.add_argument("--idle", type=float, default=30.0,
                   help="seconds of silence that end a flow")
    c.add_argument("--tshark")
    c.add_argument("--force", action="store_true",
                   help="convert a capture again even if already in --out")
    r = sub.add_parser("report", help="summarise the labelled dataset")
    r.add_argument("--csv", default=DEFAULT_CSV)
    r.add_argument("--target", type=int, default=200)
    r.add_argument("--top", type=int, default=25)
    args = ap.parse_args()
    {"convert": cmd_convert, "report": cmd_report}[args.cmd](args)


if __name__ == "__main__":
    main()
