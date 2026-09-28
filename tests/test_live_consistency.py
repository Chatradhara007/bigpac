"""Train/serve consistency: live_capture_v2 (Scapy) and pcap_to_dataset (tshark) + features.py
must produce identical feature vectors for the same capture. Needs tshark and scapy.
Run: python tests/test_live_consistency.py"""
import os
import subprocess
import sys
import tempfile
from collections import Counter

import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
import features as F  # noqa: E402
import live_capture_v2 as L  # noqa: E402

PCAP = os.path.join(HERE, "fixtures", "quic_loopback_fixture.pcapng")


class Recorder(L.Classifier):
    """Classifier that records the packets it would classify instead of using a model."""
    def __init__(self):
        self.flows, self.stats, self.last_expire, self.seen = {}, Counter(), 0.0, {}

    def classify(self, key, f, t):
        self.seen[key[1]] = list(f["pkts"])


def main():
    from scapy.all import IP, IPv6, UDP, sniff
    rec = Recorder()
    sniff(offline=PCAP, store=False, prn=lambda p: L.handle(rec, p, IP, IPv6, UDP))
    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, "x.csv")
        subprocess.run([sys.executable, os.path.join(HERE, "..", "pcap_to_dataset.py"), "convert",
                        PCAP, "--network", "t", "--out", out],
                       check=True, capture_output=True)
        df = pd.read_csv(out)
    assert len(df) >= 3 and len(rec.seen) >= 3, (len(df), rec.seen.keys())
    checked = 0
    for _, row in df.iterrows():
        # match flows by their first packets (both tools start at the client Initial)
        pk_csv = [(row[f"pkt_size_{i}"], row[f"pkt_dir_{i}"], row[f"pkt_iat_{i}"]) for i in range(30)]
        x_csv = F.features_from_packets(pk_csv)[0]
        matches = [k for k, pk in rec.seen.items()
                   if np.allclose(F.features_from_packets(pk)[0], x_csv, atol=1e-3)]
        assert matches, f"no live flow matches converter row for {row['sni']}"
        checked += 1
    print(f"ok: {checked} converter flows have identical features in the live sniffer "
          f"({len(rec.seen)} flows classified live)")


if __name__ == "__main__":
    main()
