"""Unit tests for pcap_to_dataset.py. Run: python -m pytest tests  (or python tests/test_pcap_to_dataset.py)"""
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pcap_to_dataset as p2d  # noqa: E402

C, S = ("10.0.0.2", 50000), ("142.250.1.1", 443)


def pkt(t, up, size, initial=False, sni="", client=C, server=S, ipv=4):
    src, dst = (client, server) if up else (server, client)
    return {"t": t, "src": src[0], "sport": src[1], "dst": dst[0],
            "dport": dst[1], "ipv": ipv, "size": size, "version": 1,
            "is_initial": initial, "sni": sni}


def handshake(t0=0.0, n=20, sni="rr1---sn-abc.googlevideo.com", **kw):
    ps = [pkt(t0, True, 1250, initial=True, sni=sni, **kw)]
    for i in range(1, n):
        ps.append(pkt(t0 + i * 0.01, i % 3 == 0, 1200 if i % 3 else 60, **kw))
    return ps


def test_basic_flow():
    flows = p2d.build_flows(handshake(n=20))
    assert len(flows) == 1
    f = flows[0]
    assert f["sni"] == "rr1---sn-abc.googlevideo.com"
    assert len(f["pkts"]) == 20
    assert f["pkts"][0] == (1250, 1, 0.0)
    assert f["pkts"][1][1] == -1 and abs(f["pkts"][1][2] - 10.0) < 1e-6
    assert f["ipv"] == 4 and f["server_ip"] == "142.250.1.1"


def test_cap_at_30():
    assert len(p2d.build_flows(handshake(n=50))[0]["pkts"]) == 30


def test_midstream_and_non_initial_dropped():
    st = Counter()
    ps = [pkt(0, False, 1200),                 # server first: mid-stream
          pkt(0.1, True, 1300, initial=False)]  # large but not an Initial
    assert p2d.build_flows(ps, stats=st) == []
    assert st["dropped_midstream"] == 1
    assert st["rejected_large_non_initial"] == 1


def test_small_initial_dropped():
    st = Counter()
    assert p2d.build_flows([pkt(0, True, 900, initial=True)], stats=st) == []
    assert st["dropped_midstream"] == 1


def test_idle_split_needs_new_initial():
    st = Counter()
    ps = handshake(0, 20) + [pkt(100, True, 80), pkt(100.1, False, 1200)] \
        + handshake(200, 16, sni="www.youtube.com")
    flows = p2d.build_flows(ps, idle=30, stats=st)
    assert [len(f["pkts"]) for f in flows] == [20, 16]
    assert flows[1]["sni"] == "www.youtube.com"
    assert st["dropped_midstream"] == 2


def test_split_client_hello_counts_two_initials():
    ps = [pkt(0, True, 1250, initial=True),
          pkt(0.0001, True, 1250, initial=True, sni="discord.com"),
          pkt(0.03, False, 1200, initial=True),
          pkt(0.031, True, 1250, initial=True)]   # after server: not counted
    f = p2d.build_flows(ps)[0]
    assert f["client_initials"] == 2 and f["sni"] == "discord.com"


def test_ipv6_and_separate_flows():
    c6, s6 = ("2401:4900::2", 51000), ("2404:6800::200e", 443)
    ps = handshake(0, 15) + handshake(0.005, 15, client=c6, server=s6, ipv=6)
    flows = sorted(p2d.build_flows(sorted(ps, key=lambda x: x["t"])),
                   key=lambda f: f["ipv"])
    assert [f["ipv"] for f in flows] == [4, 6]
    assert all(len(f["pkts"]) == 15 for f in flows)


def test_sni_mapping():
    m = p2d.sni_to_app
    assert m("rr5---sn-ci5gup-qxal.googlevideo.com") == "youtube"
    assert m("WWW.YouTube.com.") == "youtube"
    assert m("notyoutube.com") == "other"
    assert m("gateway.discord.gg") == "discord"
    assert m("www.google.com") == "other"
    assert m("cloudflare-ech.com") is None
    assert m("instagram.fhyd2-1.fna.fbcdn.net") == "instagram"
    assert m("scontent.fhyd2-1.fna.fbcdn.net") == "facebook-web"


def test_row_shape():
    f = p2d.build_flows(handshake(n=17))[0]
    row = p2d.flow_to_row(f, "youtube", "home", "x.pcapng", "abc")
    assert len(row) == len(p2d.HEADER)
    feats = dict(zip(p2d.HEADER, row))
    assert feats["n_pkts"] == 17
    assert feats["pkt_dir_16"] != 0 and feats["pkt_dir_17"] == 0
    assert feats["pkt_size_29"] == 0


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("ok ", fn.__name__)
    print(f"{len(fns)} passed")
