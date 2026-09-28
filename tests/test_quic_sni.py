"""quic_sni: RFC 9001 Appendix A key vector + server names from the loopback fixture.
Run: python tests/test_quic_sni.py   (needs cryptography and scapy)"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
import quic_sni as Q  # noqa: E402


def test_rfc9001_keys():
    k, iv, hp = Q.client_keys(bytes.fromhex("8394c8f03e515708"), Q.V1)
    assert k.hex() == "1f369613dd76d5467730efcbe3b1a22d"
    assert iv.hex() == "fa044b2f42a3fd3b46fb255c"
    assert hp.hex() == "9f50449e04a0e810283a1e9933adedd2"


def test_fixture_server_names():
    from scapy.all import UDP, rdpcap
    pcap = os.path.join(HERE, "fixtures", "quic_loopback_fixture.pcapng")
    truth = sorted(t["sni"] for t in json.load(open(pcap + ".truth.json")))
    flows = {}
    for p in rdpcap(pcap):
        u = p[UDP]
        if u.dport == 443:
            flows.setdefault(u.sport, Q.SniCollector()).add(bytes(u.payload))
    assert sorted(c.sni for c in flows.values()) == truth


if __name__ == "__main__":
    test_rfc9001_keys()
    print("ok  test_rfc9001_keys")
    test_fixture_server_names()
    print("ok  test_fixture_server_names (incl. ClientHello split over 2 Initials)")
    print("2 passed")
