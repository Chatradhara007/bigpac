"""
Generate a small QUIC capture on loopback for validating pcap_to_dataset.py.

This produces SYNTHETIC test traffic (aioquic client/server on 127.0.0.1 and
::1, port 443). It exists only to check the converter end-to-end. It is NOT
BigPAC data and must never be added to data/live_labelled.csv.

Linux only, needs root (port 443 and loopback capture), tshark and aioquic:
  sudo python tests/make_quic_fixture.py tests/fixtures/quic_loopback_fixture.pcapng
Writes <out>.truth.json with the ground truth for each connection.
"""
import asyncio
import datetime
import json
import os
import signal
import subprocess
import sys
import tempfile
import socket
import time

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.connection import QuicConnection
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

ALPN = "bigpac-test"
# (name, sni, host, bytes requested, pad ClientHello over two Initials?)
CASES = [
    ("youtube_v4", "rr1---sn-test.googlevideo.com", "127.0.0.1", 60000, False),
    ("discord_v6", "discord.com", "::1", 60000, False),
    ("instagram_split", "scontent.cdninstagram.com", "127.0.0.1", 60000, True),
    ("other_v4", "www.example.org", "127.0.0.1", 60000, False),
    ("ech_outer", "cloudflare-ech.com", "127.0.0.1", 60000, False),
    ("spotify_short", "open.spotify.com", "127.0.0.1", 50, False),
]


def ipv6_available():
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.bind(("::1", 0))
        return True
    except OSError:
        return False


def make_cert(d):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "bigpac-test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    c, k = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
    open(c, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    open(k, "wb").write(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    return c, k


class Server(QuicConnectionProtocol):
    def quic_event_received(self, ev):
        if isinstance(ev, StreamDataReceived) and ev.end_stream:
            n = int(ev.data.decode())
            self._quic.send_stream_data(ev.stream_id, b"x" * n, end_stream=True)
            self.transmit()


async def run_client(sni, host, nbytes, split):
    cfg = QuicConfiguration(is_client=True, server_name=sni,
                            alpn_protocols=([f"pad{i:02d}" + "p" * 190 for i in range(8)]
                                            if split else []) + [ALPN])
    cfg.verify_mode = __import__("ssl").CERT_NONE
    # Own endpoint instead of aioquic.connect(), which always opens an IPv6
    # dual-stack socket and fails on hosts without IPv6.
    loop = asyncio.get_running_loop()
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    conn = QuicConnection(configuration=cfg)
    transport, client = await loop.create_datagram_endpoint(
        lambda: QuicConnectionProtocol(conn), family=fam,
        local_addr=("::1" if fam == socket.AF_INET6 else "127.0.0.1", 0))
    try:
        client.connect((host, 443))
        await client.wait_connected()
        r, w = await client.create_stream()
        w.write(str(nbytes).encode())
        w.write_eof()
        data = await r.read()
        assert len(data) == nbytes
        client.close()
        await client.wait_closed()
    finally:
        transport.close()


async def main_async(cert, key, cases, v6):
    cfg = QuicConfiguration(is_client=False, alpn_protocols=[ALPN])
    cfg.load_cert_chain(cert, key)
    servers = [await serve("127.0.0.1", 443, configuration=cfg, create_protocol=Server)]
    if v6:
        servers.append(await serve("::1", 443, configuration=cfg, create_protocol=Server))
    for _, sni, host, n, split in cases:
        await run_client(sni, host, n, split)
        await asyncio.sleep(0.3)
    for s in servers:
        s.close()


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures/quic_loopback_fixture.pcapng"
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    v6 = ipv6_available()
    cases = [c for c in CASES if v6 or ":" not in c[2]]
    skipped = [c[0] for c in CASES if c not in cases]
    if skipped:
        print(f"IPv6 unavailable here; skipped cases: {skipped}")
    with tempfile.TemporaryDirectory() as d:
        cert, key = make_cert(d)
        cap = subprocess.Popen(["tshark", "-q", "-i", "lo", "-f", "udp port 443",
                                "-w", out], stderr=subprocess.DEVNULL)
        time.sleep(2.5)
        try:
            asyncio.run(main_async(cert, key, cases, v6))
        finally:
            time.sleep(1.0)
            cap.send_signal(signal.SIGINT)
            cap.wait()
    truth = [{"case": c, "sni": s, "host": h, "bytes": n, "split_client_hello": sp}
             for c, s, h, n, sp in cases]
    json.dump(truth, open(out + ".truth.json", "w"), indent=2)
    print(f"wrote {out} and {out}.truth.json")


if __name__ == "__main__":
    main()
