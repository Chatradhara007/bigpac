"""
Read the server name (SNI) from a client's QUIC Initial packets (RFC 9001 / RFC 9369).

QUIC Initial packets are encrypted with keys derived only from public header
values (the destination connection ID), so any observer (Wireshark, a firewall)
can read the TLS ClientHello inside them. This module does the same so the
live tool can show the true app next to the model's prediction.

Handles ClientHellos split across several Initial packets (Chrome's
post-quantum key share) and out-of-order CRYPTO frames. Returns None when the
name is not (yet) available, e.g. Encrypted Client Hello hides the real name
behind an outer one such as cloudflare-ech.com.
Requires the `cryptography` package.
"""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hmac import HMAC

V1, V2 = 0x00000001, 0x6B3343CF
SALTS = {V1: bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
         V2: bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9")}
LABELS = {V1: (b"quic key", b"quic iv", b"quic hp"),
          V2: (b"quicv2 key", b"quicv2 iv", b"quicv2 hp")}


def _hmac(key, data):
    h = HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


def _expand_label(secret, label, length):
    full = b"tls13 " + label
    info = length.to_bytes(2, "big") + bytes([len(full)]) + full + b"\x00"
    out, block, i = b"", b"", 1
    while len(out) < length:
        block = _hmac(secret, block + info + bytes([i]))
        out += block
        i += 1
    return out[:length]


def _varint(b, i):
    first = b[i]
    n = 1 << (first >> 6)
    v = first & 0x3F
    for k in range(1, n):
        v = (v << 8) | b[i + k]
    return v, i + n


def client_keys(dcid, version):
    secret = _hmac(SALTS[version], dcid)                      # HKDF-Extract
    client = _expand_label(secret, b"client in", 32)
    k, iv, hp = LABELS[version]
    return _expand_label(client, k, 16), _expand_label(client, iv, 12), _expand_label(client, hp, 16)


def decrypt_initial(datagram):
    """Decrypt the first (Initial) packet of a client datagram.
    Returns (dcid, plaintext frames) or None."""
    b = bytearray(datagram)
    if len(b) < 7 or not b[0] & 0x80:
        return None
    version = int.from_bytes(b[1:5], "big")
    if version not in SALTS:
        return None
    ptype = (b[0] & 0x30) >> 4
    if ptype != (1 if version == V2 else 0):
        return None
    i = 5
    dl = b[i]
    dcid = bytes(b[i + 1:i + 1 + dl])
    i += 1 + dl
    i += 1 + b[i]                                            # SCID
    tok_len, i = _varint(b, i)
    i += tok_len
    length, pn_off = _varint(b, i)
    if pn_off + length > len(b) or length < 20:
        return None
    key, iv, hp = client_keys(dcid, version)
    sample = bytes(b[pn_off + 4:pn_off + 20])
    enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = enc.update(sample) + enc.finalize()
    b[0] ^= mask[0] & 0x0F
    pn_len = (b[0] & 0x03) + 1
    for k in range(pn_len):
        b[pn_off + k] ^= mask[1 + k]
    pn = int.from_bytes(b[pn_off:pn_off + pn_len], "big")
    nonce = bytes(x ^ y for x, y in zip(iv, pn.to_bytes(12, "big")))
    aad = bytes(b[:pn_off + pn_len])
    ct = bytes(b[pn_off + pn_len:pn_off + length])
    try:
        return dcid, AESGCM(key).decrypt(nonce, ct, aad)
    except Exception:
        return None


def crypto_frames(plain):
    """Yield (offset, data) for CRYPTO frames; skips PADDING, PING and ACK frames."""
    i = 0
    while i < len(plain):
        t = plain[i]
        if t == 0x00:
            i += 1
        elif t == 0x01:
            i += 1
        elif t in (0x02, 0x03):
            i += 1
            _, i = _varint(plain, i)               # largest acknowledged
            _, i = _varint(plain, i)               # ack delay
            count, i = _varint(plain, i)
            _, i = _varint(plain, i)               # first range
            for _ in range(count):
                _, i = _varint(plain, i)
                _, i = _varint(plain, i)
            if t == 0x03:
                for _ in range(3):
                    _, i = _varint(plain, i)
        elif t == 0x06:
            off, i = _varint(plain, i + 1)
            n, i = _varint(plain, i)
            yield off, plain[i:i + n]
            i += n
        else:
            return                                  # anything else: stop parsing


def sni_from_client_hello(ch):
    """Server name from a complete TLS ClientHello handshake message, or None."""
    if len(ch) < 4 or ch[0] != 1:
        return None
    i = 4 + 2 + 32
    i += 1 + ch[i]                                  # session id
    i += 2 + int.from_bytes(ch[i:i + 2], "big")     # cipher suites
    i += 1 + ch[i]                                  # compression
    end = i + 2 + int.from_bytes(ch[i:i + 2], "big")
    i += 2
    while i + 4 <= end:
        etype = int.from_bytes(ch[i:i + 2], "big")
        elen = int.from_bytes(ch[i + 2:i + 4], "big")
        data = ch[i + 4:i + 4 + elen]
        if etype == 0 and len(data) >= 5 and data[2] == 0:
            n = int.from_bytes(data[3:5], "big")
            return data[5:5 + n].decode("ascii", "replace")
        i += 4 + elen
    return None


class SniCollector:
    """Accumulates CRYPTO data from a flow's client Initial datagrams until the SNI is known."""

    def __init__(self):
        self.dcid = None
        self.chunks = {}
        self.done = False
        self.sni = None

    def add(self, datagram):
        if self.done:
            return self.sni
        res = decrypt_initial(datagram)
        if res is None:
            return None
        dcid, plain = res
        if self.dcid is None:
            self.dcid = dcid
        elif dcid != self.dcid:
            return None
        for off, data in crypto_frames(plain):
            self.chunks[off] = data
        buf, pos = b"", 0
        while pos in self.chunks:
            buf += self.chunks[pos]
            pos = len(buf)
        if len(buf) >= 4:
            need = 4 + int.from_bytes(buf[1:4], "big")
            if len(buf) >= need:
                self.sni = sni_from_client_hello(buf[:need])
                self.done = True
        return self.sni
