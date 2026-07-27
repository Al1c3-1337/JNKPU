#!/usr/bin/env python3
#
# JNKPU - Java Network Key Protector Unlocker (MS-NKPU)
#
# Copyright (C) 2026 {AUTHOR}
#
# Not part of the original JNKPU by Iain Price; added 2026.
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program. If not, see <https://www.gnu.org/licenses/>.
#
"""
test_relay.py -- exercise the JNKPU HostECRelay over TCP and verify all three
operations independently. Run on your local machine against the relay (which
talks to the YubiKey 9a slot).

    pip install cryptography
    python3 test_relay.py --host <pi-ip> --port 7213

Checks:
  1. GET_PUBKEY returns a valid 65-byte P-256 point.
  2. SIGN produces a DER ECDSA signature that verifies against that point.
  3. ECDH: we act as the "SE050", send our public point, and confirm the relay's
     ECDH(9a_priv, our_pub) equals our locally computed ECDH(our_priv, relay_pub).
"""
import argparse
import socket
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

OP_PUBKEY, OP_SIGN, OP_ECDH = 0x01, 0x02, 0x03
ST_OK, ST_ERR, ST_PIN, ST_NOKEY = 0x00, 0x01, 0x02, 0x03
STATUS = {ST_OK: "OK", ST_ERR: "ERR_GENERIC", ST_PIN: "ERR_PIN", ST_NOKEY: "ERR_NO_KEY"}


def _recvn(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("connection closed mid-message")
        buf += chunk
    return buf


def request(sock, op, payload=b""):
    sock.sendall(bytes([op]) + len(payload).to_bytes(2, "big") + payload)
    status = _recvn(sock, 1)[0]
    length = int.from_bytes(_recvn(sock, 2), "big")
    data = _recvn(sock, length)
    if status != ST_OK:
        raise RuntimeError(f"relay returned {STATUS.get(status, status)}")
    return data


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=7213)
    args = ap.parse_args()

    with socket.create_connection((args.host, args.port), timeout=15) as sock:
        # 1. public key
        point = request(sock, OP_PUBKEY)
        assert len(point) == 65 and point[0] == 0x04, f"bad point: {point.hex()}"
        relay_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
        print(f"[1] GET_PUBKEY ok: {point.hex()}")

        # 2. sign + verify
        msg = b"nu-armory relay self-test: A6||7F49 stand-in"
        der = request(sock, OP_SIGN, msg)
        try:
            relay_pub.verify(der, msg, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            print("[2] SIGN FAILED: signature does not verify against the slot public key")
            sys.exit(1)
        print(f"[2] SIGN ok: {len(der)}-byte DER signature verifies")

        # 3. ECDH: we are the "SE050"
        ours = ec.generate_private_key(ec.SECP256R1())
        our_point = ours.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        relay_secret = request(sock, OP_ECDH, our_point)
        local_secret = ours.exchange(ec.ECDH(), relay_pub)
        if relay_secret != local_secret:
            print("[3] ECDH FAILED: shared secrets differ")
            print(f"    relay={relay_secret.hex()}")
            print(f"    local={local_secret.hex()}")
            sys.exit(1)
        print(f"[3] ECDH ok: 32-byte shared secret matches ({relay_secret.hex()})")

    print("\nPASS -- all three HostEC operations validated against the YubiKey.")


if __name__ == "__main__":
    main()
