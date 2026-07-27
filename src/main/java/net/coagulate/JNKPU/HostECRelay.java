/*
 * JNKPU - Java Network Key Protector Unlocker (MS-NKPU)
 *
 * Copyright (C) 2026 {AUTHOR}
 *
 * Not part of the original JNKPU by Iain Price; added 2026.
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * ---
 * HostEC relay for the nu-armory ECKey session.
 *
 * Serves the three HostEC operations (GET_PUBKEY / SIGN / ECDH) over a TCP
 * socket, backed by a YubiKey PIV slot (9a) via the SAME SunPKCS11 login that
 * JNKPU uses for the NKPU RSA key (slot 9d). One PIN, both slots.
 *
 * Wire protocol (see docs/hostec-ble-protocol.md):
 *   request  : [op:1][len:2 BE][payload]
 *   response : [status:1][len:2 BE][payload]
 *
 * This is the TCP reference; the on-dongle transport is BLE, but the framing and
 * the crypto contracts are identical, so the Pi/YubiKey side is validated here
 * first with test_relay.py before the BLE layer is added.
 *
 * GPLv3, as the rest of JNKPU.
 */
package net.coagulate.JNKPU;

import javax.crypto.KeyAgreement;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class HostECRelay {

    static final int OP_PUBKEY = 0x01, OP_SIGN = 0x02, OP_ECDH = 0x03;
    static final int ST_OK = 0x00, ST_ERR = 0x01, ST_PIN = 0x02, ST_NOKEY = 0x03;

    public static void main(String[] args) throws Exception {
        String lib = null, alias = null, pinFile = null, bind = "127.0.0.1";
        int slot = 0, port = 7213;
        boolean pinStdin = false;
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--pkcs11-lib":       lib = args[++i]; break;
                case "--pkcs11-slot":      slot = Integer.parseInt(args[++i]); break;
                case "--pkcs11-alias":     alias = args[++i]; break;
                case "--pkcs11-pin":       pinFile = args[++i]; break;
                case "--pkcs11-pin-stdin": pinStdin = true; break;
                case "--port":             port = Integer.parseInt(args[++i]); break;
                case "--bind":             bind = args[++i]; break;
                default: System.err.println("unknown arg: " + args[i]); usage(); return;
            }
        }
        if (lib == null) { System.err.println("--pkcs11-lib is required"); usage(); return; }

        String pin = readPin(pinStdin, pinFile);

        // Same login mechanism as JNKPU's Pkcs11Loader: SunPKCS11 KeyStore + PIN.
        Provider prov = Security.getProvider("SunPKCS11")
                .configure("--name=JNKPU-relay\nlibrary=" + lib + "\nslotListIndex=" + slot + "\n");
        Security.addProvider(prov);
        KeyStore ks = KeyStore.getInstance("PKCS11", prov);
        ks.load(null, pin == null ? null : pin.toCharArray());

        String a = resolveAuthAlias(ks, alias);
        PrivateKey key = (PrivateKey) ks.getKey(a, null);
        Certificate cert = ks.getCertificate(a);
        if (!(cert.getPublicKey() instanceof ECPublicKey)) {
            throw new KeyStoreException("Slot '" + a + "' is not an EC key. Use the P-256 auth slot (9a).");
        }
        ECPublicKey pub = (ECPublicKey) cert.getPublicKey();
        byte[] pubPoint = encodePoint(pub);
        System.out.println("HostECRelay: key '" + a + "' "
                + (key.getEncoded() == null ? "(non-extractable)" : "(WARNING: extractable!)")
                + ", public point " + pubPoint.length + " bytes");

        try (ServerSocket srv = new ServerSocket(port, 1, InetAddress.getByName(bind))) {
            System.out.println("HostECRelay: listening on " + bind + ":" + port);
            while (true) {
                try (Socket s = srv.accept()) {
                    serve(s, prov, key, pub.getParams(), pubPoint);
                } catch (Exception e) {
                    System.err.println("connection error: " + e);
                }
            }
        }
    }

    private static void serve(Socket s, Provider prov, PrivateKey key,
                              ECParameterSpec params, byte[] pubPoint) throws IOException {
        DataInputStream in = new DataInputStream(new BufferedInputStream(s.getInputStream()));
        OutputStream out = new BufferedOutputStream(s.getOutputStream());
        while (true) {
            int op;
            try { op = in.readUnsignedByte(); } catch (EOFException eof) { return; }
            int len = in.readUnsignedShort();
            byte[] payload = new byte[len];
            in.readFully(payload);
            try {
                byte[] resp = dispatch(op, payload, prov, key, params, pubPoint);
                write(out, ST_OK, resp);
            } catch (PinException pe) {
                System.err.println("op " + op + " PIN error: " + pe.getMessage());
                write(out, ST_PIN, new byte[0]);
            } catch (Exception e) {
                System.err.println("op " + op + " failed: " + e);
                write(out, ST_ERR, new byte[0]);
            }
            out.flush();
        }
    }

    private static byte[] dispatch(int op, byte[] payload, Provider prov, PrivateKey key,
                                   ECParameterSpec params, byte[] pubPoint) throws Exception {
        switch (op) {
            case OP_PUBKEY:
                return pubPoint;
            case OP_SIGN: {
                Signature sig = Signature.getInstance("SHA256withECDSA", prov);
                sig.initSign(key);
                sig.update(payload);          // payload = A6||7F49 bytes; SHA-256 done here
                return sig.sign();            // ASN.1 DER SEQUENCE{r,s}
            }
            case OP_ECDH: {
                ECPublicKey peer = decodePoint(payload, params);
                KeyAgreement ka = KeyAgreement.getInstance("ECDH", prov);
                ka.init(key);
                ka.doPhase(peer, true);
                return ka.generateSecret();   // 32-byte shared X (IEEE P1363)
            }
            default:
                throw new IllegalArgumentException("unknown op 0x" + Integer.toHexString(op));
        }
    }

    // ---- helpers ------------------------------------------------------------

    static class PinException extends Exception { PinException(String m){ super(m); } }

    private static void write(OutputStream out, int status, byte[] payload) throws IOException {
        out.write(status);
        out.write((payload.length >> 8) & 0xFF);
        out.write(payload.length & 0xFF);
        out.write(payload);
    }

    /** 65-byte uncompressed point 0x04 || X(32) || Y(32). */
    private static byte[] encodePoint(ECPublicKey pub) {
        byte[] x = i2osp(pub.getW().getAffineX(), 32);
        byte[] y = i2osp(pub.getW().getAffineY(), 32);
        byte[] p = new byte[65];
        p[0] = 0x04;
        System.arraycopy(x, 0, p, 1, 32);
        System.arraycopy(y, 0, p, 33, 32);
        return p;
    }

    private static ECPublicKey decodePoint(byte[] p, ECParameterSpec params) throws GeneralSecurityException {
        if (p.length != 65 || p[0] != 0x04) {
            throw new InvalidKeyException("expected 65-byte uncompressed P-256 point");
        }
        BigInteger x = new BigInteger(1, java.util.Arrays.copyOfRange(p, 1, 33));
        BigInteger y = new BigInteger(1, java.util.Arrays.copyOfRange(p, 33, 65));
        KeyFactory kf = KeyFactory.getInstance("EC");
        return (ECPublicKey) kf.generatePublic(new ECPublicKeySpec(new ECPoint(x, y), params));
    }

    private static byte[] i2osp(BigInteger v, int len) {
        byte[] b = v.toByteArray();
        if (b.length == len) return b;
        byte[] out = new byte[len];
        if (b.length > len) { // strip leading sign byte(s)
            System.arraycopy(b, b.length - len, out, 0, len);
        } else {
            System.arraycopy(b, 0, out, len - b.length, b.length);
        }
        return out;
    }

    private static String readPin(boolean stdin, String file) throws IOException {
        if (stdin) {
            BufferedReader r = new BufferedReader(new InputStreamReader(System.in));
            String pin = r.readLine();
            if (pin == null || pin.trim().isEmpty()) throw new IOException("empty PIN on stdin");
            return pin.trim();
        }
        if (file != null) return new String(Files.readAllBytes(Paths.get(file))).trim();
        return null; // no PIN (token may cache it) -- ks.load will fail if one is required
    }

    /** Pick the P-256 authentication key (PIV 9a): explicit alias, or the one whose
     *  alias contains "Authentication" but not "Card Authentication" (9e). */
    private static String resolveAuthAlias(KeyStore ks, String requested) throws GeneralSecurityException {
        List<String> privs = new ArrayList<>();
        for (String x : Collections.list(ks.aliases())) {
            if (ks.getKey(x, null) instanceof PrivateKey) privs.add(x);
        }
        if (requested != null) {
            if (!privs.contains(requested)) throw new KeyStoreException("alias '" + requested + "' not found; available: " + privs);
            return requested;
        }
        List<String> hit = new ArrayList<>();
        for (String x : privs) {
            String l = x.toLowerCase();
            if (l.contains("authentication") && !l.contains("card")) hit.add(x);
        }
        if (hit.size() == 1) return hit.get(0);
        throw new KeyStoreException("cannot auto-select the 9a auth key; pass --pkcs11-alias. candidates: " + privs);
    }

    private static void usage() {
        System.err.println("HostECRelay --pkcs11-lib PATH [--pkcs11-slot N] [--pkcs11-alias A]");
        System.err.println("            [--pkcs11-pin-stdin | --pkcs11-pin FILE] [--bind IP] [--port N]");
    }
}
