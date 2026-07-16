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
 */
package net.coagulate.JNKPU;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Arrays;
import javax.crypto.Cipher;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.modes.CCMModeCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import static org.junit.jupiter.api.Assertions.*;

/** Simulates a complete MS-NKPU client against the server and asserts every step:
 *  option 43+125 reassembly, RSA decrypt, all three protocol errata, AES-CCM, and a
 *  round trip. Proves the crypto chain without touching Windows.
 *  Runs unprivileged - DHCPv4's test constructor skips binding port 67.
 *  Key file backend by default. To exercise a real token instead:
 *    mvn test -Djnkpu.pkcs11.lib=/usr/lib/aarch64-linux-gnu/libykcs11.so \
 *             -Djnkpu.pkcs11.pin=123456
 *  The public key then comes from the token's own certificate, not from a file
 *  alongside it: if client and server resolve to different slots the failure looks
 *  like a protocol bug and is miserable to find.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class NkpuProtocolTest {

    private static final byte[] CK = new byte[32];
    private static final byte[] SK = new byte[32];

    private byte[] adm, extracted, gotCK, gotSK, hck, enc, reordered, reply, recovered;

    @BeforeAll
    void runTheProtocol() throws Exception {
        String lib   = emptyToNull(System.getProperty("jnkpu.pkcs11.lib"));
        String pin   = emptyToNull(System.getProperty("jnkpu.pkcs11.pin"));
        String alias = emptyToNull(System.getProperty("jnkpu.pkcs11.alias"));
        int    slot  = Integer.parseInt(orDefault(System.getProperty("jnkpu.pkcs11.slot"), "0"));

        for (int i = 0; i < 32; i++) { CK[i] = (byte)(0xA0 + i); SK[i] = (byte)(0x10 + i); }

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        // Race-free, owner-only, cleaned up. A fixed path in /tmp breaks the moment
        // someone runs this once with sudo, and writing a private key to a predictable
        // world-writable path is a bad habit regardless.
        Path keyPath = Files.createTempFile("jnkpu-test-", ".key",
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        keyPath.toFile().deleteOnExit();
        Files.write(keyPath, kp.getPrivate().getEncoded());   // PKCS8, no password

        // --- client ---
        byte[] plain = new byte[64];
        System.arraycopy(CK, 0, plain, 0, 32);
        System.arraycopy(SK, 0, plain, 32, 32);

        PublicKey encPub = kp.getPublic();
        Pkcs11Loader.Handle handle = null;
        if (lib != null) {
            handle = Pkcs11Loader.open(lib, slot, pin, alias);
            assertNotNull(handle.cert, "alias '" + handle.alias
                + "' has no certificate - ykman piv certificates import 9d cert.pem");
            encPub = handle.cert.getPublicKey();
        }
        Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsa.init(Cipher.ENCRYPT_MODE, encPub);
        adm = rsa.doFinal(plain);

        byte[] pkt = buildRequest(adm);

        // --- server ---
        if (lib != null) { Cryptography.setPrivateKey(handle.key); }
        else             { Cryptography.init(keyPath.toString()); }

        DHCPv4 srv = new DHCPv4(false);   // no bind, no root
        extracted = srv.getPayload(pkt);

        byte[] dec = Cryptography.decrypt(extracted);
        gotCK = srv.getCK(dec);
        gotSK = srv.getSK(dec);

        hck       = srv.headerCK(gotCK);
        enc       = Cryptography.encrypt(gotSK, hck);
        reordered = Cryptography.reorderMac(enc);
        reply     = srv.constructPayload(reordered, pkt);

        // --- client verifies the reply. This is the step that actually matters:
        //     everything above can look right and still not unlock anything.
        recovered = clientDecryptReply(reordered, SK);
    }

    @Test @DisplayName("options 43 + 125 reassemble into the 256-byte ADM")
    void optionsReassemble() {
        assertNotNull(extracted, "getPayload returned null");
        assertEquals(256, extracted.length);
        assertArrayEquals(adm, extracted);
    }

    @Test @DisplayName("RSA decrypt recovers the client key")
    void rsaRecoversCK() { assertArrayEquals(CK, gotCK); }

    @Test @DisplayName("RSA decrypt recovers the session key")
    void rsaRecoversSK() { assertArrayEquals(SK, gotSK); }

    @Test @DisplayName("ERRATUM 1: a 12-byte header precedes the 32-byte CK")
    void erratum1Header() {
        assertEquals(44, hck.length, "expected 12 + 32 bytes");
        assertArrayEquals(
            new byte[]{0x2c,0,0,0,1,0,0,0,0x06,0x20,0,0},
            Arrays.copyOf(hck, 12),
            "header is undocumented and hard-coded; see README");
        assertArrayEquals(CK, Arrays.copyOfRange(hck, 12, 44));
    }

    @Test @DisplayName("ERRATUM 2: AES-CCM output is 60 bytes, not the 32/48 the spec claims")
    void erratum2Length() { assertEquals(60, enc.length, "44 payload + 16 MAC"); }

    @Test @DisplayName("ERRATUM 3: the MAC sits at the front, not the end")
    void erratum3MacAtFront() {
        // CCM emits ciphertext||tag; NKPU wants tag||ciphertext.
        assertArrayEquals(Arrays.copyOfRange(enc, 44, 60), Arrays.copyOf(reordered, 16));
        assertArrayEquals(Arrays.copyOf(enc, 44), Arrays.copyOfRange(reordered, 16, 60));
    }

    @Test @DisplayName("reply packet: option 43 wraps a 2-byte header around the 60-byte payload")
    void replyOptionStructure() {
        assertNotNull(reply);
        assertEquals(0x2b, reply[251] & 0xff, "option 43, vendor specific information");
        assertEquals(62,   reply[252] & 0xff, "option length = 2 byte sub-header + 60 byte payload");
        assertEquals(2,    reply[253] & 0xff, "reply code");
        assertEquals(60,   reply[254] & 0xff, "payload length - the errata value, not the 32/48 of the spec");
        assertEquals(0xff, reply[255 + 60] & 0xff, "END option");
    }

    @Test @DisplayName("round trip: the client recovers the original CK from the reply")
    void roundTrip() { assertArrayEquals(CK, recovered, "full protocol round trip failed"); }

    /** The client half of erratum 3: undo the MAC reordering, then AES-CCM with a
     *  12-byte nonce and a 128-bit tag. If this returns the CK, the wire format is
     *  right - which is the only claim worth making. */
    private static byte[] clientDecryptReply(byte[] reordered, @SuppressWarnings("SameParameterValue") byte[] sessionKey) throws Exception {
        byte[] bcorder = new byte[60];
        System.arraycopy(reordered, 16, bcorder, 0, 44);   // body
        System.arraycopy(reordered, 0, bcorder, 44, 16);   // MAC back to where BC expects it

        CCMModeCipher ccm = CCMBlockCipher.newInstance(AESEngine.newInstance());
        ccm.init(false, new AEADParameters(new KeyParameter(sessionKey), 128, new byte[12], new byte[0]));
        byte[] out = new byte[ccm.getOutputSize(bcorder.length)];
        int n = ccm.processBytes(bcorder, 0, bcorder.length, out, 0);
        ccm.doFinal(out, n);
        return Arrays.copyOfRange(out, 12, 44);            // skip the 12-byte header
    }

    private static String emptyToNull(String s) { return (s == null || s.isEmpty()) ? null : s; }
    private static String orDefault(String s, @SuppressWarnings("SameParameterValue") String d) { return emptyToNull(s) == null ? d : s; }

    static byte[] buildRequest(byte[] adm) {
        byte[] p = new byte[700];
        int i = 236;
        p[0] = 1; p[1] = 1; p[2] = 6;
        p[4] = 0x11; p[5] = 0x22; p[6] = 0x33; p[7] = 0x44; // xid
        p[i++] = 0x63; p[i++] = (byte)0x82; p[i++] = 0x53; p[i++] = 0x63; // magic cookie
        // option 60 vendor class = BITLOCKER
        p[i++] = 60; p[i++] = 9;
        for (byte b : "BITLOCKER".getBytes()) p[i++] = b;
        // option 43: 0x01 + len 0x14 + 20-byte thumbprint, then 0x02 + len 128 + first half
        p[i++] = 0x2b; p[i++] = (byte)(2 + 20 + 2 + 128);
        p[i++] = 0x01; p[i++] = 0x14;
        for (int t = 0; t < 20; t++) p[i++] = (byte)t;      // SHA-1 thumbprint
        p[i++] = 0x02; p[i++] = (byte)128;
        System.arraycopy(adm, 0, p, i, 128); i += 128;
        // option 125: MS enterprise ID 0x00000137 + datalen + subopt + sublen + second half
        p[i++] = 0x7d; p[i++] = (byte)(4 + 3 + 128);
        p[i++] = 0x00; p[i++] = 0x00; p[i++] = 0x01; p[i++] = 0x37;
        p[i++] = (byte)130; p[i++] = 0x01; p[i++] = (byte)128;
        System.arraycopy(adm, 128, p, i, 128); i += 128;
        p[i++] = (byte)0xff; // END
        return Arrays.copyOf(p, i);
    }
}
