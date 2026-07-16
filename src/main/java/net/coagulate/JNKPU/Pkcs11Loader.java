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

import java.security.*;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Loads the NKPU private key from a PKCS#11 token (YubiKey PIV slot 9d, HSM, ...)
 *  instead of an unencrypted PKCS8 file on disk.
 *  The key handle is non-extractable: getEncoded() returns null and every RSA
 *  decrypt happens on the token.
 */
public class Pkcs11Loader {

    /** Key plus the certificate from the SAME alias. Handing both out together is
     *  deliberate: if the caller resolves the certificate separately it can end up
     *  on a different object than the key, and then the client encrypts against one
     *  slot while the server decrypts with another. That failure looks like a
     *  protocol bug and is miserable to find. */
    public static class Handle {
        public final PrivateKey key;
        public final Certificate cert;
        public final String alias;
        Handle(PrivateKey k, Certificate c, String a) { key=k; cert=c; alias=a; }
    }

    public static Handle open(String library, int slotIndex, String pin, String alias)
            throws GeneralSecurityException, java.io.IOException {

        Provider p = Security.getProvider("SunPKCS11")
                .configure("--name=JNKPU\nlibrary=" + library + "\nslotListIndex=" + slotIndex + "\n");
        Security.addProvider(p);

        KeyStore ks = KeyStore.getInstance("PKCS11", p);
        ks.load(null, pin == null ? null : pin.toCharArray());

        String resolved = resolveAlias(ks, alias);
        PrivateKey key = (PrivateKey) ks.getKey(resolved, null);
        Certificate cert = ks.getCertificate(resolved);

        NetworkUnlock.logger.info("Using PKCS#11 key '" + resolved + "' via " + p.getName()
                + (key.getEncoded() == null ? " (non-extractable)" : " (WARNING: extractable!)"));
        return new Handle(key, cert, resolved);
    }

    /** @param alias key alias in the token, or null to auto-detect */
    public static PrivateKey load(String library, int slotIndex, String pin, String alias)
            throws GeneralSecurityException, java.io.IOException {
        return open(library, slotIndex, pin, alias).key;
    }

    /** Picking "the first private key found" is a lottery on any multi-slot token.
     *  A YubiKey exposes up to five PIV slots, and the attestation key in f9 is
     *  sign-only: C_Decrypt on it fails with CKR_DEVICE_ERROR, which surfaces as a
     *  padding error three layers up. So: resolve by name, and refuse to guess when
     *  it is ambiguous. */
    private static String resolveAlias(KeyStore ks, String requested) throws GeneralSecurityException {
        List<String> privs = new ArrayList<>();
        for (String a : Collections.list(ks.aliases())) {
            if (ks.getKey(a, null) instanceof PrivateKey) { privs.add(a); }
        }
        if (privs.isEmpty()) {
            throw new KeyStoreException("No private key found in token.\n"
                + "  A certificate must be present in the SAME slot, otherwise the key is\n"
                + "  invisible to the Java KeyStore:  ykman piv certificates import 9d cert.pem");
        }
        if (requested != null) {
            if (!privs.contains(requested)) {
                throw new KeyStoreException("Alias '" + requested + "' not found.\n  Available: " + privs);
            }
            return requested;
        }
        // PIV: slot 9d "Key Management" is the decrypt slot. 9a/9c/9e/f9 are the wrong ones.
        List<String> km = new ArrayList<>();
        for (String a : privs) { if (a.contains("Key Management")) { km.add(a); } }
        if (km.size() == 1) {
            NetworkUnlock.logger.info("Auto-selected PIV Key Management slot (9d) from " + privs.size()
                + " keys: " + km.get(0));
            return km.get(0);
        }
        if (privs.size() == 1) {
            // Der Attestation-Key ist NIE die richtige Antwort: er ist sign-only, und
            // C_Decrypt darauf gibt CKR_DEVICE_ERROR - das taucht drei Schichten hoeher
            // als BadPaddingException auf und schickt einen auf die Padding-Faehrte.
            if (privs.get(0).contains("Attestation")) {
                throw new KeyStoreException("Only key in token is the PIV attestation key (slot f9).\n"
                    + "  That key is sign-only; decrypting with it fails as CKR_DEVICE_ERROR.\n"
                    + "  Slot 9d is empty - the import never ran:\n"
                    + "    ykman piv keys import --pin-policy=ONCE --touch-policy=NEVER 9d key.pem\n"
                    + "    ykman piv certificates import 9d cert.pem");
            }
            return privs.get(0);
        }
        throw new KeyStoreException("Ambiguous: " + privs.size() + " private keys and no obvious\n"
            + "  Key Management slot. Refusing to guess - pick one with --pkcs11-alias:\n  " + privs);
    }
}
