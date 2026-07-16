/*
 * JNKPU - Java Network Key Protector Unlocker (MS-NKPU)
 *
 * Copyright (C) 2017 Iain Price
 * Copyright (C) 2026 {AUTHOR}
 *
 * Modified 2026: pinned the RSA transform to PKCS#1 v1.5 (upstream used the bare
 * "RSA" alias, whose padding depends on which provider wins) and added an entry
 * point for externally supplied, non-extractable keys.
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

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.modes.CCMModeCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

/**  Cryptographic hooks for NKPU.
 *
 * @author Iain Price
 */
public class Cryptography {
    
    /** Initialise the crypto
     * Loads the private key and makes sure it will perform
     * @param filename The private key, in PKSC8 format, with no password
     */
    public static void init(String filename) {
        try {
            loadPrivateKey(filename);
            Cipher rsa=Cipher.getInstance(TRANSFORM);
            rsa.init(Cipher.DECRYPT_MODE,key);
        } catch (NoSuchPaddingException|NoSuchAlgorithmException ex) {
            System.err.println("Failed to load RSA algorithm - "+ex); System.exit(1);
        } catch (InvalidKeyException ex) {
            System.err.println("Failed to initialise RSA cipher with key - "+ex); System.exit(1);
        }
    }

    /** MS-NKPU uses PKCS#1 v1.5. NEVER use the bare "RSA" alias: its meaning depends on
     *  which provider wins, and BouncyCastle's default is NoPadding, which would silently
     *  return garbage. No provider is pinned here on purpose - the JCE resolves the provider
     *  at init() from the key, so this one string works for both a file key (SunJCE) and a
     *  PKCS#11 token handle (SunPKCS11).
     */
    private static final String TRANSFORM="RSA/ECB/PKCS1Padding";

    private static PrivateKey key=null;

    /** Set the private key from an external source (e.g. a PKCS#11 token).
     * The key never needs to exist as bytes on disk.
     * @param k A PrivateKey, possibly a non-extractable hardware-backed handle.
     */
    public static void setPrivateKey(PrivateKey k) {
        key=k;
        try {
            Cipher rsa=Cipher.getInstance(TRANSFORM);
            rsa.init(Cipher.DECRYPT_MODE,key);
            NetworkUnlock.logger.info("RSA preflight OK, provider="+rsa.getProvider().getName()
                +", transform="+TRANSFORM);
        } catch (Exception e) {
            System.err.println("FATAL: supplied key cannot perform "+TRANSFORM+" - "+e);
            System.exit(1);
        }
    }

    /** Load the actual key
     * 
     * @param filename Filename of the private key (PKCS8, No password)
     */
    public static void loadPrivateKey(String filename) {
        File f=new File(filename);
        FileInputStream fis;
        try {
            fis = new FileInputStream(f);
            byte[] rawkey;
            try (DataInputStream dis = new DataInputStream(fis)) {
                rawkey = new byte[(int)f.length()];
                dis.readFully(rawkey);
            }
            PKCS8EncodedKeySpec keyspec=new PKCS8EncodedKeySpec(rawkey);
            KeyFactory kf=KeyFactory.getInstance("RSA");
            key=kf.generatePrivate(keyspec);
        } catch (FileNotFoundException ex) {
            System.err.println("Unable to load private key file "+filename+", file not found?");
            System.exit(1);
        } catch (IOException ex) {
            System.err.println("IOException loading private key:"+ ex);
            System.exit(1);
        } catch (NoSuchAlgorithmException ex) {
            System.err.println("Failed to load RSA encryption provider, check your Java installation (? - "+ ex +")");
            System.exit(1);
        } catch (InvalidKeySpecException ex) {
            System.err.println("Invalid private key - is it in PKCS8 format with no password? ("+ ex +")");
            System.exit(1);
        }
    }

    /** Decrypt client provided RSA payload
     * The client sends us the CK+SK all encrypted with our public key.  Here we decrypt that payload.
     * @param clientpayload The encrypted CK+SK payload
     * @return The decrypted CK+SK payload
     */
    static byte[] decrypt(byte[] clientpayload) throws UnlockException {
        try {
            Cipher rsa=Cipher.getInstance(TRANSFORM);
            rsa.init(Cipher.DECRYPT_MODE,key);
            return rsa.doFinal(clientpayload);
        }
        catch (NoSuchAlgorithmException ex) {
            throw new UnlockException("Failed to load RSA algorithm?  After pre-flight checks passed?",ex);
        } catch (NoSuchPaddingException ex) {
            throw new UnlockException("Failed to load padding type? After pre-flight checks passed?",ex);
        }   catch (InvalidKeyException ex) {
            throw new UnlockException("Invalid key exception? After pre-flight checks passed?",ex);
        }   catch (IllegalBlockSizeException ex) {
            throw new UnlockException("Illegal block size in payload",ex);
        } catch (BadPaddingException ex) {
            throw new UnlockException("Bad padding in payload",ex);
        }
    }
    /** Encrypt reply as client requires.
     * Uses AES-CCM with 256bit AES key, zero nonce (12 bytes) and a MAC.
     * @param sk AES256 Key (Session Key)
     * @param headeredck Plaintext (Client Key with prepended header)
     * @return The AES-CCM encrypted form of headeredck encrypted with the SK, as per protocol specifications.
     * @throws UnlockException I/O error
     */
    static byte[] encrypt(byte[] sk, byte[] headeredck) throws UnlockException {
        try {
            if (headeredck.length!=44) { throw new UnlockException("We expected 44 bytes of data to encrypt, 12 byte header + 32 byte CK, but got "+headeredck.length+" bytes to encrypt"); }
            // the response uses 12 bytes of zero nonce
            byte[] nonce=new byte[12];
            // and no additional authenticate traffic
            byte[] empty=new byte[0];
            // the mode is AES-CCM with 256bit AES, roughly defined in rfc3610, called AES-CCM-CBC or counter with mac, and various other things.
            // note the microsoft implementation stores the MAC at the start of the encrypted reply, rather than at the end, which is what we will end up getting here from BouncyCastle.
            // the main receiver code handles the re-ordering

            // a CCM engine, based around AES
            CCMModeCipher ccm=CCMBlockCipher.newInstance(AESEngine.newInstance());
            // the relevant parameters - the key, 16 octets of MAC, 12 byte zero nonce, and no additional authenticated data
            ccm.init(true,new AEADParameters(new KeyParameter(sk),16*8,nonce,empty));
            // output must be this long given the 44 byte input
            byte[] out=new byte[60];
            ccm.processBytes(headeredck,0,headeredck.length,out,0);
            ccm.doFinal(out,0);
            return out;
        } catch (IllegalStateException ex) {
            throw new UnlockException("AES-CCM reported illegal state?",ex);
        } catch (InvalidCipherTextException ex) {
            throw new UnlockException("Encrypting reply failed",ex);
        }
    }

    /** Convert between BouncyCastle ordering and MS ordering.
     * Unlike the RFC's recommendation, Microsoft put the MAC at the start of the payload, while implementations
     * (including BouncyCastle, and also the Scandium implementation used by Eclipse's Californium)
     * place the MAC after the message (which probably makes sense given stream ciphers are involved).
     * Here, we reorganise the payload and move the 16 byte MAC to the start, followed by the 44 byte payload.
     * @param responsepayload The CRYPT+MAC ordered payload
     * @return The payload in MAC+CRYPT format, as required by Bitlocker
     */
    static byte[] reorderMac(byte[] responsepayload) {
        // MAC goes on start...
        byte[] out=new byte[responsepayload.length];
        System.arraycopy(responsepayload,44,out,0,16);
        System.arraycopy(responsepayload,0,out,16,44);
        return out;
    }
}
