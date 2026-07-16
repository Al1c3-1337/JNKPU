/*
 * JNKPU - Java Network Key Protector Unlocker (MS-NKPU)
 *
 * Copyright (C) 2017 Iain Price
 * Copyright (C) 2026 {AUTHOR}
 *
 * Modified 2026: added a PKCS#11 key backend and the CLI to drive it.
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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.logging.Logger;

/** Implements MS-NKPU.
 * Network Key Protector Unlocker, for unlocking Bitlocker encrypted drives.
 * Requires BouncyCastle for crypto.
 * Key backends:
 *   - file:    PKCS8 DER (NOT PEM), unencrypted
 *   - pkcs11:  YubiKey PIV slot 9d via ykcs11/opensc-pkcs11, or any other PKCS#11 token
 *
 * @author Iain Price (original), PKCS#11 backend added later
 */
public class NetworkUnlock {

    public static final Logger logger=Logger.getLogger("net.coagulate.JNKPU");

    @SuppressWarnings("unused")
    public static final boolean DEBUG=false;
    public static final String VERSION="1.2.0-pkcs11";
    public static final String RELEASE="20260715";

    private static boolean startipv4=true;
    private static boolean startipv6=true;
    private static boolean strict=false;

    private static String keyfile=null;      // PKCS8 DER
    private static String p11lib=null;       // e.g. /usr/lib/libykcs11.so
    private static int    p11slot=0;
    private static String p11pinfile=null;   // file holding the PIN
    private static boolean p11pinstdin=false;  // read PIN from stdin (systemd-ask-password)
    private static String p11alias=null;

    public static void main(String[] args) {

        System.out.println("Java Network Key Protector Unlocker version "+VERSION+" ("+RELEASE+")");
        parseArguments(args);

        if (p11lib!=null) {
            String pin=null;
            if (p11pinstdin) {
                // The PIN never touches a filesystem, not even tmpfs, and never appears
                // in /proc/<pid>/cmdline. Feed it in with:
                //   systemd-ask-password "YubiKey PIN:" | java ... --pkcs11-pin-stdin
                try (java.io.BufferedReader r = new java.io.BufferedReader(
                        new java.io.InputStreamReader(System.in))) {
                    pin = r.readLine();
                } catch (IOException e) {
                    System.err.println("FATAL: cannot read PIN from stdin - "+e.getMessage());
                    System.exit(2);
                }
                if (pin==null || pin.trim().isEmpty()) {
                    System.err.println("FATAL: empty PIN on stdin. Refusing to attempt a login.");
                    System.exit(2);
                }
                pin = pin.trim();
            } else if (p11pinfile!=null) {
                // Read ONCE at startup. If the volume is not mounted this throws and we exit
                // non-zero. Do NOT retry: the PIV PIN retry counter is 3 and burning it costs
                // you the key.
                try {
                    pin=new String(Files.readAllBytes(Paths.get(p11pinfile))).trim();
                } catch (IOException e) {
                    System.err.println("FATAL: cannot read PIN file "+p11pinfile+" - "+e.getMessage());
                    System.err.println("       Is the encrypted volume mounted? NOT retrying on purpose.");
                    System.exit(2);
                }
                if (pin.isEmpty()) {
                    System.err.println("FATAL: PIN file is empty. Refusing to attempt a login.");
                    System.exit(2);
                }
            }
            try {
                System.out.println("Loading key from PKCS#11 token ("+p11lib+", slot index "+p11slot+")...");
                Cryptography.setPrivateKey(Pkcs11Loader.load(p11lib,p11slot,pin,p11alias));
            } catch (Exception e) {
                System.err.println("FATAL: PKCS#11 init failed - "+e);
                System.err.println("       NOT retrying: a wrong PIN costs 1 of 3 attempts.");
                System.exit(3);
            }
        } else {
            if (keyfile==null || keyfile.isEmpty()) {
                System.err.println("You must specify a key file or --pkcs11-lib"); usage(); System.exit(1);
            }
            System.out.println("Loading private key from file...");
            Cryptography.init(keyfile);
        }

        if (startipv4) {
            try {
                System.out.println("Starting DHCP listener on IPv4...");
                new DHCPv4().start();
            } catch (IOException e) {
                System.err.println("Failed to start IPv4 listener: "+e.getLocalizedMessage());
                if (strict) { System.exit(1); }
            }
        }
        if (startipv6) {
            try {
                System.out.println("Starting DHCP listener on IPv6...");
                new DHCPv6().start();
            } catch (IOException e) {
                System.err.println("Failed to start IPv6 listener: "+e.getLocalizedMessage());
                if (strict) { System.exit(1); }
            }
        }
        System.out.println("Startup is complete, ready to service requests.");
    }

    private static void usage() {
        System.out.println("Usage: java net.coagulate.JNKPU.NetworkUnlock [options] [keyfile]");
        System.out.println("  keyfile             PKCS8 *DER* private key, no password. NOT PEM.");
        System.out.println("  --pkcs11-lib PATH   use a PKCS#11 token instead of a key file");
        System.out.println("                      YubiKey:  /usr/lib/x86_64-linux-gnu/libykcs11.so");
        System.out.println("                      fallback: /usr/lib/.../opensc-pkcs11.so");
        System.out.println("  --pkcs11-slot N     slot list index (default 0)");
        System.out.println("  --pkcs11-pin-stdin  read the PIN from stdin. Never hits a filesystem and never");
        System.out.println("                      shows up in /proc/<pid>/cmdline. Pair with systemd-ask-password.");
        System.out.println("  --pkcs11-pin FILE   file containing the PIN. Do NOT pass the PIN itself here:");
        System.out.println("                      command line arguments are world-readable via /proc.");
        System.out.println("                      Omit when the key's PIN policy is NEVER.");
        System.out.println("  --pkcs11-alias A    key alias in the token (default: first private key found)");
        System.out.println("  --noipv4 / --noipv6 disable a listener");
        System.out.println("  --strict            exit if any listener fails to start");
    }

    private static void parseArguments(String[] args) {
        for (int i=0;i<args.length;i++) {
            String arg=args[i];
            if (arg.equalsIgnoreCase("--noipv4")) { startipv4=false; }
            else if (arg.equalsIgnoreCase("--noipv6")) { startipv6=false; }
            else if (arg.equalsIgnoreCase("--strict")) { strict=true; }
            else if (arg.equalsIgnoreCase("--pkcs11-lib"))   { p11lib=next(args,++i); }
            else if (arg.equalsIgnoreCase("--pkcs11-slot"))  { p11slot=Integer.parseInt(next(args,++i)); }
            else if (arg.equalsIgnoreCase("--pkcs11-pin"))   { p11pinfile=next(args,++i); }
            else if (arg.equalsIgnoreCase("--pkcs11-pin-stdin")) { p11pinstdin=true; }
            else if (arg.equalsIgnoreCase("--pkcs11-alias")) { p11alias=next(args,++i); }
            else if (arg.startsWith("--")) { System.err.println("Unknown parameter '"+arg+"'"); usage(); System.exit(1); }
            else { keyfile=arg; }
        }
    }

    private static String next(String[] args,int i) {
        if (i>=args.length) { System.err.println("Missing value"); usage(); System.exit(1); }
        return args[i];
    }
}
