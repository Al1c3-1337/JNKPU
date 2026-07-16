# JNKPU-standalone

BitLocker Network Unlock (MS-NKPU) on Linux — **without a domain, without WDS, without Windows Server.**

A fork of [iprice/JNKPU](https://github.com/iprice/JNKPU) that adds a PKCS#11 key backend,
a protocol test harness, and a documented recipe for standalone (non-domain-joined) clients.

Verified end-to-end against real hardware: a Raspberry Pi 3B serving a Windows 11
workstation over Wi-Fi, with the RSA private key held in a YubiKey PIV slot.

---

## What this fork adds

**Standalone clients — no Active Directory.** Upstream assumes a domain
("assuming you have a TPM, PXE, wired network, Domain (Samba is fine)"). It turns out
you don't need one: `certutil -f -grouppolicy -addstore FVE_NKP` writes to the exact
registry store bootmgr reads, and seven `reg add` lines set the policy. Microsoft
documents this for Server 2012 R2 under "earlier versions", but nobody seems to have
written it up as a working end-to-end recipe. See [`client/`](client/).

**PKCS#11 key backend.** The key can live in a smartcard, HSM, or TPM instead of an
unencrypted PKCS#8 file. The private key never leaves the token; `getEncoded()` returns
null and every RSA operation happens on-device. Swap `--pkcs11-lib` to change backends —
tested with ykcs11 (YubiKey PIV) and SoftHSM; opensc-pkcs11 and tpm2-pkcs11 should work
unchanged.

**A protocol test harness.** [`NkpuProtocolTest`](src/test/java/net/coagulate/JNKPU/NkpuProtocolTest.java)
simulates a full NKPU client against the server: option 43+125 reassembly, RSA decrypt,
all three protocol errata, AES-CCM, and a round trip. It proves the entire crypto chain
without touching Windows, and runs unprivileged. If you are debugging an unlock that
doesn't work, run this first — it tells you whether the problem is your crypto or your
network.

**A bug fix worth knowing about.** Upstream calls `Cipher.getInstance("RSA")` — no
padding, no provider. The JCE resolves that alias per-provider, and BouncyCastle's
default is **NoPadding**. Upstream only uses BouncyCastle's lightweight API and never
registers the provider, so the bug is latent — but anything that registers BC first turns
NKPU into a silent garbage generator. Now pinned to `RSA/ECB/PKCS1Padding`, deliberately
without a provider, so the JCE picks SunJCE for a file key and SunPKCS11 for a token
handle. One string, both paths.
*(Submitted upstream separately as a minimal patch.)*

**PIN handling that doesn't cost you the key.** The PIV PIN retry counter is 3. Burn it
plus the PUK and the slot is gone. So: `--pkcs11-pin-stdin` keeps the PIN off every
filesystem and out of `/proc/<pid>/cmdline`; an empty PIN is refused rather than
submitted; there is no retry on failure; and the alias resolver refuses to guess when a
token holds several keys — picking "the first private key found" lands on the YubiKey's
sign-only attestation key in f9, which fails as `CKR_DEVICE_ERROR` and surfaces three
layers up as a padding error.

---

## Quick start

```bash
mvn package
sudo java -jar target/jnkpu.jar --noipv6 networkunlock.key
```

Prove the protocol before you touch Windows:

```bash
mvn test
```

Prove it against your actual token — this is what tells you whether your slot, your PIN
policy and your PKCS#11 module work, without rebooting anything:

```bash
mvn test -Djnkpu.pkcs11.lib=/usr/lib/aarch64-linux-gnu/libykcs11.so -Djnkpu.pkcs11.pin=<PIN>
```

Run with the token:

```bash
systemd-ask-password --timeout=0 "YubiKey PIN:" | sudo java -jar target/jnkpu.jar \
    --noipv6 --pkcs11-lib /usr/lib/aarch64-linux-gnu/libykcs11.so --pkcs11-pin-stdin
```

Windows side: [client setup](#windows-client-setup-no-domain). Token side:
[provisioning](#token-provisioning-yubikey-piv). For a proper install, build
the [Debian package](#debianubuntu-package) instead of copying jars around.

---

## Debian/Ubuntu package

```bash
sudo apt install debhelper maven default-jdk-headless   # build tools
./scripts/build-deb.sh                                  # or: dpkg-buildpackage -us -uc -b
sudo apt install ../jnkpu_1.2.0_all.deb
```

The first build downloads Maven dependencies, so it needs network. The
protocol tests run during the build; `DEB_BUILD_OPTIONS=nocheck` skips them.
CI builds and smoke-installs the package on every push.

Or skip building entirely: every push to master produces a
[tagged release](../../releases) with the `.deb`, the bare jar, and the
Windows client files as a zip (auto-versioned `v1.2.0`, `v1.2.0.1`, … —
bump `pom.xml` + `debian/changelog` to start a new series).

What lands where:

| Path | |
|---|---|
| `/usr/share/jnkpu/jnkpu.jar` | the server |
| `/usr/bin/jnkpu` | launcher: `sudo jnkpu --noipv6 /etc/jnkpu/networkunlock.key` |
| `/usr/bin/jnkpu-provision-token` | PFX → YubiKey, see [token provisioning](#token-provisioning-yubikey-piv) |
| `/etc/default/jnkpu` | service configuration: backend, PIN prompt |
| `/etc/jnkpu/` | key directory for the file backend, mode 700 |
| `jnkpu.service` | systemd unit — installed **disabled**, on purpose |

Dependencies are wired into the package: a Java 11+ runtime is the only hard
dependency. `pcscd`, `ykcs11`, `yubikey-manager` and `openssl` — everything the
token path and `jnkpu-provision-token` need — are Recommends, so apt pulls them
by default and a file-backend-only server can drop them with
`--no-install-recommends`. `opensc-pkcs11` and `softhsm2` are Suggests.

The unit ships disabled because a fresh install has no key. Pick a backend in
`/etc/default/jnkpu`, put the key in place (or the token in its slot), then:

```bash
sudo systemctl enable --now jnkpu
sudo systemd-tty-ask-password-agent --query   # answer the PIN prompt, e.g. over SSH
```

The packaged unit reads `/etc/default/jnkpu` instead of hardcoding paths; the
unit in [`systemd/`](systemd/) is the same service as a hand-install `/opt`
variant, kept for the copy-a-jar-to-a-Pi workflow.

---

## Windows client setup (no domain)

Everything referenced here lives in [`client/`](client/). Run on the Windows machine you
want to unlock, elevated. **Before you start: have the BitLocker recovery key somewhere
offline.** From here on you are editing `HKLM\SOFTWARE\Policies\Microsoft\FVE`.

**1. Create the certificate.**

```
certreq.exe -new client\BitLocker-NetworkUnlock.inf BitLocker-NetworkUnlock.cer
```

Self-signed, 2048-bit RSA, Key Encipherment, EKU `1.3.6.1.4.1.311.67.1.1` (BitLocker
Network Unlock), 25 years, machine store. The `.inf` is the current CNG variant from the
Microsoft docs; if certreq complains, add `KeySpec=1` to `[NewRequest]` — an old errata
note.

**2. Export the private key for the server.** certreq put the keypair in
`LocalMachine\My`, exportable:

```powershell
$c = Get-ChildItem Cert:\LocalMachine\My | Where-Object Subject -like '*Network Unlock*'
Export-PfxCertificate -Cert $c -FilePath BitLocker-NetworkUnlock.pfx `
    -Password (Read-Host -AsSecureString 'PFX password')
```

This PFX is what [token provisioning](#token-provisioning-yubikey-piv) consumes. Once
the unlock works end to end, delete the entry from `certlm.msc` → Personal — the machine
that gets unlocked should not itself hold the key that unlocks it. The `.cer` and the
FVE_NKP copy keep the public half; the private key belongs on the token and in the
offline backup, nowhere else.

**3. Install certificate and policy.**

```
client\setup.cmd BitLocker-NetworkUnlock.cer
```

Two things happen, and they are the entire no-domain trick:

- `certutil -f -grouppolicy -addstore FVE_NKP` writes the certificate into the exact
  registry store bootmgr reads. It has to be certutil: the store is a serialized
  CryptoAPI store, not raw DER, so `reg add` can't build it.
- Seven `reg add` lines set the policy: `OSManageNKP=1` (the running Windows creates the
  protector itself), `UseAdvancedStartup=1`, and the five `UsePIN`/`UseTPM*` values
  to 2 = *allow* (0 = disallow, 1 = require). Set `UsePIN=1` instead if you want to
  *require* TPM+PIN as the fallback.

**4. Reboot twice.** `OSManageNKP=1` means the protector is created by a running Windows
under active policy: reboot 1 creates it, reboot 2 uses it.

**5. Verify.**

```
client\verify.cmd
```

Or by hand: `manage-bde -protectors -get C:` must list **Network (Certificate Based)**
(type `TpmCertificate`, 9), and the entry name under
`HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\FVE_NKP\Certificates` must equal
the certificate's SHA-1 thumbprint.

---

## Token provisioning (YubiKey PIV)

[`scripts/jnkpu-provision-token`](scripts/jnkpu-provision-token) — installed into
`/usr/bin` by the [Debian package](#debianubuntu-package) — takes the PFX from client
step 2 onto the token:

```bash
jnkpu-provision-token BitLocker-NetworkUnlock.pfx [backup-dir]
```

It needs `yubikey-manager` and `openssl`; the package Recommends both.

What it does, in order — the pauses are deliberate:

1. **ROCA check** (CVE-2017-15361). YubiKey firmware 4.2.6–4.3.4 generates broken RSA
   keys **on-chip**. This script only *imports*, which is unaffected — but it shows
   `ykman info` so you know never to generate on such a device.
2. Extracts key and certificate from the PFX and converts the key to **PKCS#8 DER** —
   the file backend reads the file raw into `PKCS8EncodedKeySpec`, so PEM won't load
   (see [traps](#traps-so-you-dont-rediscover-them)).
3. Writes a backup (`chmod 600`, directory `700`): `networkunlock.key` (DER — runs
   directly on the file backend), `networkunlock-backup.pem` (reimport after a PIV
   reset; the thumbprint stays the same, the client never notices), and
   `networkunlock.crt`. **Store it offline, next to the BitLocker recovery key** — and
   not in a password manager on the machine this thing unlocks.
4. Stops so you can set the PUK and PIN first: `ykman piv access change-puk` /
   `change-pin`. PIN and PUK have 3 attempts each; both exhausted means PIV reset means
   empty slot. Recoverable — but only if the backup from step 3 actually exists.
5. Imports the key into **slot 9d** (Key Management) with `--pin-policy=ONCE`
   (once per card session — a PIN prompt per decrypt would break unattended unlocks)
   and `--touch-policy=NEVER` (nobody is standing next to the server at boot). The pin
   policy is **immutable after import** — decide before, not after.
6. Imports the certificate into the same slot. Without a certificate in the slot the
   key is invisible to the Java KeyStore — that's the JCA, not a bug.

Sensible staging: bring the server up on the file backend first
(`java -jar jnkpu.jar --noipv6 networkunlock.key`), prove the unlock end to end, then
switch to `--pkcs11-lib`. Same key, same thumbprint — the client can't tell the
difference, so any new failure is the token path.

---

## Traps, so you don't rediscover them

| Symptom | Cause |
|---|---|
| `Could not find or load main class` | Stale `/opt/jnkpu`. Rebuild, then copy the jar. |
| `InvalidKeySpecException` on the key file | It's PEM. The loader wants **DER**. Upstream says "PKCS8, no password" and omits this. |
| KeyStore empty although the key is in the slot | No **certificate** in that slot. Without one the key is invisible to the Java KeyStore. Not a bug — that's the JCA. |
| `CKR_DEVICE_ERROR` → `BadPaddingException` | Wrong slot. YubiKey f9 (attestation) is sign-only. Use 9d, Key Management. |
| `CKR_FUNCTION_FAILED` → `BadPaddingException` | Client and server are on different slots. |
| Decrypt fails via ykcs11 | Try `opensc-pkcs11.so`. Two independent modules is the point of PIV. |
| No protector after reboot | FVE_NKP store empty, or the policy didn't apply. You need **two** reboots: `OSManageNKP=1` means the running Windows creates the protector, so reboot 1 creates it and reboot 2 uses it. |
| Client broadcasts, server silent | Thumbprint mismatch, or wrong certificate. |
| Another DHCP server answers | The third client packet carries no message-type option, so BOOTP-capable servers answer it and break the unlock. Set them to DHCP-only. |
| 48-digit recovery prompt | PCRs changed (firmware update, mainboard). Not automatable. |
| `Failed to query password: Timer expired` | `systemd-ask-password` defaults to 90s. Use `--timeout=0`. |
| `Not querying ... lacking privileges` | Run the agent with sudo — the prompt belongs to a root process. |
| pcscd works only as root | polkit, not file permissions. Debian's default refuses non-local sessions, and SSH counts as non-local. Add a polkit rule allowing your user `org.debian.pcsc-lite.access_pcsc` and `access_card`. |

**UEFI:** native mode, CSM **off**, network stack on, DHCP on the **first** NIC, wired,
TPM enabled. The network stack alone is the documented requirement — PXE in the boot
order is not needed, though some firmware only initialises the DHCP driver when PXE is
enabled. If PXE boot works, the UEFI DHCP driver works; that isolates firmware from
everything else.

---

## Protocol errata

Undocumented, from a 2016 MSDN thread. The spec claims 32/48 bytes; reality is 60.
Upstream already had these right — its author credits Edgar Olougouna of Microsoft, the
same person who described them in that thread.

1. A 12-byte header precedes the 32-byte CK: `2c 00 00 00 01 00 00 00 06 20 00 00`
2. AES-CCM with a 12-byte nonce and a 16-byte tag
3. The MAC goes at the **front**, not the end

Key material is DHCP option 43 (0x2B) concatenated with option 125 (0x7D) = 256-byte ADM.

`ErrataTest` asserts all three.

---

## Security notes

**This is a convenience path, not a security gain.** The fallback stays TPM+PIN. If the
server is down, someone types a PIN. Design accordingly — the failure modes that matter
are the ones that lock *you* out.

**No client restriction.** The server answers any valid request on the network. No
allowlist, no subnet filter. Fine on a home LAN; know it before you deploy it elsewhere.

**NKPU is structurally a Bleichenbacher oracle.** Anyone on the LAN can broadcast
arbitrary 256-byte blobs; the server answers on success and stays silent on a padding
failure. SunJCE and hardware tokens have countermeasures. Practically irrelevant — an
attacker would need millions of queries on your LAN to recover a key that is worthless
without your TPM — but it is the reason not to hand-roll RSA here.

**A token protects against exfiltration from a running, compromised server.** That is
the whole delta over a key file on an encrypted volume. It is real but modest. If you
back the key up (you should), "non-extractable" becomes half a truth: security is now
`min(token, backup storage)`.

---

## Changes from upstream

Fork point: [iprice/JNKPU](https://github.com/iprice/JNKPU) @ 1.0.0 (2017-08-30).
This fork: 1.2.0.

Dependency note: upstream's README says to fetch `bcprov` **and** `bcpkix`. Only
`bcprov` is used — the code touches nothing but BouncyCastle's lightweight crypto API.

| File | |
|---|---|
| `Cryptography.java` | RSA transform pinned to PKCS#1 v1.5; `setPrivateKey()` with preflight |
| `NetworkUnlock.java` | PKCS#11 backend, `--pkcs11-lib/-slot/-pin/-pin-stdin/-alias` |
| `DHCPv4.java` | package-private no-bind constructor for testing |
| `Pkcs11Loader.java` | **new** — token backend, alias resolution |
| `NkpuProtocolTest.java` | **new** — protocol test harness (JUnit, runs in CI) |
| `pom.xml` | **new** — Maven build, fat jar, CI |
| `scripts/`, `client/`, `systemd/`, `debian/`, `.github/` | **new** |
| layout | moved to Maven's `src/main/java` / `src/test/java` |
| `DHCPv6.java`, `Listener.java`, `UnlockException.java` | unchanged |

---

## License

GPLv3 or later, inherited from upstream — the original README states
"this work is covered under the GPLv3 or later". Upstream ships no LICENSE file; the
canonical text is included here for clarity. Original code © 2017 Iain Price;
modifications © 2026 {AUTHOR}. Each source file carries a notice of what changed.

Upstream's caveat, passed on: *"you may run into patent issues if you attempt to
commercially redistribute this. Please see Microsoft open protocols, patents, etc pages
for more information."* MS-NKPU is published under the Microsoft Open Specifications
Promise, which is why implementing it is legitimate — but read the OSP yourself rather
than taking a README's word for it.

## Credits

**Iain Price** — the original JNKPU. The errata are implemented correctly there; this
fork would not exist without it.

**Edgar Olougouna (Microsoft)** — documented the protocol errata that the specification
omits.
