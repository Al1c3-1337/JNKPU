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
sps_bridge.py -- Pi-side BLE bridge for the nu-armory HostEC relay.

Exposes a u-blox Serial Port Service (SPS) peripheral over BlueZ and forwards
every byte to/from the local Java HostECRelay (TCP). It is a DUMB byte pipe: no
crypto, no framing awareness -- the dongle's relay.Client and the Java relay do
the framing; this just moves bytes between BLE (SPS FIFO) and localhost TCP.

    dongle (ANNA, SPS central)  <--BLE-->  sps_bridge  <--TCP-->  HostECRelay --> YubiKey

Requires: python3-dbus, python3-gi, BlueZ >= 5.48, bluetooth service running.
Run (typically alongside JNKPU + HostECRelay on the Pi):

    python3 sps_bridge.py --relay-host 127.0.0.1 --relay-port 7213 --adapter hci0

SPS UUIDs (UBX-16011192): service d701, FIFO d703, credits d704.
"""
import argparse
import socket
import subprocess
import sys

import dbus
import dbus.exceptions
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib

BLUEZ = "org.bluez"
ADAPTER_IF = "org.bluez.Adapter1"
GATT_MANAGER_IF = "org.bluez.GattManager1"
LE_ADV_MANAGER_IF = "org.bluez.LEAdvertisingManager1"
GATT_SERVICE_IF = "org.bluez.GattService1"
GATT_CHRC_IF = "org.bluez.GattCharacteristic1"
LE_ADV_IF = "org.bluez.LEAdvertisement1"
DBUS_OM_IF = "org.freedesktop.DBus.ObjectManager"
DBUS_PROP_IF = "org.freedesktop.DBus.Properties"

SPS_SVC_UUID = "2456e1b9-26e2-8f83-e744-f34f01e9d701"
SPS_FIFO_UUID = "2456e1b9-26e2-8f83-e744-f34f01e9d703"
SPS_CREDITS_UUID = "2456e1b9-26e2-8f83-e744-f34f01e9d704"

CREDIT_GRANT = 0x7F  # generous fixed grant; we never actually throttle the pipe

RELAY_HOST = "127.0.0.1"
RELAY_PORT = 7213
ADAPTER = "hci0"

# ---- BlueZ GATT base classes (canonical example-gatt-server.py pattern) ------

class Application(dbus.service.Object):
    def __init__(self, bus):
        self.path = "/nu/relay"
        self.services = []
        dbus.service.Object.__init__(self, bus, self.path)

    def get_path(self):
        return dbus.ObjectPath(self.path)

    def add_service(self, service):
        self.services.append(service)

    @dbus.service.method(DBUS_OM_IF, out_signature="a{oa{sa{sv}}}")
    def GetManagedObjects(self):
        response = {}
        for service in self.services:
            response[service.get_path()] = service.get_properties()
            for chrc in service.characteristics:
                response[chrc.get_path()] = chrc.get_properties()
        return response


class Service(dbus.service.Object):
    PATH_BASE = "/nu/relay/service"

    def __init__(self, bus, index, uuid, primary):
        self.path = self.PATH_BASE + str(index)
        self.uuid = uuid
        self.primary = primary
        self.characteristics = []
        dbus.service.Object.__init__(self, bus, self.path)

    def get_properties(self):
        return {GATT_SERVICE_IF: {
            "UUID": self.uuid,
            "Primary": self.primary,
            "Characteristics": dbus.Array(
                [c.get_path() for c in self.characteristics], signature="o"),
        }}

    def get_path(self):
        return dbus.ObjectPath(self.path)

    def add_characteristic(self, chrc):
        self.characteristics.append(chrc)


class Characteristic(dbus.service.Object):
    def __init__(self, bus, index, uuid, flags, service):
        self.path = service.path + "/char" + str(index)
        self.uuid = uuid
        self.service = service
        self.flags = flags
        self.notifying = False
        dbus.service.Object.__init__(self, bus, self.path)

    def get_properties(self):
        return {GATT_CHRC_IF: {
            "Service": self.service.get_path(),
            "UUID": self.uuid,
            "Flags": self.flags,
        }}

    def get_path(self):
        return dbus.ObjectPath(self.path)

    @dbus.service.method(DBUS_PROP_IF, in_signature="s", out_signature="a{sv}")
    def GetAll(self, interface):
        if interface != GATT_CHRC_IF:
            raise dbus.exceptions.DBusException("org.bluez.Error.InvalidArguments")
        return self.get_properties()[GATT_CHRC_IF]

    @dbus.service.signal(DBUS_PROP_IF, signature="sa{sv}as")
    def PropertiesChanged(self, interface, changed, invalidated):
        pass

    @dbus.service.method(GATT_CHRC_IF, in_signature="a{sv}", out_signature="ay")
    def ReadValue(self, options):
        return dbus.Array([], signature="y")

    @dbus.service.method(GATT_CHRC_IF, in_signature="aya{sv}")
    def WriteValue(self, value, options):
        pass

    @dbus.service.method(GATT_CHRC_IF)
    def StartNotify(self):
        self.notifying = True

    @dbus.service.method(GATT_CHRC_IF)
    def StopNotify(self):
        self.notifying = False

    def notify_bytes(self, data):
        if not self.notifying:
            return
        self.PropertiesChanged(GATT_CHRC_IF,
                               {"Value": dbus.Array(data, signature="y")}, [])


class Advertisement(dbus.service.Object):
    PATH_BASE = "/nu/relay/advertisement"

    def __init__(self, bus, index, service_uuids):
        self.path = self.PATH_BASE + str(index)
        self.service_uuids = service_uuids
        dbus.service.Object.__init__(self, bus, self.path)

    def get_path(self):
        return dbus.ObjectPath(self.path)

    @dbus.service.method(DBUS_PROP_IF, in_signature="s", out_signature="a{sv}")
    def GetAll(self, interface):
        if interface != LE_ADV_IF:
            raise dbus.exceptions.DBusException("org.bluez.Error.InvalidArguments")
        return {
            "Type": "peripheral",
            "ServiceUUIDs": dbus.Array(self.service_uuids, signature="s"),
        }

    @dbus.service.method(LE_ADV_IF)
    def Release(self):
        pass

# ---- SPS characteristics + TCP bridge glue -----------------------------------

class FIFOCharacteristic(Characteristic):
    def __init__(self, bus, index, service, bridge):
        super().__init__(bus, index, SPS_FIFO_UUID,
                         ["write", "write-without-response", "notify"], service)
        self.bridge = bridge
        bridge.fifo = self

    def WriteValue(self, value, options):
        self.bridge.on_ble_data(bytes(value))


class CreditsCharacteristic(Characteristic):
    def __init__(self, bus, index, service, bridge):
        super().__init__(bus, index, SPS_CREDITS_UUID,
                         ["write", "write-without-response", "notify"], service)

    def WriteValue(self, value, options):
        # Per SPS spec (UBX-16011192 4.1.2.1): the central establishes the
        # flow-controlled connection by writing its credits; the peripheral
        # ACCEPTS by sending credits back. So we grant our credits HERE, in
        # response to the central's write -- not proactively. By now the central
        # has already enabled FIFO client config, satisfying the 4.3.1 note that
        # the credit notification must not precede FIFO config.
        if not getattr(self, "_granted", False):
            self._granted = True
            self.notify_bytes([CREDIT_GRANT])

    def StartNotify(self):
        self.notifying = True
        self._granted = False  # re-grant on the central's next credit write
        # Do NOT grant credits here: sending the credit notification before the
        # central has written its credits (and before FIFO config) makes the
        # module's SPS client reject the connection (+UUDPD). Wait for WriteValue.


class Bridge:
    """Moves bytes between the SPS FIFO characteristic and one TCP relay socket."""

    def __init__(self, relay_host, relay_port, chunk=20):
        self.relay_host = relay_host
        self.relay_port = relay_port
        self.chunk = chunk
        self.sock = None
        self.watch = None
        self.fifo = None

    def _ensure_conn(self):
        if self.sock is not None:
            return
        self.sock = socket.create_connection((self.relay_host, self.relay_port), timeout=15)
        self.watch = GLib.io_add_watch(
            self.sock.fileno(), GLib.IO_IN | GLib.IO_HUP | GLib.IO_ERR, self._on_tcp)
        print("bridge: TCP relay connected")

    def on_ble_data(self, data):
        try:
            self._ensure_conn()
            self.sock.sendall(data)
        except OSError as e:
            print("bridge: TCP send error:", e)
            self._close()

    def _on_tcp(self, fd, cond):
        if cond & (GLib.IO_HUP | GLib.IO_ERR):
            self._close()
            return False
        try:
            data = self.sock.recv(4096)
        except OSError as e:
            print("bridge: TCP recv error:", e)
            self._close()
            return False
        if not data:
            self._close()
            return False
        for i in range(0, len(data), self.chunk):
            self.fifo.notify_bytes(list(data[i:i + self.chunk]))
        return True

    def _close(self):
        if self.watch is not None:
            GLib.source_remove(self.watch)
            self.watch = None
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--relay-host", default=RELAY_HOST)
    ap.add_argument("--relay-port", type=int, default=RELAY_PORT)
    ap.add_argument("--adapter", default=ADAPTER)
    ap.add_argument("--name", default="nurelay",
                    help="advertised adapter name the dongle scans for")
    args = ap.parse_args()

    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    adapter_path = "/org/bluez/" + args.adapter

    props = dbus.Interface(bus.get_object(BLUEZ, adapter_path), DBUS_PROP_IF)
    try:
        props.Set(ADAPTER_IF, "Powered", dbus.Boolean(True))
    except dbus.exceptions.DBusException as e:
        print("bridge: could not power adapter via D-Bus (%s)" % e)
        print("bridge: run once, then retry:")
        print("        sudo rfkill unblock bluetooth && sudo systemctl restart bluetooth")
        print("        bluetoothctl power on")
        # continue anyway -- the adapter may already be powered
    try:
        # Advertised name the dongle scans for (config.go: blePeerName). Set over
        # D-Bus rather than `btmgmt name`, which hangs when run this early against
        # a just-started bluetoothd.
        props.Set(ADAPTER_IF, "Alias", dbus.String(args.name))
    except dbus.exceptions.DBusException as e:
        print("bridge: could not set adapter name '%s' via D-Bus (%s)" % (args.name, e))
    bd_addr = str(props.Get(ADAPTER_IF, "Address"))

    bridge = Bridge(args.relay_host, args.relay_port)
    app = Application(bus)
    svc = Service(bus, 0, SPS_SVC_UUID, True)
    svc.add_characteristic(FIFOCharacteristic(bus, 0, svc, bridge))
    svc.add_characteristic(CreditsCharacteristic(bus, 1, svc, bridge))
    app.add_service(svc)

    gatt_mgr = dbus.Interface(bus.get_object(BLUEZ, adapter_path), GATT_MANAGER_IF)

    def ok(what):
        return lambda: print("bridge:", what, "registered")

    def fail(what):
        return lambda e: print("bridge:", what, "FAILED:", e)

    gatt_mgr.RegisterApplication(app.get_path(), {},
                                 reply_handler=ok("GATT app"), error_handler=fail("GATT app"))

    # This BCM controller rejects BlueZ's RegisterAdvertisement (Extended
    # Advertising instance API, 0x003E) with "Invalid Parameters". Use the legacy
    # kernel-mgmt path via btmgmt instead. The dongle connects by address, so a
    # plain connectable advertisement (no service UUID in the payload) is enough.
    idx = args.adapter.replace("hci", "")

    def btmgmt(*cmd, timeout=6):
        # btmgmt uses the bt_shell (readline) framework and HANGS when run without
        # a controlling terminal -- as here, from a service/subprocess: the command
        # executes but bt_shell never returns, so a plain subprocess call blocks
        # until timeout (works instantly from an interactive shell). Run it under a
        # PTY via script(1) so it behaves interactively and exits. timeout guards
        # against any residual stall.
        line = "btmgmt --index %s %s" % (idx, " ".join(cmd))
        try:
            r = subprocess.run(["script", "-qec", line, "/dev/null"],
                               capture_output=True, text=True, timeout=timeout)
            if r.returncode != 0:
                print("bridge: %s failed: %s" % (line, (r.stderr or r.stdout).strip()))
        except subprocess.TimeoutExpired:
            print("bridge: %s timed out" % line)
        except FileNotFoundError:
            print("bridge: script(1) or btmgmt not found (install util-linux / bluez)")

    # Legacy btmgmt path: LE + connectable + advertising, plus the local name the
    # dongle scans for (the advertised name comes from the kernel local name, not
    # the bluetoothd Alias). Name last so it is the final state on the live
    # controller; on Linux, changing the local name refreshes the scan response.
    for cmd in (("le", "on"), ("connectable", "on"), ("advertising", "on"), ("name", args.name)):
        btmgmt(*cmd)
    print("bridge: advertising '%s' enabled via btmgmt (legacy path)" % args.name)

    print("sps_bridge: peripheral up on %s, BD_ADDR=%s" % (args.adapter, bd_addr))
    print("sps_bridge: dongle connect string -> sps://%s/?role=c"
          % bd_addr.replace(":", "").lower())
    GLib.MainLoop().run()


if __name__ == "__main__":
    main()
