#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Bluetooth Manager GUI (PySide6 + BlueZ + Bleak)

Wymaga:
    pip install PySide6 qasync bleak dbus-next
    sudo apt install -y bluez bluez-tools
"""

import asyncio
import json
import logging
import platform
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, Any, Optional, Set, List

from PySide6 import QtCore, QtGui, QtWidgets
from PySide6.QtCore import Qt, Signal, QObject
from qasync import QEventLoop, asyncSlot

from bleak import BleakScanner, BleakClient
try:
    from bleak.backends.scanner import AdvertisementData  # 0.22+
except Exception:  # pragma: no cover
    AdvertisementData = Any

from dbus_next import Message, MessageType, Variant
from dbus_next.aio import MessageBus
from dbus_next.constants import BusType
from dbus_next.service import ServiceInterface, method

APP_NAME = "BluetoothManager"
CONFIG_DIR = Path.home() / ".config" / "BluetoothManager"
CONFIG_DIR.mkdir(parents=True, exist_ok=True)
BLOCK_FILE = CONFIG_DIR / "blocked.json"          # legacy
DB_FILE = CONFIG_DIR / "devices.json"             # trwała baza urządzeń
SET_FILE = CONFIG_DIR / "settings.json"           # ustawienia (motyw itp.)

DISCOVERY_SECONDS = 8
BLE_SCAN_SECONDS = 6
BLE_PROBE_TIMEOUT = 5
MAX_CONCURRENT_BLE_PROBES = 5

# ---------- Logowanie ----------
logger = logging.getLogger("btmgr")
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
ch.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
logger.addHandler(ch)


# ==========================
# Pomocnicze: odwijanie Variant + bezpieczny JSON
# ==========================
def unwrap_variant_deep(value):
    if isinstance(value, Variant):
        return unwrap_variant_deep(value.value)
    if isinstance(value, dict):
        return {k: unwrap_variant_deep(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [unwrap_variant_deep(x) for x in value]
    return value


def to_jsonable(obj: Any) -> Any:
    if isinstance(obj, bytes):
        return "hex:" + obj.hex()
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    if isinstance(obj, (list, tuple, set)):
        return [to_jsonable(x) for x in obj]
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    return str(obj)


# ==========================
# Dane urządzenia
# ==========================
@dataclass
class DeviceInfo:
    address: str
    name: Optional[str] = None
    alias: Optional[str] = None
    paired: Optional[bool] = None
    trusted: Optional[bool] = None
    connected: Optional[bool] = None
    rssi: Optional[int] = None
    tx_power: Optional[int] = None
    uuids: List[str] = field(default_factory=list)
    manufacturer_data: dict = field(default_factory=dict)
    service_data: dict = field(default_factory=dict)
    services: list = field(default_factory=list)
    characteristics: list = field(default_factory=list)
    details: dict = field(default_factory=dict)
    object_path: Optional[str] = None
    adapter_path: Optional[str] = None

    last_seen: Optional[float] = None  # epoch (ostatni skan / połączenie)
    available: bool = False            # „widoczne” (w ostatnim skanie) lub connected

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["uuids"] = to_jsonable(self.uuids)
        d["manufacturer_data"] = to_jsonable(self.manufacturer_data)
        d["service_data"] = to_jsonable(self.service_data)
        d["services"] = to_jsonable(self.services)
        d["characteristics"] = to_jsonable(self.characteristics)
        d["details"] = to_jsonable(self.details)
        return d

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "DeviceInfo":
        return DeviceInfo(
            address=data.get("address"),
            name=data.get("name"),
            alias=data.get("alias"),
            paired=data.get("paired"),
            trusted=data.get("trusted"),
            connected=data.get("connected"),
            rssi=data.get("rssi"),
            tx_power=data.get("tx_power"),
            uuids=list(data.get("uuids") or []),
            manufacturer_data=dict(data.get("manufacturer_data") or {}),
            service_data=dict(data.get("service_data") or {}),
            services=list(data.get("services") or []),
            characteristics=list(data.get("characteristics") or []),
            details=dict(data.get("details") or {}),
            object_path=data.get("object_path"),
            adapter_path=data.get("adapter_path"),
            last_seen=data.get("last_seen"),
            available=bool(data.get("available", False)),
        )

    def display_name(self) -> str:
        return self.name or self.alias or "Nieznane"

    def looks_like_ble(self) -> bool:
        std_gatt = {"00001800-0000-1000-8000-00805f9b34fb", "00001801-0000-1000-8000-00805f9b34fb"}
        u = {x.lower() for x in (self.uuids or [])}
        if u & std_gatt:
            return True
        if self.service_data or self.manufacturer_data:
            return True
        return False


# ==========================
# BlueZ Agent (org.bluez.Agent1)
# ==========================
class QtAgent(ServiceInterface):
    def __init__(self, parent_window: QtWidgets.QWidget):
        super().__init__("org.bluez.Agent1")
        self.parent = parent_window

    @method()
    def Release(self):
        logger.info("Agent.Release()")

    @method()
    def Cancel(self):
        logger.info("Agent.Cancel()")

    @method()
    def RequestPinCode(self, device: 'o') -> 's':
        addr = device.split("dev_")[-1].replace("_", ":")
        pin, ok = QtWidgets.QInputDialog.getText(self.parent, "Parowanie – PIN",
                                                 f"Podaj PIN dla {addr}:", QtWidgets.QLineEdit.Normal)
        if not ok or not pin:
            raise Exception("org.bluez.Error.Canceled")
        return pin

    @method()
    def DisplayPinCode(self, device: 'o', pincode: 's'):
        addr = device.split("dev_")[-1].replace("_", ":")
        QtWidgets.QMessageBox.information(self.parent, "Parowanie – PIN",
                                          f"PIN dla {addr}: {pincode}")

    @method()
    def RequestPasskey(self, device: 'o') -> 'u':
        addr = device.split("dev_")[-1].replace("_", ":")
        val, ok = QtWidgets.QInputDialog.getInt(self.parent, "Parowanie – Passkey",
                                                f"Podaj passkey (0–999999) dla {addr}:", 0, 0, 999999)
        if not ok:
            raise Exception("org.bluez.Error.Canceled")
        return int(val)

    @method()
    def DisplayPasskey(self, device: 'o', passkey: 'u', entered: 'q'):
        addr = device.split("dev_")[-1].replace("_", ":")
        QtWidgets.QMessageBox.information(self.parent, "Parowanie – Passkey",
                                          f"Passkey dla {addr}: {passkey:06d}")

    @method()
    def RequestConfirmation(self, device: 'o', passkey: 'u'):
        addr = device.split("dev_")[-1].replace("_", ":")
        ok = QtWidgets.QMessageBox.question(self.parent, "Potwierdź parowanie",
                                            f"Czy kod dla {addr} to {passkey:06d}?",
                                            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No)
        if ok != QtWidgets.QMessageBox.Yes:
            raise Exception("org.bluez.Error.Rejected")

    @method()
    def RequestAuthorization(self, device: 'o'):
        addr = device.split("dev_")[-1].replace("_", ":")
        ok = QtWidgets.QMessageBox.question(self.parent, "Autoryzacja",
                                            f"Czy autoryzować urządzenie {addr}?",
                                            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No)
        if ok != QtWidgets.QMessageBox.Yes:
            raise Exception("org.bluez.Error.Rejected")


# ==========================
# BlueZ Helper (D-Bus)
# ==========================
class BlueZManager:
    def __init__(self, log: logging.Logger):
        self.bus: Optional[MessageBus] = None
        self.log = log
        self.agent_path = "/com/example/BtAgent"
        self.agent: Optional[QtAgent] = None

    async def ensure_bus(self):
        if self.bus is None:
            self.bus = await MessageBus(bus_type=BusType.SYSTEM).connect()

    async def _call(self, destination: str, path: str, interface: str, member: str,
                    signature: str = "", body: list = None):
        await self.ensure_bus()
        msg = Message(destination=destination, path=path, interface=interface,
                      member=member, signature=signature, body=body or [])
        reply = await self.bus.call(msg)
        if reply.message_type != MessageType.METHOD_RETURN:
            err = reply.error_name or "org.bluez.Error.Failed"
            self.log.error(f"D-Bus error: {interface}.{member} -> {err}")
            raise RuntimeError(f"Błąd D-Bus: {interface}.{member} -> {err}")
        return reply

    async def _call_quiet(self, destination: str, path: str, interface: str, member: str,
                          signature: str = "", body: list = None):
        await self.ensure_bus()
        msg = Message(destination=destination, path=path, interface=interface,
                      member=member, signature=signature, body=body or [])
        reply = await self.bus.call(msg)
        if reply.message_type != MessageType.METHOD_RETURN:
            err = reply.error_name or "org.bluez.Error.Failed"
            raise RuntimeError(f"{err}")
        return reply

    async def get_managed_objects(self) -> Dict[str, Dict[str, Dict[str, Any]]]:
        await self.ensure_bus()
        reply = await self.bus.call(Message(
            destination='org.bluez',
            path='/',
            interface='org.freedesktop.DBus.ObjectManager',
            member='GetManagedObjects'
        ))
        if reply.message_type != MessageType.METHOD_RETURN:
            return {}
        return reply.body[0]

    async def power_on_adapters(self):
        objs = await self.get_managed_objects()
        for path, ifs in objs.items():
            if "org.bluez.Adapter1" in ifs:
                try:
                    await self._set_property(path, "org.bluez.Adapter1", "Powered", Variant("b", True))
                    self.log.info(f"Włączono adapter: {path}")
                except Exception as e:
                    self.log.warning(f"Nie udało się włączyć adaptera {path}: {e}")

    async def _set_property(self, path: str, iface: str, prop: str, value: Variant):
        await self.ensure_bus()
        msg = Message(
            destination="org.bluez",
            path=path,
            interface="org.freedesktop.DBus.Properties",
            member="Set",
            signature="ssv",
            body=[iface, prop, value]
        )
        reply = await self.bus.call(msg)
        if reply.message_type != MessageType.METHOD_RETURN:
            raise RuntimeError(reply.error_name or "org.bluez.Error.Failed")

    def attach_agent(self, agent: QtAgent):
        self.agent = agent
        self.bus.export(self.agent_path, agent)

    async def register_agent(self, capability="KeyboardDisplay"):
        await self.ensure_bus()
        if self.agent is None:
            raise RuntimeError("Agent nie jest zainicjalizowany.")
        await self._call("org.bluez", "/org/bluez", "org.bluez.AgentManager1", "RegisterAgent",
                         "os", [self.agent_path, capability])
        try:
            await self._call_quiet("org.bluez", "/org/bluez", "org.bluez.AgentManager1", "SetDefaultAgent",
                                   "o", [self.agent_path])
        except RuntimeError as e:
            if "UnknownMethod" in str(e):
                await self._call("org.bluez", "/org/bluez", "org.bluez.AgentManager1", "RequestDefaultAgent",
                                 "o", [self.agent_path])
            else:
                raise
        self.log.info("Zarejestrowano BlueZ Agent jako domyślny.")

    async def unregister_agent(self):
        try:
            await self._call("org.bluez", "/org/bluez", "org.bluez.AgentManager1", "UnregisterAgent",
                             "o", [self.agent_path])
            self.log.info("Wyrejestrowano BlueZ Agent.")
        except Exception as e:
            self.log.warning(f"UnregisterAgent błąd: {e}")

    @staticmethod
    def _parse_device_props(raw_props: dict) -> DeviceInfo:
        props = unwrap_variant_deep(raw_props)
        di = DeviceInfo(
            address=props.get("Address"),
            name=props.get("Name") or props.get("Alias"),
            alias=props.get("Alias"),
            paired=props.get("Paired"),
            trusted=props.get("Trusted"),
            connected=props.get("Connected"),
            uuids=list(props.get("UUIDs") or []),
            rssi=props.get("RSSI"),
            tx_power=props.get("TxPower"),
            manufacturer_data=props.get("ManufacturerData") or {},
            service_data=props.get("ServiceData") or {},
            details={}
        )
        if di.connected or (di.rssi is not None):
            di.available = True
            di.last_seen = time.time()
        return di

    async def start_discovery_on_all_adapters(self):
        objs = await self.get_managed_objects()
        adapters = [path for path, ifs in objs.items() if "org.bluez.Adapter1" in ifs]
        for ap in adapters:
            try:
                await self._call("org.bluez", ap, "org.bluez.Adapter1", "StartDiscovery")
            except Exception as e:
                self.log.warning(f"StartDiscovery błąd na {ap}: {e}")
        return adapters

    async def stop_discovery_on_all_adapters(self):
        objs = await self.get_managed_objects()
        adapters = [path for path, ifs in objs.items() if "org.bluez.Adapter1" in ifs]
        for ap in adapters:
            try:
                await self._call_quiet("org.bluez", ap, "org.bluez.Adapter1", "StopDiscovery")
            except Exception:
                pass

    async def list_devices(self) -> Dict[str, DeviceInfo]:
        objs = await self.get_managed_objects()
        result: Dict[str, DeviceInfo] = {}
        for path, ifs in objs.items():
            dev = ifs.get("org.bluez.Device1")
            if dev:
                di = self._parse_device_props(dev)
                if not di.address:
                    continue
                di.object_path = path
                di.adapter_path = path.split("/dev_")[0]
                old = result.get(di.address)
                if old:
                    result[di.address] = self._merge(old, di)
                else:
                    result[di.address] = di
        return result

    @staticmethod
    def _merge(a: DeviceInfo, b: DeviceInfo) -> DeviceInfo:
        def pick(x, y): return y if (x is None and y is not None) else x
        a.name = pick(a.name, b.name)
        a.alias = pick(a.alias, b.alias)
        a.paired = pick(a.paired, b.paired)
        a.trusted = pick(a.trusted, b.trusted)
        a.connected = pick(a.connected, b.connected)
        a.rssi = pick(a.rssi, b.rssi)
        a.tx_power = pick(a.tx_power, b.tx_power)
        a.uuids = list({*(a.uuids or []), *(b.uuids or [])})
        a.manufacturer_data.update(b.manufacturer_data or {})
        a.service_data.update(b.service_data or {})
        a.services += [x for x in (b.services or []) if x not in a.services]
        a.characteristics += [x for x in (b.characteristics or []) if x not in a.characteristics]
        a.details.update(b.details or {})
        a.object_path = a.object_path or b.object_path
        a.adapter_path = a.adapter_path or b.adapter_path
        a.available = a.available or b.available
        a.last_seen = a.last_seen or b.last_seen
        return a

    # --- Akcje na urządzeniu ---
    async def pair(self, dev: DeviceInfo):
        async def _do():
            await self._call("org.bluez", dev.object_path, "org.bluez.Device1", "Pair")
        await self._with_path_recovery(dev, _do)

    async def cancel_pairing(self, dev: DeviceInfo):
        if not dev.object_path:
            raise RuntimeError("Brak object_path urządzenia.")
        await self._call("org.bluez", dev.object_path, "org.bluez.Device1", "CancelPairing")

    async def connect_profile(self, dev: DeviceInfo, uuid: str):
        async def _do():
            await self._call("org.bluez", dev.object_path, "org.bluez.Device1", "ConnectProfile", "s", [uuid])
        await self._with_path_recovery(dev, _do)

    async def disconnect(self, dev: DeviceInfo):
        async def _do():
            await self._call("org.bluez", dev.object_path, "org.bluez.Device1", "Disconnect")
        await self._with_path_recovery(dev, _do)

    async def remove_device(self, dev: DeviceInfo):
        if not dev.adapter_path:
            p = await self.find_device_path_by_address(dev.address)
            if p:
                dev.object_path = p
                dev.adapter_path = p.split("/dev_")[0]
        if not dev.object_path or not dev.adapter_path:
            raise RuntimeError("Brak object_path/adapter_path.")
        await self._call("org.bluez", dev.adapter_path, "org.bluez.Adapter1", "RemoveDevice", "o", [dev.object_path])

    async def set_trusted(self, dev: DeviceInfo, trusted: bool):
        async def _do():
            await self._set_property(dev.object_path, "org.bluez.Device1", "Trusted", Variant("b", trusted))
        await self._with_path_recovery(dev, _do)

    async def _with_path_recovery(self, dev: DeviceInfo, op_coro_factory):
        if not dev.object_path:
            p = await self.ensure_device_present(dev.address, timeout=8.0)
            if not p:
                self.log.warning("Urządzenie zniknęło z BlueZ (brak node Device1 po ponownej próbie).")
                return
            dev.object_path = p
            dev.adapter_path = p.split("/dev_")[0]
        try:
            await op_coro_factory()
            return
        except RuntimeError as e:
            if "UnknownObject" not in str(e):
                raise
            p = await self.ensure_device_present(dev.address, timeout=8.0)
            if not p:
                raise RuntimeError("Urządzenie zniknęło z BlueZ (brak node Device1 po ponownej próbie).")
            dev.object_path = p
            dev.adapter_path = p.split("/dev_")[0]
            await op_coro_factory()

    async def list_device_nodes(self):
        objs = await self.get_managed_objects()
        out = []
        for path, ifs in objs.items():
            dev = ifs.get("org.bluez.Device1")
            if dev:
                props = unwrap_variant_deep(dev)
                addr = props.get("Address")
                adapter_path = path.split("/dev_")[0]
                out.append((adapter_path, path, addr))
        return out

    async def remove_all_devices(self) -> int:
        count = 0
        objs = await self.get_managed_objects()
        by_adapter = {}
        for path, ifs in objs.items():
            if "org.bluez.Device1" in ifs:
                adapter_path = path.split("/dev_")[0]
                by_adapter.setdefault(adapter_path, []).append(path)
        for adapter_path, dev_paths in by_adapter.items():
            for dev_path in dev_paths:
                try:
                    await self._call("org.bluez", adapter_path, "org.bluez.Adapter1",
                                     "RemoveDevice", "o", [dev_path])
                    count += 1
                except Exception as e:
                    self.log.warning(f"RemoveDevice({dev_path}) na {adapter_path} nie powiodło się: {e}")
        return count

    async def find_device_path_by_address(self, address: str) -> Optional[str]:
        objs = await self.get_managed_objects()
        for path, ifs in objs.items():
            dev = ifs.get("org.bluez.Device1")
            if not dev:
                continue
            props = unwrap_variant_deep(dev)
            if props.get("Address") == address:
                return path
        return None

    async def ensure_device_present(self, address: str, timeout: float = 10.0) -> Optional[str]:
        p = await self.find_device_path_by_address(address)
        if p:
            return p
        try:
            await self.start_discovery_on_all_adapters()
        except Exception:
            pass
        t0 = time.time()
        while time.time() - t0 < timeout:
            p = await self.find_device_path_by_address(address)
            if p:
                break
            await asyncio.sleep(0.4)
        try:
            await self.stop_discovery_on_all_adapters()
        except Exception:
            pass
        return p

    async def power_cycle_adapters(self, off_ms: int = 600):
        objs = await self.get_managed_objects()
        adapters = [p for p, ifs in objs.items() if "org.bluez.Adapter1" in ifs]
        for ap in adapters:
            try:
                await self._set_property(ap, "org.bluez.Adapter1", "Powered", Variant("b", False))
                self.log.info(f"Wyłączono adapter: {ap}")
            except Exception as e:
                self.log.warning(f"Power OFF nie powiódł się na {ap}: {e}")
        await asyncio.sleep(off_ms / 1000.0)
        for ap in adapters:
            try:
                await self._set_property(ap, "org.bluez.Adapter1", "Powered", Variant("b", True))
                self.log.info(f"Włączono adapter: {ap}")
            except Exception as e:
                self.log.warning(f"Power ON nie powiódł się na {ap}: {e}")

    async def set_discovery_filter_default(self):
        objs = await self.get_managed_objects()
        adapters = [p for p, ifs in objs.items() if "org.bluez.Adapter1" in ifs]
        for ap in adapters:
            try:
                body = {
                    "Transport": Variant("s", "auto"),
                    "DuplicateData": Variant("b", True),
                }
                await self._call("org.bluez", ap, "org.bluez.Adapter1", "SetDiscoveryFilter", "a{sv}", [body])
                self.log.info(f"Ustawiono domyślny filtr discovery na {ap}")
            except Exception as e:
                self.log.warning(f"SetDiscoveryFilter na {ap} nie powiódł się: {e}")


# ==========================
# BLE skan + sonda GATT
# ==========================
async def bleak_scan(timeout=BLE_SCAN_SECONDS) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}

    def on_detect(device, adv: AdvertisementData):
        out[device.address] = {
            "name": device.name or adv.local_name,
            "rssi": adv.rssi,
            "uuids": list(adv.service_uuids or []),
            "manufacturer_data": dict(adv.manufacturer_data or {}),
            "service_data": dict(adv.service_data or {}),
            "details": {"tx_power": adv.tx_power, "platform_data": str(adv.platform_data)},
        }

    scanner = BleakScanner(detection_callback=on_detect)
    await scanner.start()
    await asyncio.sleep(timeout)
    await scanner.stop()
    return out


async def bleak_probe_services(address: str, timeout=BLE_PROBE_TIMEOUT) -> Dict[str, Any]:
    try:
        async with BleakClient(address, timeout=timeout) as client:
            svcs = await client.get_services()
            services, chars = [], []
            for s in svcs:
                services.append({"uuid": s.uuid, "description": s.description})
                for c in s.characteristics:
                    chars.append({
                        "uuid": c.uuid,
                        "properties": list(c.properties),
                        "description": getattr(c, "description", None)
                    })
            return {"services": services, "characteristics": chars}
    except Exception as e:
        return {"probe_error": str(e)}


# ==========================
# GUI: model + log handler
# ==========================
GREEN = QtGui.QBrush(QtGui.QColor("#0a7f17"))
RED = QtGui.QBrush(QtGui.QColor("#b00020"))
FG_DARK = QtGui.QBrush(QtGui.QColor("#0b0b0b"))
FG_LIGHT = QtGui.QBrush(QtGui.QColor("#e8eaf0"))


class DeviceModel(QtGui.QStandardItemModel):
    COLS = ["Nazwa", "Adres", "Widoczne", "RSSI", "Sparowane", "Zaufane", "Połączone", "UUIDs", "Adapter"]
    TICK_COLS = {2, 4, 5, 6}

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setColumnCount(len(self.COLS))
        self.setHorizontalHeaderLabels(self.COLS)
        self._for_light_theme = True

    def set_light_theme(self, light: bool):
        self._for_light_theme = light

    @staticmethod
    def _tick(v: Optional[bool]) -> (str, QtGui.QBrush):
        if v is None:
            return "", QtGui.QBrush()
        return ("✓", GREEN) if v else ("✗", RED)

    def add_or_update(self, dev: DeviceInfo):
        matches = self.findItems(dev.address, column=1)
        if matches:
            row = matches[0].row()
        else:
            row = self.rowCount()
            self.insertRow(row)
            for col in range(len(self.COLS)):
                it = QtGui.QStandardItem("")
                if col in self.TICK_COLS:
                    it.setTextAlignment(Qt.AlignCenter)
                self.setItem(row, col, it)

        self.item(row, 0).setText(dev.display_name())
        self.item(row, 1).setText(dev.address)
        t, color = self._tick(dev.available)
        self.item(row, 2).setText(t)
        self.item(row, 2).setForeground(color)
        self.item(row, 2).setTextAlignment(Qt.AlignCenter)
        self.item(row, 3).setText("" if dev.rssi is None else str(dev.rssi))
        t, color = self._tick(dev.paired)
        self.item(row, 4).setText(t)
        self.item(row, 4).setForeground(color)
        self.item(row, 4).setTextAlignment(Qt.AlignCenter)
        t, color = self._tick(dev.trusted)
        self.item(row, 5).setText(t)
        self.item(row, 5).setForeground(color)
        self.item(row, 5).setTextAlignment(Qt.AlignCenter)
        t, color = self._tick(dev.connected)
        self.item(row, 6).setText(t)
        self.item(row, 6).setForeground(color)
        self.item(row, 6).setTextAlignment(Qt.AlignCenter)
        self.item(row, 7).setText(str(len(dev.uuids or [])))
        self.item(row, 8).setText(dev.adapter_path or "")

        f = self.item(row, 0).font()
        f.setBold(bool(dev.connected))
        self.item(row, 0).setFont(f)

        fg = FG_DARK if self._for_light_theme else FG_LIGHT
        for c in range(self.columnCount()):
            if c not in (2, 4, 5, 6):
                self.item(row, c).setForeground(fg)


class LogEmitter(QObject):
    message = Signal(str)


class LogHandler(logging.Handler):
    def __init__(self, widget: QtWidgets.QTextEdit):
        super().__init__()
        self.widget = widget
        self.emitter = LogEmitter()
        self.emitter.message.connect(self.widget.append)
        self.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))

    def emit(self, self_record):
        try:
            msg = self.format(self_record)
            self.emitter.message.emit(msg)
        except Exception:
            pass


# ==========================
# Główne okno
# ==========================
class MainWindow(QtWidgets.QMainWindow):
    PROFILE_PRIORITY = [
        "0000110b-0000-1000-8000-00805f9b34fb",  # A2DP Sink
        "0000110a-0000-1000-8000-00805f9b34fb",  # A2DP Source
        "0000110e-0000-1000-8000-00805f9b34fb",  # AVRCP Target
        "0000110c-0000-1000-8000-00805f9b34fb",  # AVRCP Controller
        "00001108-0000-1000-8000-00805f9b34fb",  # Headset
        "0000111e-0000-1000-8000-00805f9b34fb",  # Handsfree
        "00001124-0000-1000-8000-00805f9b34fb",  # HID
        "00001115-0000-1000-8000-00805f9b34fb",  # PANU
        "00001116-0000-1000-8000-00805f9b34fb",  # NAP
        "00001117-0000-1000-8000-00805f9b34fb",  # GN
        "00001101-0000-1000-8000-00805f9b34fb",  # SPP
    ]

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Bluetooth Manager")
        self.resize(1300, 820)

        self.settings = self._load_settings()
        self.light_theme = self.settings.get("light_theme", True)

        self._apply_style()

        # --- Baza / stan ---
        self.bluez = BlueZManager(logger)
        self.devices: Dict[str, DeviceInfo] = self._load_devices()
        self.blocked: Set[str] = self._load_blocked()
        self.favorites: Set[str] = self._load_favorites()
        self.just_reset = False
        self.bottom_panel_hidden = True  # domyślnie schowany

        # --- UI ---
        self._build_ui()
        QtCore.QTimer.singleShot(0, self._post_init)

        if platform.system() != "Linux":
            QtWidgets.QMessageBox.information(self, "Uwaga",
                "Ten menedżer działa w pełni na Linuxie (BlueZ). "
                "Na tym systemie część funkcji może nie działać.")

        # animacja statusu skanowania
        self.scan_anim_timer = QtCore.QTimer(self)
        self.scan_anim_timer.setInterval(350)
        self.scan_anim_timer.timeout.connect(self._tick_scan_anim)
        self._scan_anim_state = 0
        self._is_scanning = False

    # ---------- Ustawienia / baza ----------
    def _load_settings(self) -> Dict[str, Any]:
        try:
            return json.loads(SET_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _save_settings(self):
        try:
            SET_FILE.write_text(json.dumps({"light_theme": self.light_theme}, indent=2), encoding="utf-8")
        except Exception as e:
            logger.error(f"Nie udało się zapisać settings: {e}")

    def _load_blocked(self) -> Set[str]:
        try:
            if DB_FILE.exists():
                db = json.loads(DB_FILE.read_text(encoding="utf-8"))
                return {str(x).upper() for x in db.get("blocked", [])}
        except Exception:
            pass
        if BLOCK_FILE.exists():
            try:
                return {str(x).upper() for x in json.loads(BLOCK_FILE.read_text(encoding="utf-8"))}
            except Exception:
                pass
        return set()

    def _load_favorites(self) -> Set[str]:
        try:
            if DB_FILE.exists():
                db = json.loads(DB_FILE.read_text(encoding="utf-8"))
                return {str(x).upper() for x in db.get("favorites", [])}
        except Exception:
            pass
        return set()

    def _load_devices(self) -> Dict[str, DeviceInfo]:
        try:
            data = json.loads(DB_FILE.read_text(encoding="utf-8"))
            devs = {addr: DeviceInfo.from_dict(d) for addr, d in data.get("devices", {}).items()}
            return devs
        except Exception:
            return {}

    def _save_db(self):
        try:
            out = {
                "blocked": sorted(self.blocked),
                "favorites": sorted(self.favorites),
                "devices": {addr: dev.to_dict() for addr, dev in self.devices.items()},
                "saved_at": time.time(),
            }
            DB_FILE.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception as e:
            logger.error(f"Nie udało się zapisać {DB_FILE}: {e}")

    # ---------- UI ----------
    def _apply_style(self):
        if self.light_theme:
            self.setStyleSheet("""
                QMainWindow { background: #ffffff; }
                QWidget { color: #0b0b0b; font-size: 14px; }
                QLineEdit, QTextEdit, QTableView {
                    background: #ffffff; border: 1px solid #ced4da; border-radius: 6px; padding: 6px; color: #0b0b0b;
                }
                QHeaderView::section {
                    background: #f3f5f7; color: #0b0b0b; padding: 6px; border: 0px; font-weight: 600;
                }
                QToolBar { background: #f8f9fb; spacing: 8px; }
                QToolButton { color: #0b0b0b; padding: 6px 10px; }
                QTabBar::tab { background: #eef1f5; padding: 8px 14px; margin: 2px; border-radius: 10px; }
                QTabBar::tab:selected { background: #dbe4f0; }
                QLabel { color: #333333; }
            """)
        else:
            self.setStyleSheet("""
                QMainWindow { background: #11161f; }
                QWidget { color: #e8eaf0; font-size: 14px; }
                QLineEdit, QTextEdit, QTableView {
                    background: #151a22; border: 1px solid #222836; border-radius: 8px; padding: 6px; color: #e8eaf0;
                }
                QHeaderView::section {
                    background: #1a202c; color: #e8eaf0; padding: 6px; border: 0px;
                }
                QToolBar { background: #121622; spacing: 8px; }
                QToolButton { color: #e8eaf0; padding: 6px 10px; }
                QTabBar::tab { background: #151a22; padding: 8px 14px; margin: 2px; border-radius: 10px; }
                QTabBar::tab:selected { background: #243047; }
                QLabel { color: #a9b3c9; }
            """)

    def on_toggle_theme(self):
        """PRZYWRÓCONE: przełączanie trybu jasny/ciemny + odświeżenie tabel i zapis ustawień."""
        self.light_theme = not self.light_theme
        self._apply_style()
        # odśwież modele pod kolorystykę
        for m in (self.model_main, self.model_hidden, self.model_archive, self.model_favorites):
            m.set_light_theme(self.light_theme)
        self._rebuild_tables()
        self._save_settings()

    def _icon(self, sp):
        return self.style().standardIcon(sp)

    def _build_ui(self):
        # ======= Menu =======
        mb = self.menuBar()
        self.menu_file = mb.addMenu("Plik")
        self.menu_tools = mb.addMenu("Narzędzia")
        self.menu_device = mb.addMenu("Urządzenie")
        self.menu_view = mb.addMenu("Widok")

        # ======= Toolbar =======
        toolbar = QtWidgets.QToolBar()
        toolbar.setMovable(False)
        toolbar.setToolButtonStyle(Qt.ToolButtonTextUnderIcon)
        self.addToolBar(Qt.TopToolBarArea, toolbar)

        # ======= Akcje (z ikonami + skrótami) =======
        self.act_scan = QtGui.QAction(self._icon(QtWidgets.QStyle.SP_BrowserReload), "Skanuj", self)
        self.act_scan.setShortcut(Qt.Key_F5)

        self.act_refresh = QtGui.QAction(self._icon(QtWidgets.QStyle.SP_BrowserStop), "Odśwież", self)
        self.act_refresh.setShortcut(QtGui.QKeySequence("Ctrl+R"))

        self.act_connect = QtGui.QAction(self._icon(QtWidgets.QStyle.SP_DialogYesButton), "Połącz", self)
        self.act_connect.setShortcut(QtGui.QKeySequence("Ctrl+Return"))

        self.act_disconnect = QtGui.QAction(self._icon(QtWidgets.QStyle.SP_DialogNoButton), "Rozłącz", self)
        self.act_disconnect.setShortcut(QtGui.QKeySequence("Ctrl+Shift+Return"))

        self.act_pair = QtGui.QAction(self._icon(QtWidgets.QStyle.SP_DialogApplyButton), "Paruj", self)
        self.act_pair.setShortcut(QtGui.QKeySequence("Ctrl+P"))

        self.act_unpair = QtGui.QAction(self._icon(QtWidgets.QStyle.SP_DialogCancelButton), "Usuń parowanie", self)
        self.act_unpair.setShortcut(QtGui.QKeySequence("Ctrl+Shift+P"))

        self.act_trust = QtGui.QAction(self._icon(QtWidgets.QStyle.SP_DialogYesButton), "Zaufaj", self)
        self.act_trust.setShortcut(QtGui.QKeySequence("Ctrl+T"))

        self.act_untrust = QtGui.QAction(self._icon(QtWidgets.QStyle.SP_DialogNoButton), "Przestań ufać", self)
        self.act_untrust.setShortcut(QtGui.QKeySequence("Ctrl+Shift+T"))

        self.act_fav_add = QtGui.QAction(self._icon(QtWidgets.QStyle.SP_DirIcon), "Dodaj do Ulubionych", self)
        self.act_fav_add.setShortcut(QtGui.QKeySequence("Ctrl+F"))
        self.act_fav_remove = QtGui.QAction(self._icon(QtWidgets.QStyle.SP_DirHomeIcon), "Usuń z Ulubionych", self)
        self.act_fav_remove.setShortcut(QtGui.QKeySequence("Ctrl+Shift+F"))

        self.act_hide = QtGui.QAction(self._icon(QtWidgets.QStyle.SP_ArrowDown), "Przenieś do Ukryte", self)
        self.act_hide.setShortcut(QtGui.QKeySequence("Ctrl+H"))
        self.act_unhide = QtGui.QAction(self._icon(QtWidgets.QStyle.SP_ArrowUp), "Usuń z Ukrytych", self)

        self.act_delete = QtGui.QAction(self._icon(QtWidgets.QStyle.SP_TrashIcon), "Usuń z listy", self)
        self.act_export = QtGui.QAction(self._icon(QtWidgets.QStyle.SP_DialogSaveButton), "Eksportuj JSON", self)
        self.act_theme = QtGui.QAction(self._icon(QtWidgets.QStyle.SP_DesktopIcon), "Jasny/Ciemny", self)

        self.act_reset = QtGui.QAction(self._icon(QtWidgets.QStyle.SP_BrowserReload), "Resetuj BT", self)

        self.act_toggle_bottom = QtGui.QAction(self._icon(QtWidgets.QStyle.SP_TitleBarShadeButton), "Pokaż/Ukryj panel", self)
        self.act_toggle_bottom.setShortcut(Qt.Key_F9)

        # ======= Toolbar – podstawowe =======
        for a in (self.act_scan, self.act_refresh, self.act_connect, self.act_disconnect,
                  self.act_pair, self.act_unpair, self.act_trust, self.act_untrust,
                  self.act_fav_add, self.act_fav_remove, self.act_hide, self.act_unhide,
                  self.act_delete, self.act_export, self.act_theme, self.act_toggle_bottom, self.act_reset):
            toolbar.addAction(a)

        # ======= Menu główne =======
        self.menu_file.addAction(self.act_export)
        self.menu_file.addSeparator()
        self.menu_file.addAction(self.act_reset)
        self.menu_file.addSeparator()
        self.menu_file.addAction(QtGui.QAction("Zamknij", self, triggered=self.close))

        self.menu_tools.addAction(self.act_scan)
        self.menu_tools.addAction(self.act_refresh)

        self.menu_device.addAction(self.act_connect)
        self.menu_device.addAction(self.act_disconnect)
        self.menu_device.addSeparator()
        self.menu_device.addAction(self.act_pair)
        self.menu_device.addAction(self.act_unpair)
        self.menu_device.addSeparator()
        self.menu_device.addAction(self.act_trust)
        self.menu_device.addAction(self.act_untrust)
        self.menu_device.addSeparator()
        self.menu_device.addAction(self.act_fav_add)
        self.menu_device.addAction(self.act_fav_remove)
        self.menu_device.addAction(self.act_hide)
        self.menu_device.addAction(self.act_unhide)
        self.menu_device.addSeparator()
        self.menu_device.addAction(self.act_delete)

        self.menu_view.addAction(self.act_toggle_bottom)
        self.menu_view.addAction(self.act_theme)

        # ======= Centralny layout: zakładki list + splitter + tabs logi/szczegóły =======
        central = QtWidgets.QWidget(self)
        self.setCentralWidget(central)
        root_v = QtWidgets.QVBoxLayout(central)
        root_v.setContentsMargins(6, 6, 6, 6)
        root_v.setSpacing(6)

        # Filtr
        filter_box = QtWidgets.QHBoxLayout()
        self.search_edit = QtWidgets.QLineEdit()
        self.search_edit.setPlaceholderText("Filtruj po nazwie lub adresie MAC…")
        filter_box.addWidget(QtWidgets.QLabel("Szukaj:"))
        filter_box.addWidget(self.search_edit)

        # Zakładki list
        self.tabs = QtWidgets.QTabWidget()
        self.tab_devices = QtWidgets.QWidget()
        self.tab_hidden = QtWidgets.QWidget()   # (UI: Ukryte)
        self.tab_archive = QtWidgets.QWidget()
        self.tab_favorites = QtWidgets.QWidget()
        self.tabs.addTab(self.tab_devices, "Urządzenia")
        self.tabs.addTab(self.tab_hidden, "Ukryte")
        self.tabs.addTab(self.tab_archive, "Archiwum")
        self.tabs.addTab(self.tab_favorites, "Ulubione")

        # MODELE/PROXY/WIDOKI
        self.model_main = DeviceModel(self)
        self.model_hidden = DeviceModel(self)
        self.model_archive = DeviceModel(self)
        self.model_favorites = DeviceModel(self)
        for m in (self.model_main, self.model_hidden, self.model_archive, self.model_favorites):
            m.set_light_theme(self.light_theme)

        def make_proxy(model):
            p = QtCore.QSortFilterProxyModel(self)
            p.setSourceModel(model)
            p.setFilterCaseSensitivity(Qt.CaseInsensitive)
            p.setFilterKeyColumn(-1)
            return p

        self.proxy_main = make_proxy(self.model_main)
        self.proxy_hidden = make_proxy(self.model_hidden)
        self.proxy_archive = make_proxy(self.model_archive)
        self.proxy_favorites = make_proxy(self.model_favorites)

        def make_view(proxy):
            v = QtWidgets.QTableView()
            v.setModel(proxy)
            v.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
            v.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
            v.horizontalHeader().setStretchLastSection(True)
            v.verticalHeader().setVisible(False)
            v.setAlternatingRowColors(True)
            v.setSortingEnabled(True)
            v.setContextMenuPolicy(Qt.CustomContextMenu)
            return v

        self.view_main = make_view(self.proxy_main)
        self.view_hidden = make_view(self.proxy_hidden)
        self.view_archive = make_view(self.proxy_archive)
        self.view_favorites = make_view(self.proxy_favorites)

        # układy kart z widokami
        def fill_tab(tab, view):
            vbox = QtWidgets.QVBoxLayout(tab)
            vbox.addLayout(filter_box if tab is self.tab_devices else QtWidgets.QVBoxLayout())  # filtr tylko w pierwszej
            if tab is not self.tab_devices:
                spacer = QtWidgets.QWidget()
                spacer.setFixedHeight(0)
                vbox.addWidget(spacer)
            vbox.addWidget(view, 1)

        fill_tab(self.tab_devices, self.view_main)
        fill_tab(self.tab_hidden, self.view_hidden)
        fill_tab(self.tab_archive, self.view_archive)
        fill_tab(self.tab_favorites, self.view_favorites)

        # Panel dolny: Logi + Szczegóły (zakładki)
        self.bottom_tabs = QtWidgets.QTabWidget()
        self.log_view = QtWidgets.QTextEdit()
        self.log_view.setReadOnly(True)
        self.details = QtWidgets.QTextEdit()
        self.details.setReadOnly(True)
        self.details.setMinimumHeight(160)

        self.bottom_tabs.addTab(self.log_view, "Logi")
        self.bottom_tabs.addTab(self.details, "Szczegóły")
        self.bottom_tabs.setCurrentIndex(0)  # Logi aktywne

        # Log handler podłączony do log_view
        self.log_handler = LogHandler(self.log_view)
        logger.addHandler(self.log_handler)

        # Splitter pionowy: zakładki (listy) + panel dolny
        self.splitter = QtWidgets.QSplitter(Qt.Vertical)
        self.splitter.addWidget(self.tabs)
        self.splitter.addWidget(self.bottom_tabs)
        root_v.addWidget(self.splitter, 1)

        # Domyślnie panel dolny schowany
        self._apply_bottom_panel_hidden(True)

        # ======= Połączenia sygnałów =======
        self.act_scan.triggered.connect(self.on_scan_clicked)
        self.act_refresh.triggered.connect(self.on_refresh_clicked)
        self.act_connect.triggered.connect(self.on_connect_clicked)
        self.act_disconnect.triggered.connect(self.on_disconnect_clicked)
        self.act_pair.triggered.connect(self.on_pair_clicked)
        self.act_unpair.triggered.connect(self.on_unpair_clicked)
        self.act_trust.triggered.connect(self.on_trust_clicked)
        self.act_untrust.triggered.connect(self.on_untrust_clicked)
        self.act_fav_add.triggered.connect(self.on_fav_add_clicked)
        self.act_fav_remove.triggered.connect(self.on_fav_remove_clicked)
        self.act_hide.triggered.connect(self.on_hide_clicked)
        self.act_unhide.triggered.connect(self.on_unhide_clicked)
        self.act_delete.triggered.connect(self.on_delete_clicked)
        self.act_export.triggered.connect(self.on_export_clicked)
        self.act_theme.triggered.connect(self.on_toggle_theme)
        self.act_reset.triggered.connect(self.on_reset_clicked)
        self.act_toggle_bottom.triggered.connect(self.on_toggle_bottom_clicked)

        self.search_edit.textChanged.connect(self._on_filter_changed)
        for view in (self.view_main, self.view_hidden, self.view_archive, self.view_favorites):
            view.selectionModel().selectionChanged.connect(self._on_selection_changed)
            view.customContextMenuRequested.connect(self._on_context_menu)
        self.tabs.currentChanged.connect(lambda _: self._on_selection_changed())

        # Pierwsze zbudowanie tabel
        self._rebuild_tables()
        self._update_actions_state()

    def closeEvent(self, event: QtGui.QCloseEvent) -> None:
        self._save_settings()
        self._save_db()
        super().closeEvent(event)

    # ---------- Pomocnicze UI ----------
    def _apply_bottom_panel_hidden(self, hidden: bool):
        self.bottom_panel_hidden = hidden
        if hidden:
            self.splitter.setSizes([1, 0])
        else:
            self.splitter.setSizes([2, 1])

    def on_toggle_bottom_clicked(self):
        self._apply_bottom_panel_hidden(not self.bottom_panel_hidden)

    def _active_view_and_model(self):
        idx = self.tabs.currentIndex()
        if idx == 0:
            return self.view_main, self.model_main, self.proxy_main
        if idx == 1:
            return self.view_hidden, self.model_hidden, self.proxy_hidden
        if idx == 2:
            return self.view_archive, self.model_archive, self.proxy_archive
        return self.view_favorites, self.model_favorites, self.proxy_favorites

    def _on_filter_changed(self, text: str):
        self.proxy_main.setFilterFixedString(text)
        self.proxy_hidden.setFilterFixedString(text)
        self.proxy_archive.setFilterFixedString(text)
        self.proxy_favorites.setFilterFixedString(text)

    def _selected_address_from_view(self, view, model, proxy) -> Optional[str]:
        idxs = view.selectionModel().selectedRows()
        if not idxs:
            return None
        sidx = idxs[0]
        src = proxy.mapToSource(sidx)
        return model.item(src.row(), 1).text()

    def _on_selection_changed(self, *_):
        view, model, proxy = self._active_view_and_model()
        addr = self._selected_address_from_view(view, model, proxy)
        dev = self.devices.get(addr) if addr else None
        self._update_details(dev)
        self._update_actions_state()

    def _update_details(self, dev: Optional[DeviceInfo]):
        if not dev:
            self.details.clear()
            return
        self.details.setPlainText(json.dumps(dev.to_dict(), indent=2, ensure_ascii=False))

    def _current_device(self) -> Optional[DeviceInfo]:
        view, model, proxy = self._active_view_and_model()
        addr = self._selected_address_from_view(view, model, proxy)
        return self.devices.get(addr) if addr else None

    def _update_actions_state(self):
        dev = self._current_device()
        has = dev is not None

        # domyślne
        for a in (self.act_connect, self.act_disconnect, self.act_pair, self.act_unpair,
                  self.act_trust, self.act_untrust, self.act_fav_add, self.act_fav_remove,
                  self.act_hide, self.act_unhide, self.act_delete):
            a.setEnabled(has)

        # Widoczność/etykiety zależne od stanu
        if not has:
            return

        # Connect/Disconnect
        self.act_connect.setVisible(not dev.connected)
        self.act_disconnect.setVisible(bool(dev.connected))

        # Pair/Unpair
        self.act_pair.setVisible(not dev.paired)
        self.act_unpair.setVisible(bool(dev.paired))

        # Trust/Untrust
        self.act_trust.setVisible(not dev.trusted)
        self.act_untrust.setVisible(bool(dev.trusted))

        addr_up = dev.address.upper()
        in_fav = addr_up in self.favorites
        in_hidden = addr_up in self.blocked

        # Favorites
        self.act_fav_add.setVisible(not in_fav)
        self.act_fav_remove.setVisible(in_fav)

        # Hidden
        self.act_hide.setVisible(not in_hidden)
        self.act_unhide.setVisible(in_hidden)

    def _on_context_menu(self, pos: QtCore.QPoint):
        view, model, proxy = self._active_view_and_model()
        menu = QtWidgets.QMenu(self)

        # Sekcje wg opisu
        menu.addAction(self.act_scan)
        menu.addSeparator()
        menu.addAction(self.act_refresh)
        menu.addSeparator()
        # dynamiczne pary
        if self.act_connect.isVisible(): menu.addAction(self.act_connect)
        if self.act_disconnect.isVisible(): menu.addAction(self.act_disconnect)
        if self.act_pair.isVisible(): menu.addAction(self.act_pair)
        if self.act_unpair.isVisible(): menu.addAction(self.act_unpair)
        if self.act_trust.isVisible(): menu.addAction(self.act_trust)
        if self.act_untrust.isVisible(): menu.addAction(self.act_untrust)
        menu.addSeparator()
        if self.act_fav_add.isVisible(): menu.addAction(self.act_fav_add)
        if self.act_fav_remove.isVisible(): menu.addAction(self.act_fav_remove)
        if self.act_hide.isVisible(): menu.addAction(self.act_hide)
        if self.act_unhide.isVisible(): menu.addAction(self.act_unhide)
        menu.addAction(self.act_delete)
        menu.addSeparator()
        menu.addAction(self.act_export)
        menu.addAction(self.act_theme)
        menu.addAction(self.act_toggle_bottom)
        menu.addSeparator()
        menu.addAction(self.act_reset)

        menu.exec(view.mapToGlobal(pos))

    # ---------- Akcje (logika) ----------
    @asyncSlot()
    async def on_scan_clicked(self):
        await self.scan_all()

    @asyncSlot()
    async def on_refresh_clicked(self):
        await self.refresh_all()

    @asyncSlot()
    async def on_connect_clicked(self):
        dev = self._current_device()
        if not dev: return
        await self._safe_action(self._connect_addr_smart, dev.address)

    @asyncSlot()
    async def on_disconnect_clicked(self):
        dev = self._current_device()
        if not dev: return
        await self._safe_action(self._disconnect_addr, dev.address)

    @asyncSlot()
    async def on_pair_clicked(self):
        dev = self._current_device()
        if not dev: return
        await self._safe_action(self._pair_addr_only, dev.address)

    @asyncSlot()
    async def on_unpair_clicked(self):
        dev = self._current_device()
        if not dev: return
        ok = QtWidgets.QMessageBox.question(self, "Usuń parowanie",
                                            f"Czy na pewno usunąć parowanie urządzenia {dev.address}?")
        if ok == QtWidgets.QMessageBox.Yes:
            await self._safe_action(self._unpair_addr, dev.address)

    @asyncSlot()
    async def on_trust_clicked(self):
        dev = self._current_device()
        if not dev: return
        await self._safe_action(self._trust_addr, dev.address, True)

    @asyncSlot()
    async def on_untrust_clicked(self):
        dev = self._current_device()
        if not dev: return
        await self._safe_action(self._trust_addr, dev.address, False)

    @QtCore.Slot()
    def on_fav_add_clicked(self):
        dev = self._current_device()
        if not dev: return
        a = dev.address.upper()
        self.blocked.discard(a)
        self.favorites.add(a)
        self._save_db()
        self._rebuild_tables()

    @QtCore.Slot()
    def on_fav_remove_clicked(self):
        dev = self._current_device()
        if not dev: return
        a = dev.address.upper()
        if a in self.favorites:
            self.favorites.remove(a)
            self._save_db()
            self._rebuild_tables()

    @QtCore.Slot()
    def on_hide_clicked(self):
        dev = self._current_device()
        if not dev: return
        a = dev.address.upper()
        self.favorites.discard(a)
        self.blocked.add(a)
        self._save_db()
        self._rebuild_tables()

    @QtCore.Slot()
    def on_unhide_clicked(self):
        dev = self._current_device()
        if not dev: return
        a = dev.address.upper()
        if a in self.blocked:
            self.blocked.remove(a)
            self._save_db()
            self._rebuild_tables()

    @asyncSlot()
    async def on_delete_clicked(self):
        dev = self._current_device()
        if not dev: return
        addr = dev.address

        ok_local = QtWidgets.QMessageBox.question(
            self, "Usuń urządzenie z listy",
            f"Usunąć z lokalnej bazy urządzenie {addr}?\n"
            f"(Nie usuwa z systemowego BlueZ)"
        )
        if ok_local != QtWidgets.QMessageBox.Yes:
            return

        dev_ref = self.devices.get(addr)
        also_bluez = False
        if dev_ref and dev_ref.object_path and dev_ref.adapter_path:
            ans = QtWidgets.QMessageBox.question(
                self, "Usuń również z BlueZ",
                "Czy chcesz również **usunąć z systemowego BlueZ** (Adapter1.RemoveDevice)?",
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No
            )
            also_bluez = (ans == QtWidgets.QMessageBox.Yes)

        up = addr.upper()
        self.blocked.discard(up)
        self.favorites.discard(up)
        if addr in self.devices:
            del self.devices[addr]
        self._save_db()
        self._rebuild_tables()
        self.details.clear()

        if also_bluez and dev_ref:
            await self._safe_action(self._remove_from_bluez_by_info, dev_ref)

    def on_export_clicked(self):
        out = {
            "exported_at": QtCore.QDateTime.currentDateTimeUtc().toString(Qt.ISODate) + "Z",
            "blocked": sorted(self.blocked),
            "favorites": sorted(self.favorites),
            "devices": {addr: dev.to_dict() for addr, dev in self.devices.items()},
        }
        path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Zapisz jako", "bt_devices.json", "JSON (*.json)"
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(out, f, indent=2, ensure_ascii=False)
            QtWidgets.QMessageBox.information(self, "OK", f"Zapisano do: {path}")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Błąd", f"Nie udało się zapisać: {e}")

    # ---------- Bezpieczeństwo akcji ----------
    def _explain_bluetooth_error(self, e: Exception) -> Optional[str]:
        s = str(e)
        if "org.bluez.Error.AuthenticationFailed" in s:
            return (
                "Parowanie nie powiodło się (AuthenticationFailed).\n\n"
                "Upewnij się, że urządzenie jest w trybie parowania i nie ma starego parowania."
            )
        if "org.freedesktop.DBus.Error.UnknownObject" in s:
            return (
                "System BlueZ nie ma już obiektu dla tego urządzenia.\n"
                "Odśwież listę (Skanuj/Odśwież) i spróbuj ponownie."
            )
        # >>> DODANE: wyjaśnienie dla ogólnego 'Failed' <<<
        if "org.bluez.Error.Failed" in s:
            return (
                "Nie udało się połączyć (org.bluez.Error.Failed).\n\n"
                "Częste przyczyny: urządzenie nie jest w zasięgu/wybudzone, "
                "profil nieobsługiwany, konflikt z inną aplikacją.\n"
                "Spróbuj: włączyć tryb parowania/advertising, ponowić skan i połączyć ponownie."
            )
        return None

    async def _safe_action(self, fn, *args):
        try:
            self.setDisabled(True)
            await fn(*args)
        except Exception as e:
            msg = self._explain_bluetooth_error(e)
            if msg:
                QtWidgets.QMessageBox.warning(self, "Parowanie/połączenie", msg)
                logger.warning(str(e))
            else:
                QtWidgets.QMessageBox.critical(self, "Błąd", str(e))
                logger.exception(e)
        finally:
            self.setDisabled(False)
            await self.refresh_all()

    # ---------- Łączenie ----------
    async def _connect_addr_smart(self, addr: str):
        await self.bluez.power_on_adapters()
        dev = self.devices.get(addr)
        if not dev:
            # było: raise RuntimeError(...)
            QtWidgets.QMessageBox.warning(self, "Połączenie", "Nie znaleziono urządzenia w bazie.")
            return
        try:
            await self.bluez.stop_discovery_on_all_adapters()
        except Exception:
            pass
        if not dev.paired:
            logger.info(f"{addr}: nie sparowane – próba parowania…")
            try:
                await self.bluez.pair(dev)
            except Exception as e:
                if "InProgress" in str(e):
                    await asyncio.sleep(2)
                    await self.bluez.pair(dev)
                else:
                    # zostawiamy komunikat, ale nie wywalamy wyjątku dalej
                    raise

        try:
            await self.bluez.set_trusted(dev, True)
        except Exception as e:
            logger.warning(f"{addr}: nie udało się ustawić Trusted: {e}")

        # Główna próba Connect
        try:
            await self.bluez.connect(dev)
            logger.info(f"{addr}: połączono (Device1.Connect).")
            return
        except Exception as e:
            logger.warning(f"{addr}: Connect() nie powiodło się: {e}")

        # Kolejne profile wg priorytetu
        uuids = [u.lower() for u in (dev.uuids or [])]
        for uuid in self.PROFILE_PRIORITY:
            if uuid in uuids:
                try:
                    logger.info(f"{addr}: próba ConnectProfile({uuid})…")
                    await self.bluez.connect_profile(dev, uuid)
                    logger.info(f"{addr}: połączono profil {uuid}.")
                    return
                except Exception as e:
                    logger.warning(f"{addr}: ConnectProfile({uuid}) nie powiodło się: {e}")

        # BLE fallback (jeśli wygląda na BLE)
        if dev.looks_like_ble():
            try:
                logger.info(f"{addr}: BLE fallback – próba GATT (BleakClient.connect)…")
                async with BleakClient(addr) as client:
                    if await client.is_connected():
                        logger.info(f"{addr}: GATT połączony (Bleak).")
                        return
            except Exception as e:
                logger.warning(f"{addr}: BLE fallback nieudany: {e}")

        # >>> ZMIANA: nie rzucamy wyjątku, tylko pokazujemy komunikat i kończymy łagodnie <<<
        QtWidgets.QMessageBox.warning(
            self, "Połączenie",
            "Nie udało się połączyć z urządzeniem.\n"
            "Upewnij się, że urządzenie jest aktywne/w zasięgu, włącz skan i spróbuj ponownie."
        )
        logger.warning(f"{addr}: wszystkie próby połączenia nieudane – kończę bez wyjątku.")
        return

    async def _disconnect_addr(self, addr: str):
        dev = self.devices.get(addr)
        if not dev:
            raise RuntimeError("Nie znaleziono urządzenia.")
        await self.bluez.disconnect(dev)

    async def _pair_addr_only(self, addr: str):
        await self.bluez.power_on_adapters()
        dev = self.devices.get(addr)
        if not dev:
            raise RuntimeError("Nie znaleziono urządzenia.")
        logger.info(f"{addr}: przygotowanie do parowania – sprawdzam obecność node w BlueZ…")
        await self.bluez.pair(dev)
        await self.bluez.set_trusted(dev, True)

    async def _unpair_addr(self, addr: str):
        dev = self.devices.get(addr)
        if not dev:
            raise RuntimeError("Nie znaleziono urządzenia.")
        await self.bluez.remove_device(dev)

    async def _trust_addr(self, addr: str, value: bool):
        dev = self.devices.get(addr)
        if not dev:
            raise RuntimeError("Nie znaleziono urządzenia.")
        await self.bluez.set_trusted(dev, value)

    async def _remove_from_bluez_by_info(self, dev: DeviceInfo):
        await self.bluez.remove_device(dev)
        logger.info(f"{dev.address}: usunięto z BlueZ (RemoveDevice).")

    # ---------- Skanowanie / odświeżanie ----------
    def _start_scan_anim(self):
        self._is_scanning = True
        self._scan_anim_state = 0
        self.scan_anim_timer.start()
        self._tick_scan_anim()

    def _stop_scan_anim(self):
        self.scan_anim_timer.stop()
        self._is_scanning = False
        self.statusBar().clearMessage()

    def _tick_scan_anim(self):
        dots = "." * (self._scan_anim_state % 4)
        self.statusBar().showMessage(f"Skanowanie{dots}")
        self._scan_anim_state += 1

    async def refresh_all(self):
        self.statusBar().showMessage("Odświeżanie…")
        try:
            await self._refresh_model()
        finally:
            self.statusBar().clearMessage()
            self._save_db()
            self._update_actions_state()

    async def scan_all(self):
        if platform.system() != "Linux":
            QtWidgets.QMessageBox.warning(self, "Uwaga", "Discovery działa w pełni na Linuxie (BlueZ).")
        self._start_scan_anim()
        scan_token = time.time()
        try:
            await self.bluez.power_on_adapters()
            await self.bluez.start_discovery_on_all_adapters()
            ble_task = asyncio.create_task(bleak_scan(BLE_SCAN_SECONDS))
            await asyncio.sleep(DISCOVERY_SECONDS)
            await self.bluez.stop_discovery_on_all_adapters()
            bluez_devs = await self.bluez.list_devices()
            ble_map = await ble_task
            for addr, add in ble_map.items():
                if addr in bluez_devs:
                    di = bluez_devs[addr]
                    if di.rssi is None:
                        di.rssi = add.get("rssi")
                    di.uuids = list({*(di.uuids or []), *add.get("uuids", [])})
                    di.manufacturer_data.update(add.get("manufacturer_data") or {})
                    di.service_data.update(add.get("service_data") or {})
                    di.details.update(add.get("details") or {})
                else:
                    di = DeviceInfo(address=addr,
                                    name=add.get("name"),
                                    rssi=add.get("rssi"),
                                    uuids=list(add.get("uuids") or []),
                                    manufacturer_data=add.get("manufacturer_data") or {},
                                    service_data=add.get("service_data") or {},
                                    details=add.get("details") or {})
                    bluez_devs[addr] = di
                di = bluez_devs[addr]
                di.available = True
                di.last_seen = scan_token

            for addr, di in bluez_devs.items():
                if di.connected:
                    di.available = True
                    di.last_seen = di.last_seen or scan_token
                elif di.last_seen != scan_token:
                    di.available = False

            for addr, old in list(self.devices.items()):
                if addr in bluez_devs:
                    cur = bluez_devs[addr]
                    if old.uuids and not cur.uuids:
                        cur.uuids = old.uuids
                    if old.manufacturer_data and not cur.manufacturer_data:
                        cur.manufacturer_data = old.manufacturer_data
                    if old.service_data and not cur.service_data:
                        cur.service_data = old.service_data
                    if old.services and not cur.services:
                        cur.services = old.services
                    if old.characteristics and not cur.characteristics:
                        cur.characteristics = old.characteristics

            self.devices = {**self.devices, **bluez_devs}
            self._rebuild_tables()
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Błąd skanowania", str(e))
            logger.exception(e)
        finally:
            self._stop_scan_anim()
            self._save_db()
            self._update_actions_state()

    async def _refresh_model(self):
        devs = await self.bluez.list_devices()
        for addr, old in self.devices.items():
            if addr in devs:
                cur = devs[addr]
                if old.uuids and not cur.uuids:
                    cur.uuids = old.uuids
                if old.manufacturer_data and not cur.manufacturer_data:
                    cur.manufacturer_data = old.manufacturer_data
                if old.service_data and not cur.service_data:
                    cur.service_data = old.service_data
                if old.services and not cur.services:
                    cur.services = old.services
                if old.characteristics and not cur.characteristics:
                    cur.characteristics = old.characteristics
                if not cur.available:
                    cur.available = old.available
                    cur.last_seen = old.last_seen
            else:
                devs[addr] = old
                devs[addr].available = False
        self.devices = devs
        self._rebuild_tables()

    def _rebuild_tables(self):
        for m in (self.model_main, self.model_hidden, self.model_archive, self.model_favorites):
            m.removeRows(0, m.rowCount())

        for addr, dev in sorted(self.devices.items()):
            a = addr.upper()
            if getattr(self, "just_reset", False) and dev.available and a in self.blocked:
                self.blocked.discard(a)

            if a in self.favorites:
                self.model_favorites.add_or_update(dev)
                continue
            if a in self.blocked:
                self.model_hidden.add_or_update(dev)
                continue
            if dev.available or dev.connected:
                self.model_main.add_or_update(dev)
            else:
                self.model_archive.add_or_update(dev)

        for v in (self.view_main, self.view_hidden, self.view_archive, self.view_favorites):
            v.resizeColumnsToContents()

        if getattr(self, "just_reset", False):
            self.just_reset = False
            self._save_db()

        view, model, proxy = self._active_view_and_model()
        addr = self._selected_address_from_view(view, model, proxy)
        self._update_details(self.devices.get(addr) if addr else None)

    # ---------- Post init ----------
    async def _post_init_async(self):
        await self.bluez.ensure_bus()
        agent = QtAgent(self)
        self.bluez.attach_agent(agent)
        try:
            await self.bluez.register_agent("KeyboardDisplay")
        except Exception as e:
            logger.warning(f"Rejestracja agenta nie powiodła się (może już istnieje lub brak metody): {e}")
        await self.bluez.power_on_adapters()
        await self.refresh_all()

    def _post_init(self):
        asyncio.get_event_loop().create_task(self._post_init_async())

    @asyncSlot()
    async def on_reset_clicked(self):
        msg = ("To **usunie wszystkie parowania/urządzenia** z BlueZ oraz **wyczyści lokalną bazę**.\n\n"
               "Po tym skanowaniu urządzenia pojawią się jak „nowe”. Kontynuować?")
        ok = QtWidgets.QMessageBox.question(
            self, "Reset Bluetooth", msg,
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No
        )
        if ok != QtWidgets.QMessageBox.Yes:
            return
        try:
            self.setDisabled(True)
            try:
                await self.bluez.stop_discovery_on_all_adapters()
            except Exception:
                pass
            removed = await self.bluez.remove_all_devices()
            logger.info(f"BlueZ: usunięto {removed} urządzeń.")
            await self.bluez.power_cycle_adapters()
            await self.bluez.set_discovery_filter_default()

            self.devices.clear()
            self.blocked.clear()
            self.favorites.clear()
            try:
                if BLOCK_FILE.exists():
                    BLOCK_FILE.unlink()
            except Exception as e:
                logger.warning(f"Nie udało się usunąć {BLOCK_FILE}: {e}")
            self._save_db()

            try:
                await self.bluez.start_discovery_on_all_adapters()
                await asyncio.sleep(3.0)
            finally:
                await self.bluez.stop_discovery_on_all_adapters()

            self.just_reset = True
            await self.refresh_all()
            self.details.clear()

            QtWidgets.QMessageBox.information(
                self, "Reset zakończony",
                f"Usunięto z BlueZ: {removed}. Adaptery przełączone. "
                "Włącz tryb parowania/advertising na urządzeniach i kliknij „Skanuj”."
            )
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Błąd resetu", str(e))
            logger.exception(e)
        finally:
            self.setDisabled(False)


# ==========================
# Uruchomienie aplikacji
# ==========================
def main():
    app = QtWidgets.QApplication(sys.argv)
    app.setApplicationName(APP_NAME)

    loop = QEventLoop(app)
    asyncio.set_event_loop(loop)

    w = MainWindow()
    w.show()

    with loop:
        loop.run_forever()


if __name__ == "__main__":
    main()
