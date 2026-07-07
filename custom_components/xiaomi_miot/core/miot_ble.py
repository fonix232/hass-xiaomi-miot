"""mible V2 BLE transport for Xiaomi MIoT devices.

Implements the same ``async_get_properties_for_mapping`` / ``async_send``
interface as ``MiotDevice`` (local WiFi transport) so it can plug directly
into hass-xiaomi-miot's ``Device`` class as a third transport option
alongside ``local`` (WiFi) and ``cloud``.

Protocol: mible V2 — AES-128-CCM encrypted GATT session with HKDF-derived
per-session keys exchanged over characteristic 0x0019.

GATT service UUID: 0000fe95-0000-1000-8000-00805f9b34fb

Handshake overview (4 phases):
  Phase 1 — info exchange : firmware/model string read over 0x001c
  Phase 2 — version ping  : echo 0x04 pings on 0x0019
  Phase 3 — key exchange  : HKDF nonce + HMAC proof on 0x0019
  Phase 4 — encrypted     : AES-128-CCM on 0x001a (TX) / 0x001b (RX)
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac as _hmac
import logging
import os
import struct
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Optional

from bleak.backends.device import BLEDevice
from bleak_retry_connector import BleakClientWithServiceCache, establish_connection
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from homeassistant.components import bluetooth
from homeassistant.core import HomeAssistant

if TYPE_CHECKING:
    from .miot_spec import MiotSpec

_LOGGER = logging.getLogger(__name__)

# ── GATT characteristic UUIDs (mible V2, service 0000fe95-...) ────────────────
_CHAR_CMD  = "00000010-0000-1000-8000-00805f9b34fb"  # CMD  (login / error codes)
_CHAR_AUTH = "00000019-0000-1000-8000-00805f9b34fb"  # Auth (key exchange)
_CHAR_TX   = "0000001a-0000-1000-8000-00805f9b34fb"  # TX   (encrypted app→dev)
_CHAR_RX   = "0000001b-0000-1000-8000-00805f9b34fb"  # RX   (encrypted dev→app)
_CHAR_INFO = "0000001c-0000-1000-8000-00805f9b34fb"  # Info (firmware / model)

# ── Timeouts ──────────────────────────────────────────────────────────────────
_HANDSHAKE_TIMEOUT    = 10.0  # seconds per handshake exchange step
_STATE_TIMEOUT        = 5.0   # seconds to wait for a properties response
_WRITE_SUPPRESS_SECS  = 5.0   # suppress push-report reverts for this long after a write

# ── HKDF / CCM parameters ─────────────────────────────────────────────────────
_HKDF_INFO    = b"mible-login-info"
_HKDF_LEN     = 64
_CCM_TAG_LEN  = 4
_CCM_NONCE_LEN = 12

# ── Wire-format type codes (high nibble of type_len LE u16) ───────────────────
# type_len encoding: ((type_code << 12) | byte_length) stored as LE u16
# e.g. uint8 → (1<<12)|1 = 0x1001 → wire bytes [0x01, 0x10]
_FMT_TYPE: dict[str, int] = {
    "bool":   1,
    "uint8":  1,
    "int8":   1,
    "uint16": 3,
    "int16":  3,
    "uint32": 5,
    "int32":  5,
    "float":  5,
    "string": 7,
}

# ── Crypto helpers ────────────────────────────────────────────────────────────

def _gen_nonce() -> bytes:
    return os.urandom(16)


def _derive_session_keys(
    token: bytes,
    app_nonce: bytes,
    dev_nonce: bytes,
) -> tuple[bytes, bytes, bytes, bytes]:
    """HKDF-SHA256 (RFC 5869). Returns (rx_key, tx_key, rx_pfx, tx_pfx)."""
    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=_HKDF_LEN,
        salt=app_nonce + dev_nonce,
        info=_HKDF_INFO,
    ).derive(token)
    return okm[0:16], okm[16:32], okm[32:36], okm[36:40]


def _build_ccm_nonce(pfx: bytes, seq: int, ovf: int) -> bytes:
    return pfx + b"\x00\x00\x00\x00" + struct.pack("<HH", seq, ovf)


def _ccm_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    return AESCCM(key, tag_length=_CCM_TAG_LEN).encrypt(nonce, plaintext, None)


def _ccm_decrypt(key: bytes, nonce: bytes, ct_with_tag: bytes) -> bytes:
    return AESCCM(key, tag_length=_CCM_TAG_LEN).decrypt(nonce, ct_with_tag, None)


def _verify_dev_proof(
    rx_key: bytes, dev_nonce: bytes, app_nonce: bytes, proof: bytes
) -> None:
    expected = _hmac.new(rx_key, dev_nonce + app_nonce, hashlib.sha256).digest()
    if not _hmac.compare_digest(expected, proof):
        raise RuntimeError("Device HMAC proof verification failed")


def _compute_app_proof(
    tx_key: bytes, app_nonce: bytes, dev_nonce: bytes
) -> bytes:
    return _hmac.new(tx_key, app_nonce + dev_nonce, hashlib.sha256).digest()


# ── Value encode / decode ─────────────────────────────────────────────────────

def _encode_prop_value(value, fmt: str) -> bytes:
    """Encode a Python value to raw wire bytes for a given MIoT format string."""
    if fmt == "bool":
        return bytes([1 if value else 0])
    if fmt in ("uint8", "int8"):
        return bytes([int(value) & 0xFF])
    if fmt == "uint16":
        return struct.pack("<H", int(value))
    if fmt == "int16":
        return struct.pack("<h", int(value))
    if fmt == "uint32":
        return struct.pack("<I", int(value))
    if fmt == "int32":
        return struct.pack("<i", int(value))
    if fmt == "float":
        return struct.pack("<f", float(value))
    if fmt == "string":
        return str(value).encode("utf-8")
    _LOGGER.warning("miot_ble: unknown format %r, falling back to uint8", fmt)
    return bytes([int(value) & 0xFF])


def _decode_prop_value(raw: bytes, fmt: str):
    """Decode raw wire bytes to a Python value for a given MIoT format string."""
    if not raw:
        return None
    if fmt == "bool":
        return bool(raw[0])
    if fmt == "uint8":
        return raw[0]
    if fmt == "int8":
        v = raw[0]
        return v - 256 if v >= 128 else v
    if fmt in ("uint16",) and len(raw) >= 2:
        return struct.unpack_from("<H", raw)[0]
    if fmt == "int16" and len(raw) >= 2:
        return struct.unpack_from("<h", raw)[0]
    if fmt == "uint32" and len(raw) >= 4:
        return struct.unpack_from("<I", raw)[0]
    if fmt == "int32" and len(raw) >= 4:
        return struct.unpack_from("<i", raw)[0]
    if fmt == "float" and len(raw) >= 4:
        return struct.unpack_from("<f", raw)[0]
    if fmt == "string":
        return raw.decode("utf-8", errors="replace")
    # Fallback: interpret by byte count (unsigned)
    return int.from_bytes(raw, "little")


def _infer_format(value) -> str:
    """Infer a MIoT format string from a Python value's type and magnitude.

    Used when the MIoT spec is not available to provide an explicit format.
    """
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "string"
    if isinstance(value, int):
        v = abs(value)
        if v <= 0xFF:
            return "uint8"
        if v <= 0xFFFF:
            return "uint16"
        return "uint32"
    return "uint8"


# ── Frame builders ────────────────────────────────────────────────────────────

def _build_get_properties_payload(fc: int, props: list[tuple[int, int]]) -> bytes:
    """Build a get_properties (opcode 0x02) MIIO plaintext frame.

    Props: list of (siid, piid) pairs.
    Frame: [total_len:1][0x20][fc:2 LE][0x02][count:1][siid piid …]
    """
    body = b"".join(bytes([siid]) + struct.pack("<H", piid) for siid, piid in props)
    n = 6 + len(body)
    return bytes([n, 0x20]) + struct.pack("<H", fc) + bytes([0x02, len(props)]) + body


def _build_set_properties_payload(
    fc: int, props: list[tuple[int, int, bytes]]
) -> bytes:
    """Build a set_properties (opcode 0x00) MIIO plaintext frame.

    Props: list of (siid, piid, type_len_and_value_bytes) where the third
    element is ``struct.pack("<H", type_len) + raw_value``.

    Frame: [total_len:1][0x20][fc:2 LE][0x00][count:1][records…]
    """
    records = b"".join(
        bytes([siid]) + struct.pack("<H", piid) + val_bytes
        for siid, piid, val_bytes in props
    )
    n = 6 + len(records)
    return bytes([n, 0x20]) + struct.pack("<H", fc) + bytes([0x00, len(props)]) + records


# ── Frame parser ─────────────────────────────────────────────────────────────

def _parse_rsp(data: bytes, spec: Optional["MiotSpec"] = None) -> list[dict]:
    """Parse a get_properties_rsp (opcode 0x03) or property_report (opcode 0x04).

    Returns ``[{'siid': S, 'piid': P, 'value': V, 'code': 0}, …]``.

    If ``spec`` is provided, the MIoT property format is used for correct
    signed/float decoding.  Without it, unsigned integers are assumed.
    """
    if len(data) < 6:
        return []
    if (struct.unpack_from("<H", data, 0)[0] & 0xE000) != 0x2000:
        return []
    opcode = data[4]
    if opcode not in (0x03, 0x04):
        return []

    count = data[5]
    offset = 6
    results = []
    for _ in range(count):
        if offset + 5 > len(data):
            break
        siid     = data[offset]
        piid     = struct.unpack_from("<H", data, offset + 1)[0]
        type_len = struct.unpack_from("<H", data, offset + 3)[0]
        vlen     = type_len & 0x0FFF
        type_code = type_len >> 12
        if offset + 5 + vlen > len(data):
            break
        raw = data[offset + 5: offset + 5 + vlen]

        # Resolve format: prefer spec lookup, fall back to wire type_code
        fmt: str | None = None
        if spec is not None:
            from .miot_spec import MiotSpec as _MS, MiotProperty
            mi = _MS.unique_prop(siid, piid=piid)
            prop = spec.specs.get(mi)
            if isinstance(prop, MiotProperty):
                fmt = prop.format

        if fmt:
            value = _decode_prop_value(raw, fmt)
        elif type_code == 7:
            value = raw.decode("utf-8", errors="replace")
        elif vlen == 1:
            value = raw[0]
        elif vlen == 2:
            value = struct.unpack_from("<H", raw)[0]
        elif vlen == 4:
            value = struct.unpack_from("<I", raw)[0]
        elif vlen == 8:
            value = struct.unpack_from("<Q", raw)[0]
        else:
            value = int.from_bytes(raw, "little")

        results.append({"siid": siid, "piid": piid, "value": value, "code": 0})
        offset += 5 + vlen
    return results


# ── Main transport class ──────────────────────────────────────────────────────

class MiotBleDevice:
    """mible V2 BLE transport implementing the MiotDevice interface.

    After creating an instance, set ``spec`` once the MIoT spec is available
    (``device.async_init`` does this) for proper signed/float decoding.

    Optionally set ``on_properties`` to receive push-notification callbacks
    whenever the device sends an unsolicited property_report over BLE.
    """

    def __init__(
        self,
        hass: HomeAssistant,
        mac: str,
        token: str,
        logger: logging.Logger | None = None,
    ) -> None:
        self.hass  = hass
        self.log   = logger or _LOGGER
        self._mac   = mac
        self._token = bytes.fromhex(token)

        # MIoT spec — injected by Device after the spec is loaded so that
        # _parse_rsp can use proper format info for signed / float values.
        self.spec: Optional["MiotSpec"] = None

        # Push-notification callback: called with decoded property list on
        # every get_properties_rsp or unsolicited property_report from the device.
        # Set by Device.async_init() to forward updates to dispatch().
        self.on_properties: Callable[[list[dict]], None] | None = None

        self._client: BleakClientWithServiceCache | None = None
        self._session_ready = False

        # Session keys (populated during _do_session_auth)
        self._rx_key:       bytes | None = None
        self._tx_key:       bytes | None = None
        self._rx_nonce_pfx: bytes | None = None
        self._tx_nonce_pfx: bytes | None = None

        # Sequence / overflow counters
        self._tx_seq = self._tx_ovf = 0
        self._rx_seq = self._rx_ovf = 0

        # MIIO frame counter (starts at 2, matches device captures)
        self._fc = 2

        # Handshake synchronisation queues
        self._cmd_queue:  asyncio.Queue[bytes] = asyncio.Queue()
        self._auth_queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._info_queue: asyncio.Queue[bytes] = asyncio.Queue()

        # Decoded property responses (get_properties_rsp + property_report)
        self._rx_queue: asyncio.Queue[list[dict]] = asyncio.Queue()

        # Recently-written properties: (siid, piid) → monotonic expiry time.
        # Push-notification updates for these keys are suppressed until expiry
        # so that ~1 Hz property_reports don't revert optimistic state updates.
        self._pending_writes: dict[tuple[int, int], float] = {}

        # Prevents concurrent connect() calls from racing each other
        self._connect_lock = asyncio.Lock()

    # ── Factory ───────────────────────────────────────────────────────────────

    @staticmethod
    def from_device(device) -> "MiotBleDevice | None":
        """Create a ``MiotBleDevice`` for *device* if BLE is configured.

        Returns ``None`` when:
        - ``miot_ble: true`` is not set in DEVICE_CUSTOMIZES for this model
        - the device has no MAC address
        - the device has no token
        """
        from .utils import get_customize_via_model
        cfg = get_customize_via_model(device.info.model)
        if not cfg.get('miot_ble'):
            return None
        mac   = device.info.mac
        token = device.info.token
        if not mac or not token:
            return None
        try:
            bytes.fromhex(token)
        except ValueError:
            return None
        return MiotBleDevice(device.hass, mac, token, device.log)

    # ── MiotDevice interface ──────────────────────────────────────────────────

    async def async_get_properties_for_mapping(
        self,
        *,
        max_properties: int | None = None,
        did: str | None = None,
        mapping: dict | None = None,
    ) -> list[dict]:
        """Query all properties in *mapping* over BLE.

        Returns ``[{'siid': S, 'piid': P, 'value': V, 'code': 0}, …]``
        in the same format as ``MiotDevice.async_get_properties_for_mapping``.
        """
        if not mapping:
            return []
        if not self._session_ready:
            await self.connect()

        props = [(v["siid"], v["piid"]) for v in mapping.values()]

        # Drain stale responses before issuing the request
        while not self._rx_queue.empty():
            self._rx_queue.get_nowait()

        payload = _build_get_properties_payload(self._fc, props)
        await self._send_encrypted(payload)  # increments self._fc

        try:
            results = await asyncio.wait_for(
                self._rx_queue.get(), timeout=_STATE_TIMEOUT
            )
        except asyncio.TimeoutError:
            self.log.warning(
                "miot_ble %s: no get_properties response within %.1fs",
                self._mac, _STATE_TIMEOUT,
            )
            return []

        # Filter to only the properties that were explicitly requested
        requested = {(v["siid"], v["piid"]) for v in mapping.values()}
        return [r for r in results if (r["siid"], r["piid"]) in requested]

    async def async_send(self, method: str, params):
        """Execute a MIoT method.  Currently supports ``set_properties``."""
        if method != "set_properties":
            self.log.warning("miot_ble: unsupported method %r", method)
            return []
        if not self._session_ready:
            await self.connect()

        prop_records = []
        for p in params:
            siid  = p["siid"]
            piid  = p["piid"]
            value = p["value"]
            fmt   = self._get_prop_format(siid, piid) or _infer_format(value)
            raw   = _encode_prop_value(value, fmt)
            type_code = _FMT_TYPE.get(fmt, 1)
            type_len_bytes = struct.pack("<H", (type_code << 12) | len(raw))
            prop_records.append((siid, piid, type_len_bytes + raw))

        payload = _build_set_properties_payload(self._fc, prop_records)
        await self._send_encrypted(payload)  # increments self._fc

        # Suppress incoming property_report reverts for these properties.
        expiry = time.monotonic() + _WRITE_SUPPRESS_SECS
        for p in params:
            self._pending_writes[(p["siid"], p["piid"])] = expiry

        # The device acknowledges set_properties asynchronously via RX; return
        # a synthetic success result so callers see no error immediately.
        return [{"siid": p["siid"], "piid": p["piid"], "code": 0} for p in params]

    def get_max_properties(self, mapping) -> int:
        """BLE has no practical chunk limit; return the full mapping size."""
        return len(mapping)

    # ── Session management ────────────────────────────────────────────────────

    async def connect(self) -> None:
        """Connect and run the full four-phase mible V2 handshake."""
        async with self._connect_lock:
            await self._connect_inner()

    async def _connect_inner(self) -> None:
        """Inner connect — must only be called while holding ``_connect_lock``."""
        if self._session_ready and self._client and self._client.is_connected:
            return  # A concurrent caller already connected
        self._session_ready = False
        self._rx_key = self._tx_key = None
        self._fc = 2
        self._tx_seq = self._tx_ovf = 0
        self._rx_seq = self._rx_ovf = 0

        # Clean up any lingering connection so the device sees a fresh session
        if self._client and self._client.is_connected:
            try:
                await self._client.disconnect()
            except Exception:  # noqa: BLE001
                pass
        self._client = None

        for q in (self._cmd_queue, self._auth_queue, self._info_queue, self._rx_queue):
            while not q.empty():
                q.get_nowait()

        ble_device = (
            bluetooth.async_ble_device_from_address(
                self.hass, self._mac, connectable=True
            )
            or bluetooth.async_ble_device_from_address(
                self.hass, self._mac, connectable=False
            )
        )

        if ble_device is None:
            self.log.debug(
                "miot_ble: %s not in BT scanner cache; connecting directly", self._mac
            )
            ble_device = BLEDevice(self._mac, None, {}, -127)

        self._client = await establish_connection(
            BleakClientWithServiceCache, ble_device, self._mac,
            disconnected_callback=self._on_disconnect,
        )

        self.log.debug("miot_ble: BLE connected to %s", self._mac)

        # Force StartNotify (not AcquireNotify) on all characteristics so
        # BlueZ releases the notification fd when the session ends.
        _sn = {"bluez": {"use_start_notify": True}}
        await self._client.start_notify(_CHAR_CMD,  self._on_cmd,  **_sn)
        await self._client.start_notify(_CHAR_AUTH, self._on_auth, **_sn)
        await self._client.start_notify(_CHAR_INFO, self._on_info, **_sn)
        await self._client.start_notify(_CHAR_RX,   self._on_rx,   **_sn)

        await self._do_info_exchange()
        await self._write(_CHAR_CMD, b"\xa4")
        await self._do_version_ping()
        await self._write(_CHAR_CMD, b"\x24\x00\x00\x00")
        try:
            await self._do_session_auth()
        except Exception:
            try:
                await self._client.disconnect()
            except Exception:  # noqa: BLE001
                pass
            raise

        # Mandatory unencrypted session-init frame before any encrypted traffic
        await self._write(_CHAR_TX, b"\x00\x00\x00\x00\x01\x00")

        # Sync the device clock and trigger an immediate property_report.
        # SIID=3 PIID=8 (unix_time, uint32) is standard on mible V2 devices;
        # if the device doesn't support it the error is silently ignored.
        _time_val   = struct.pack("<I", int(time.time()))
        _time_tl    = struct.pack("<H", (5 << 12) | 4)  # uint32, 4 bytes
        _time_frame = _build_set_properties_payload(
            self._fc, [(3, 8, _time_tl + _time_val)]
        )
        await self._send_encrypted(_time_frame)  # increments self._fc

        # Wait for the property_report triggered by the time sync.
        # If it doesn't arrive in time, fall back to an explicit poll.
        try:
            await asyncio.wait_for(self._rx_queue.get(), timeout=_STATE_TIMEOUT)
        except asyncio.TimeoutError:
            self.log.debug(
                "miot_ble: no initial property_report within %.1fs; will poll",
                _STATE_TIMEOUT,
            )

        self._session_ready = True
        self.log.debug("miot_ble: session ready for %s", self._mac)

    async def disconnect(self) -> None:
        """Stop notifications and disconnect."""
        self._session_ready = False
        if self._client and self._client.is_connected:
            for uuid in (_CHAR_CMD, _CHAR_AUTH, _CHAR_INFO, _CHAR_TX, _CHAR_RX):
                try:
                    await self._client.stop_notify(uuid)
                except Exception:  # noqa: BLE001
                    pass
            await self._client.disconnect()

    @property
    def is_connected(self) -> bool:
        return (
            self._session_ready
            and self._client is not None
            and self._client.is_connected
        )

    # ── Handshake phases ──────────────────────────────────────────────────────

    async def _do_info_exchange(self) -> None:
        """Phase 1: read firmware/model string from 0x001c (6 round trips)."""
        await self._write(_CHAR_INFO, b"\x00")
        await self._wait(self._info_queue, _HANDSHAKE_TIMEOUT)

        for offset in (0x00, 0x11, 0x22, 0x33):
            await self._write(_CHAR_INFO, bytes([0x08, 0x01, offset]))
            await self._wait(self._info_queue, _HANDSHAKE_TIMEOUT)

        await self._write(_CHAR_INFO, b"\x03")
        model_resp = await self._wait(self._info_queue, _HANDSHAKE_TIMEOUT)
        if len(model_resp) >= 3 and model_resp[0] == 0x03:
            model = model_resp[2:].decode("ascii", errors="replace")
            self.log.debug("miot_ble: device reports model %r", model)

    async def _do_version_ping(self) -> None:
        """Phase 2: acknowledge 0x04 version pings from the device on 0x0019."""
        while True:
            try:
                frame = await asyncio.wait_for(self._auth_queue.get(), timeout=3.0)
            except asyncio.TimeoutError:
                break
            if len(frame) >= 3 and frame[2] == 0x04:
                await self._write(_CHAR_AUTH, frame[:2] + b"\x05" + frame[3:])
            else:
                self._auth_queue.put_nowait(frame)
                break

    async def _do_session_auth(self) -> None:
        """Phase 3: HKDF nonce exchange + mutual HMAC proof on 0x0019."""
        app_nonce = _gen_nonce()

        await self._write_auth(b"\x00\x00\x00\x0b\x01\x00")
        data = await self._wait_auth_or_cmd_err(_HANDSHAKE_TIMEOUT)
        if data != b"\x00\x00\x01\x01":
            raise RuntimeError(f"miot_ble: expected RCV_RDY, got {data.hex()}")

        await self._write_auth(b"\x01\x00" + app_nonce)
        data = await self._wait(self._auth_queue, _HANDSHAKE_TIMEOUT)
        if data != b"\x00\x00\x01\x00":
            raise RuntimeError(f"miot_ble: expected RCV_OK (nonce), got {data.hex()}")

        data = await self._wait(self._auth_queue, _HANDSHAKE_TIMEOUT)
        if not data.startswith(b"\x00\x00\x02\x0d"):
            raise RuntimeError(f"miot_ble: expected dev_nonce, got {data.hex()}")
        dev_nonce = data[4:]
        await self._write_auth(b"\x00\x00\x03\x00")

        data = await self._wait(self._auth_queue, _HANDSHAKE_TIMEOUT)
        if not data.startswith(b"\x00\x00\x02\x0c"):
            raise RuntimeError(f"miot_ble: expected dev_proof, got {data.hex()}")
        dev_proof = data[4:]
        await self._write_auth(b"\x00\x00\x03\x00")

        rx_key, tx_key, rx_pfx, tx_pfx = _derive_session_keys(
            self._token, app_nonce, dev_nonce
        )
        _verify_dev_proof(rx_key, dev_nonce, app_nonce, dev_proof)
        app_proof = _compute_app_proof(tx_key, app_nonce, dev_nonce)

        self._rx_key, self._tx_key       = rx_key, tx_key
        self._rx_nonce_pfx, self._tx_nonce_pfx = rx_pfx, tx_pfx
        self._tx_seq = self._tx_ovf = self._rx_seq = self._rx_ovf = 0

        await self._write_auth(b"\x00\x00\x00\x0a\x01\x00")
        data = await self._wait(self._auth_queue, _HANDSHAKE_TIMEOUT)
        if data != b"\x00\x00\x01\x01":
            raise RuntimeError(f"miot_ble: expected RCV_RDY (proof), got {data.hex()}")

        await self._write_auth(b"\x01\x00" + app_proof)
        data = await self._wait(self._auth_queue, _HANDSHAKE_TIMEOUT)
        if data != b"\x00\x00\x01\x00":
            raise RuntimeError(f"miot_ble: expected RCV_OK (proof), got {data.hex()}")

        login_ok = await self._wait(self._cmd_queue, _HANDSHAKE_TIMEOUT)
        if login_ok != b"\x21\x00\x00\x00":
            self.log.warning(
                "miot_ble: unexpected CMD after proof: %s", login_ok.hex()
            )
        self.log.debug("miot_ble: session auth complete for %s", self._mac)

    # ── Notification callbacks ────────────────────────────────────────────────

    def _on_cmd(self, _handle: int, data: bytearray) -> None:
        self._cmd_queue.put_nowait(bytes(data))

    def _on_auth(self, _handle: int, data: bytearray) -> None:
        self._auth_queue.put_nowait(bytes(data))

    def _on_info(self, _handle: int, data: bytearray) -> None:
        self._info_queue.put_nowait(bytes(data))

    def _on_disconnect(self, _client) -> None:
        """Called by Bleak when the connection drops unexpectedly."""
        if self._session_ready:
            self.log.warning("miot_ble: %s disconnected unexpectedly", self._mac)
        self._session_ready = False

    def _on_rx(self, _handle: int, data: bytearray) -> None:
        """Decrypt a frame from 0x001b and dispatch decoded properties."""
        raw = bytes(data)
        # The device expects an ACK on every RX frame as a keepalive.
        asyncio.ensure_future(self._write(_CHAR_RX, b"\x00\x00\x03\x00"))

        if self._rx_key is None or len(raw) < 10:
            return

        # Frame layout: [00 00 02 00][seq:2 LE][CCM ciphertext + 4-byte tag]
        seq = int.from_bytes(raw[4:6], "little")
        ct  = raw[6:]

        old_hi = self._rx_seq & 0x8000
        self._rx_seq = seq
        if (self._rx_seq & 0x8000) != old_hi:
            self._rx_ovf = (self._rx_ovf + 1) & 0xFFFF

        nonce = _build_ccm_nonce(self._rx_nonce_pfx, self._rx_seq, self._rx_ovf)
        try:
            plaintext = _ccm_decrypt(self._rx_key, nonce, ct)
        except InvalidTag:
            self.log.warning("miot_ble: CCM tag invalid (seq=%d)", seq)
            return

        self.log.debug(
            "miot_ble: RX seq=%d plain=%s", seq, plaintext.hex()
        )

        opcode = plaintext[4] if len(plaintext) >= 5 else 0xFF
        if opcode in (0x03, 0x04):
            results = _parse_rsp(plaintext, self.spec)
            if results:
                self._rx_queue.put_nowait(results)
                if self.on_properties is not None:
                    # Don't let ~1 Hz push reports revert optimistic writes.
                    # Filter out any property that was written within the
                    # suppression window; expire stale entries while we're here.
                    now = time.monotonic()
                    self._pending_writes = {
                        k: v for k, v in self._pending_writes.items() if v > now
                    }
                    push = [
                        r for r in results
                        if (r["siid"], r["piid"]) not in self._pending_writes
                    ]
                    if push:
                        self.on_properties(push)
        elif opcode == 0x01:
            self._log_set_rsp(plaintext)

    def _log_set_rsp(self, data: bytes) -> None:
        """Log per-property status codes from a set_properties_rsp (opcode 0x01)."""
        if len(data) < 6:
            return
        count  = data[5]
        offset = 6
        for _ in range(count):
            if offset + 5 > len(data):
                break
            siid   = data[offset]
            piid   = struct.unpack_from("<H", data, offset + 1)[0]
            status = struct.unpack_from("<H", data, offset + 3)[0]
            if status == 0:
                self.log.debug(
                    "miot_ble: SET rsp siid=%d piid=0x%04x OK", siid, piid
                )
            else:
                self.log.warning(
                    "miot_ble: SET rsp siid=%d piid=0x%04x ERROR 0x%04x",
                    siid, piid, status,
                )
            offset += 5

    # ── Encrypted TX channel ──────────────────────────────────────────────────

    async def _send_encrypted(self, plaintext: bytes) -> None:
        if self._tx_key is None:
            raise RuntimeError("miot_ble: session not established — call connect() first")

        nonce = _build_ccm_nonce(self._tx_nonce_pfx, self._tx_seq, self._tx_ovf)
        ct    = _ccm_encrypt(self._tx_key, nonce, plaintext)
        frame = b"\x01\x00" + struct.pack("<H", self._tx_seq) + ct

        old_hi      = self._tx_seq & 0x8000
        self._tx_seq = (self._tx_seq + 1) & 0xFFFF
        if (self._tx_seq & 0x8000) != old_hi:
            self._tx_ovf = (self._tx_ovf + 1) & 0xFFFF

        self._fc = (self._fc + 1) & 0xFFFF

        await self._write(_CHAR_TX, frame)

    # ── Low-level helpers ─────────────────────────────────────────────────────

    async def _write(self, uuid: str, data: bytes) -> None:
        await self._client.write_gatt_char(uuid, data, response=False)

    async def _write_auth(self, data: bytes) -> None:
        await self._write(_CHAR_AUTH, data)

    @staticmethod
    async def _wait(queue: asyncio.Queue[bytes], timeout: float) -> bytes:
        try:
            return await asyncio.wait_for(queue.get(), timeout=timeout)
        except asyncio.TimeoutError as exc:
            raise TimeoutError(
                f"Timeout ({timeout:.1f}s) waiting for device response"
            ) from exc

    async def _wait_auth_or_cmd_err(self, timeout: float) -> bytes:
        """Wait for the AUTH queue but fail fast on CMD login errors (e0/e1/e2)."""
        _ERR = {
            b"\xe0\x00\x00\x00",
            b"\xe1\x00\x00\x00",
            b"\xe2\x00\x00\x00",
        }
        auth_t = asyncio.ensure_future(self._auth_queue.get())
        cmd_t  = asyncio.ensure_future(self._cmd_queue.get())
        try:
            done, pending = await asyncio.wait(
                (auth_t, cmd_t),
                timeout=timeout,
                return_when=asyncio.FIRST_COMPLETED,
            )
            for t in pending:
                t.cancel()
            if not done:
                raise TimeoutError(
                    f"Timeout ({timeout:.1f}s) waiting for device response"
                )
            if cmd_t in done:
                val = cmd_t.result()
                if val in _ERR:
                    raise RuntimeError(
                        f"miot_ble: device rejected login: {val.hex()} "
                        "(previous session still active — wait a moment and retry)"
                    )
                self.log.warning(
                    "miot_ble: unexpected CMD during auth: %s", val.hex()
                )
                self._cmd_queue.put_nowait(val)
                if auth_t.done():
                    return auth_t.result()
                return await self._wait(self._auth_queue, timeout)
            if cmd_t.done():
                self._cmd_queue.put_nowait(cmd_t.result())
            return auth_t.result()
        except BaseException:
            auth_t.cancel()
            cmd_t.cancel()
            raise

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _get_prop_format(self, siid: int, piid: int) -> str | None:
        """Look up the MIoT format string for a property from the loaded spec."""
        if self.spec is None:
            return None
        from .miot_spec import MiotSpec as _MS, MiotProperty
        mi = _MS.unique_prop(siid, piid=piid)
        prop = self.spec.specs.get(mi)
        if isinstance(prop, MiotProperty):
            return prop.format
        return None
