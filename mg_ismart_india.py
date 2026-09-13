#!/usr/bin/env python3
"""Lightweight MG iSMART India client (sync, stdlib+3 deps).

Protocol: MG India TAP (ASN.1 UPER over HTTPS) + encrypted JSON gateway.
Based on the reverse-engineering in john-lazarus/mg-ismart-india-ha (MIT)
which this file ports to a dependency-light sync client.

Endpoints (all HTTPS, verified live 2026-09-13, Azure Central India):
  TAP login+PIN : POST https://iov-tap.mgindia.co.in/TAP.Web/ota.mp
  TAP status/ctl: POST https://iov-tap.mgindia.co.in/TAP.Web/ota.mpv21
  Gateway base  : https://iov-gateway.mgindia.co.in/api.app/v1
    GET /vehicle/userVinList
    GET /vehicle/feature/list?vin=...
    GET /vehicle/service/subscription?vin=...
    GET /navi/vehicle/co2info?vin=...
    GET /navi/vehicle/co2info/supplementInfo?vin=...

Install: pip install requests asn1tools pycryptodome
Usage:
  python mg_ismart_india.py --phone 9876543210 --password 'xxx' vehicles
  python mg_ismart_india.py --phone ... --password 'xxx' --vin <VIN> status
  python mg_ismart_india.py --phone ... --password 'xxx' --vin <VIN> --pin 123456 lock
"""
from __future__ import annotations
import argparse
import getpass
import hashlib
import hmac
import json
import math
import os
import re
import time
from binascii import unhexlify
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any
from urllib.parse import urlencode

import asn1tools
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# ---------------------------------------------------------------- endpoints
TAP_LOGIN_URL = "https://iov-tap.mgindia.co.in/TAP.Web/ota.mp"
TAP_STATUS_URL = "https://iov-tap.mgindia.co.in/TAP.Web/ota.mpv21"
GATEWAY_BASE = "https://iov-gateway.mgindia.co.in/api.app/v1"
USER_AGENT = "CER_IKE_01/2.3.0 (iPad; iOS 26.3; Scale/2.00)"

LOGIN_DISPATCHER_TEMPLATE_HEX = (
    "11005600882c60c183060c183060c183060c183060c183060c183060c183060c183060c183"
    "060c183060c183060c183060c1ab06200000000020200468acf134468acf1342468acf134"
    "2468acf1342000000000100a0"
)

TOKEN_CACHE = os.path.expanduser("~/.cache/mg-india-auth.json")


def _load_cached_auth(phone: str) -> tuple[str | None, str | None]:
    """Reuse the last token so routine polls don't log in (and kick the phone)."""
    try:
        with open(TOKEN_CACHE) as f:
            entry = json.load(f).get(phone, {})
        uid, token = entry.get("uid"), entry.get("token")
        if isinstance(uid, str) and isinstance(token, str) and len(uid) == 50 and len(token) == 40:
            return uid, token
    except (FileNotFoundError, ValueError, AttributeError):
        pass
    return None, None


def _save_cached_auth(phone: str, uid: str, token: str) -> None:
    try:
        os.makedirs(os.path.dirname(TOKEN_CACHE), exist_ok=True)
        try:
            with open(TOKEN_CACHE) as f:
                all_data = json.load(f)
        except (FileNotFoundError, ValueError):
            all_data = {}
        all_data[phone] = {"uid": uid, "token": token, "ts": int(time.time())}
        tmp = TOKEN_CACHE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(all_data, f)
        os.replace(tmp, TOKEN_CACHE)
        os.chmod(TOKEN_CACHE, 0o600)
    except OSError:
        pass


# ---------------------------------------------------------------- errors
class MgIndiaApiError(Exception):
    pass


class SessionTakenError(MgIndiaApiError):
    """Our cached token was rejected — another client (e.g. the phone app)
    holds the single MG session. Raise instead of logging in when the
    caller passes auto_login=False, so we don't kick the other side."""

# ---------------------------------------------------------------- bitcodec
class PackedBitReader:
    def __init__(self, data: bytes | bytearray) -> None:
        self.data = data
        self.offset = 0
    def read(self, count: int) -> int:
        value = 0
        for _ in range(count):
            absolute = self.offset
            self.offset += 1
            value = (value << 1) | ((self.data[absolute // 8] >> (7 - absolute % 8)) & 1)
        return value
    def read_string(self, minimum: int, maximum: int) -> str:
        span = maximum - minimum
        length = minimum + (self.read(math.ceil(math.log2(span + 1))) if span else 0)
        return "".join(chr(self.read(7)) for _ in range(length))

class PackedBitWriter:
    def __init__(self) -> None:
        self.bits: list[int] = []
    def write(self, value: int, count: int) -> None:
        if value < 0 or value >= (1 << count):
            raise ValueError("bit value out of range")
        self.bits.extend((value >> shift) & 1 for shift in range(count - 1, -1, -1))
    def write_string(self, value: str, minimum: int, maximum: int) -> None:
        span = maximum - minimum
        if not minimum <= len(value) <= maximum:
            raise ValueError("string length out of range")
        if span:
            self.write(len(value) - minimum, math.ceil(math.log2(span + 1)))
        for char in value:
            self.write(ord(char), 7)
    def bytes(self) -> bytes:
        out = bytearray()
        for start in range(0, len(self.bits), 8):
            val = 0
            chunk = self.bits[start:start + 8]
            for bit in chunk:
                val = (val << 1) | bit
            out.append(val << (8 - len(chunk)))
        return bytes(out)

def set_msb_bits(buf: bytearray, offset: int, count: int, value: int) -> None:
    for idx in range(count):
        absolute = offset + idx
        mask = 1 << (7 - absolute % 8)
        if (value >> (count - 1 - idx)) & 1:
            buf[absolute // 8] |= mask
        else:
            buf[absolute // 8] &= ~mask

def set_fixed_7bit(buf: bytearray, offset: int, value: str) -> None:
    for idx, char in enumerate(value):
        set_msb_bits(buf, offset + idx * 7, 7, ord(char))

def read_fixed_7bit(buf: bytes | bytearray, offset: int, count: int) -> str:
    out = []
    for idx in range(count):
        v = 0
        for j in range(7):
            absolute = offset + idx * 7 + j
            v = (v << 1) | ((buf[absolute // 8] >> (7 - absolute % 8)) & 1)
        out.append(chr(v))
    return "".join(out)

# ---------------------------------------------------------------- crypto
def normalize_phone(phone: str) -> str:
    digits = re.sub(r"\D", "", phone or "")
    if len(digits) >= 10:
        digits = digits[-10:]
    if len(digits) != 10:
        raise MgIndiaApiError("Use the 10 digit India mobile number (no +91)")
    return digits

def make_device_id(phone: str) -> str:
    seed = hashlib.sha256(f"mg-ismart-india:{normalize_phone(phone)}".encode()).hexdigest()
    return (f"haos-mg-ismart-india-{seed}" + "0" * 120)[:103]

def md5_hex(value: str) -> str:
    return hashlib.md5(value.encode()).hexdigest()

def tap_signature(body: str) -> str:
    key = md5_hex(body[1:len(body) // 2])
    return hmac.new(key.encode(), body.encode(), hashlib.sha256).hexdigest()

def gateway_signature(path: str, timestamp: str, content_type: str = "application/json") -> str:
    part1 = md5_hex(path)
    part2 = md5_hex(part1 + timestamp + "1" + content_type)
    key = md5_hex(part2 + timestamp)
    return hmac.new(key.encode(), (path + timestamp + "1" + content_type).encode(), hashlib.sha256).hexdigest()

def hash_control_pin(pin: str) -> str:
    if not re.fullmatch(r"\d{4,8}", pin or ""):
        raise MgIndiaApiError("Control PIN must be 4 to 8 digits")
    normalized = pin if len(pin) == 6 else f"{pin}00"
    return md5_hex(normalized).upper()

def decrypt_gateway_body(encrypted: str, headers: Any) -> str:
    get = headers.get if hasattr(headers, "get") else lambda k, d="": headers.get(k, d)
    timestamp = get("APP-SEND-DATE") or get("app-send-date") or ""
    content_type = get("ORIGINAL-CONTENT-TYPE") or get("original-content-type") or "application/json"
    key = md5_hex(timestamp + "1" + content_type)
    iv = md5_hex(timestamp)
    return unpad(AES.new(unhexlify(key), AES.MODE_CBC, unhexlify(iv)).decrypt(unhexlify(encrypted)), AES.block_size).decode()

# ---------------------------------------------------------------- TAP ASN.1
TAP_RESERVED_SIZE = 16
TAP_PROTOCOL_VERSION = 33
V11_PROTOCOL_VERSION = 17
PROTOCOL = 513
STATUS_APP_ID = "511"
CONTROL_APP_ID = "510"
PIN_APP_ID = "313"

ASN_V21 = """MGIndiaTapModule
DEFINITIONS AUTOMATIC TAGS ::= BEGIN
MPDispatcherBody ::= SEQUENCE { uid IA5String(SIZE(50)) OPTIONAL, token IA5String(SIZE(40)) OPTIONAL, applicationID IA5String(SIZE(3)), vin IA5String(SIZE(17)) OPTIONAL, messageID INTEGER(0..255), eventCreationTime INTEGER(0..2147483647), eventID INTEGER(0..2147483647) OPTIONAL, ulMessageCounter INTEGER(0..65535) OPTIONAL, dlMessageCounter INTEGER(0..65535) OPTIONAL, ackMessageCounter INTEGER(0..65535) OPTIONAL, ackRequired BOOLEAN OPTIONAL, applicationDataLength INTEGER(0..65535) OPTIONAL, applicationDataEncoding DataEncodingType OPTIONAL, applicationDataProtocolVersion INTEGER(0..65535) OPTIONAL, testFlag INTEGER(1..3) OPTIONAL, result INTEGER(0..65535) OPTIONAL, errorMessage OCTET STRING(SIZE(1..1024)) OPTIONAL }
DataEncodingType ::= ENUMERATED { perUnaligned(0), der(1), ber(2) }
OTARVMVehicleStatusReq ::= SEQUENCE { vehStatusReqType INTEGER(0..255) }
OTARVCReq ::= SEQUENCE { rvcReqType OCTET STRING(SIZE(1)), rvcParams SEQUENCE SIZE(1..10) OF RvcReqParam OPTIONAL }
RvcReqParam ::= SEQUENCE { paramId INTEGER(0..65535), paramValue OCTET STRING(SIZE(1..255)) }
OTARVMVehicleStatusResp513 ::= SEQUENCE { statusTime INTEGER(0..2147483647), gpsPosition RvsPosition, basicVehicleStatus RvsBasicStatus513, extendedVehicleStatus RvsExtStatus OPTIONAL }
OTARVCStatus513 ::= SEQUENCE { rvcReqType OCTET STRING(SIZE(1)), rvcReqSts OCTET STRING(SIZE(1)), failureType INTEGER(0..255) OPTIONAL, gpsPosition RvsPosition, basicVehicleStatus RvsBasicStatus513 }
RvsPosition ::= SEQUENCE { wayPoint RvsWayPoint, timestamp4Short Timestamp4Short, gpsStatus GPSStatus }
RvsWayPoint ::= SEQUENCE { position RvsWGS84Point, heading INTEGER(0..359), speed INTEGER(-1000..4500), hdop INTEGER(0..1000), satellites INTEGER(0..16) }
RvsWGS84Point ::= SEQUENCE { latitude INTEGER(-90000000..90000000), longitude INTEGER(-180000000..180000000), altitude INTEGER(-100..8900) }
Timestamp4Short ::= SEQUENCE { seconds INTEGER(0..2147483647) }
GPSStatus ::= ENUMERATED { noGpsSignal(0), timeFix(1), fix2D(2), fix3D(3) }
RvsBasicStatus513 ::= SEQUENCE { driverDoor BOOLEAN, passengerDoor BOOLEAN, rearLeftDoor BOOLEAN, rearRightDoor BOOLEAN, bootStatus BOOLEAN, bonnetStatus BOOLEAN, lockStatus BOOLEAN, driverWindow BOOLEAN OPTIONAL, passengerWindow BOOLEAN OPTIONAL, rearLeftWindow BOOLEAN OPTIONAL, rearRightWindow BOOLEAN OPTIONAL, sunroofStatus BOOLEAN OPTIONAL, frontRrightTyrePressure INTEGER(0..255) OPTIONAL, frontLeftTyrePressure INTEGER(0..255) OPTIONAL, rearRightTyrePressure INTEGER(0..255) OPTIONAL, rearLeftTyrePressure INTEGER(0..255) OPTIONAL, wheelTyreMonitorStatus INTEGER(0..255) OPTIONAL, sideLightStatus BOOLEAN, dippedBeamStatus BOOLEAN, mainBeamStatus BOOLEAN, vehicleAlarmStatus INTEGER(0..255) OPTIONAL, engineStatus INTEGER(0..255), powerMode INTEGER(0..255), lastKeySeen INTEGER(0..65535), currentJourneyDistance INTEGER(0..65535), currentJourneyID INTEGER(0..2147483647), interiorTemperature INTEGER(-128..127), exteriorTemperature INTEGER(-128..127), fuelLevelPrc INTEGER(0..255), fuelRange INTEGER(0..65535), remoteClimateStatus INTEGER(0..255), frontLeftSeatHeatLevel INTEGER(0..255) OPTIONAL, frontRightSeatHeatLevel INTEGER(0..255) OPTIONAL, canBusActive BOOLEAN, timeOfLastCANBUSActivity INTEGER(0..2147483647), clstrDspdFuelLvlSgmt INTEGER(0..255), mileage INTEGER(0..2147483647), batteryVoltage INTEGER(0..65535), extendedData1 INTEGER(0..2147483647) OPTIONAL, extendedData2 INTEGER(0..2147483647) OPTIONAL, handBrake BOOLEAN }
RvsExtStatus ::= SEQUENCE { vehicleAlerts SEQUENCE SIZE(0..64) OF VehicleAlertInfo }
VehicleAlertInfo ::= SEQUENCE { id INTEGER(0..255), value INTEGER(0..255) }
END
"""
ASN_V11 = """MGIndiaTapV11Module
DEFINITIONS AUTOMATIC TAGS ::= BEGIN
MPDispatcherBodyV11 ::= SEQUENCE { uid IA5String(SIZE(50)) OPTIONAL, token IA5String(SIZE(40)) OPTIONAL, applicationID IA5String(SIZE(3)), vin IA5String(SIZE(17)) OPTIONAL, eventCreationTime INTEGER(0..4294967295), eventID INTEGER(0..281474976710655) OPTIONAL, messageID INTEGER(0..255), messageCounter MessageCounter OPTIONAL, ackRequired BOOLEAN OPTIONAL, statelessDispatcherMessage BOOLEAN OPTIONAL, crqmRequest BOOLEAN OPTIONAL, basicPosition BasicPosition OPTIONAL, networkInfo NetworkInfo OPTIONAL, simInfo NumericString(SIZE(19)) OPTIONAL, hmiLanguage LanguageType OPTIONAL, iccID NumericString(SIZE(20)), applicationDataLength INTEGER(0..4294967295), applicationDataEncoding DataEncodingType OPTIONAL, applicationDataProtocolVersion INTEGER(0..65535), testFlag INTEGER(1..3) OPTIONAL, result INTEGER(0..65535) OPTIONAL, errorMessage OCTET STRING(SIZE(1..1024)) OPTIONAL }
MessageCounter ::= SEQUENCE { uplinkCounter INTEGER(0..255), downlinkCounter INTEGER(0..255) }
BasicPosition ::= SEQUENCE { latitude INTEGER(-90000000..90000000), longitude INTEGER(-180000000..180000000) }
NetworkInfo ::= SEQUENCE { mccNetwork NumericString(SIZE(3)), mncNetwork NumericString(SIZE(3)), mccSim NumericString(SIZE(3)), mncSim NumericString(SIZE(3)), signalStrength INTEGER(0..99) }
LanguageType ::= ENUMERATED { simplifiedChinese(0), english(1), spanish(2), arabic(3), hindi(4) }
DataEncodingType ::= ENUMERATED { perUnaligned(0), der(1), ber(2) }
PINVerificationReq ::= SEQUENCE { pin IA5String(SIZE(32)) }
END
"""

@lru_cache(maxsize=1)
def codec21():
    return asn1tools.compile_string(ASN_V21, "uper")

@lru_cache(maxsize=1)
def codec11():
    return asn1tools.compile_string(ASN_V11, "uper")

def _frame_v21(dispatcher: bytes, app: bytes) -> str:
    dispatcher_length = len(dispatcher) + 3
    if dispatcher_length > 255:
        raise ValueError("TAP dispatcher too large")
    payload = bytes((TAP_PROTOCOL_VERSION, dispatcher_length, 0)) + bytes(TAP_RESERVED_SIZE) + dispatcher + app
    return "1" + f"{len(payload) + 3:04X}" + payload.hex().upper()

def _dispatcher(uid: str, token: str, vin: str, app_id: str, app: bytes, event_id: int, msg_id: int = 1) -> bytes:
    return codec21().encode("MPDispatcherBody", {
        "uid": uid, "token": token, "applicationID": app_id, "vin": vin,
        "messageID": msg_id, "eventCreationTime": int(time.time()), "eventID": event_id,
        "ulMessageCounter": 0, "dlMessageCounter": 0, "ackMessageCounter": 0,
        "ackRequired": False, "applicationDataLength": len(app),
        "applicationDataEncoding": "perUnaligned", "applicationDataProtocolVersion": PROTOCOL,
        "testFlag": 2, "result": 0,
    })

def encode_status_request(uid: str, token: str, vin: str, event_id: int) -> str:
    app = codec21().encode("OTARVMVehicleStatusReq", {"vehStatusReqType": 2})
    return _frame_v21(_dispatcher(uid, token, vin, STATUS_APP_ID, app, event_id), app)

def encode_control_request(uid: str, token: str, vin: str, event_id: int, typ: int, params: list[tuple[int, bytes]]) -> str:
    app = codec21().encode("OTARVCReq", {
        "rvcReqType": bytes([typ]),
        "rvcParams": [{"paramId": i, "paramValue": v} for i, v in params],
    })
    return _frame_v21(_dispatcher(uid, token, vin, CONTROL_APP_ID, app, event_id), app)

def encode_pin_request(uid: str, token: str, vin: str, event_id: int, pin_hash: str) -> str:
    app = codec11().encode("PINVerificationReq", {"pin": pin_hash})
    body = codec11().encode("MPDispatcherBodyV11", {
        "uid": uid, "token": token, "applicationID": PIN_APP_ID, "vin": vin,
        "eventCreationTime": int(time.time()), "messageID": 1,
        "messageCounter": {"uplinkCounter": 1, "downlinkCounter": 0},
        "simInfo": "1234567890987654321", "iccID": "12345678901234567890",
        "applicationDataLength": len(app), "applicationDataEncoding": "perUnaligned",
        "applicationDataProtocolVersion": PROTOCOL, "testFlag": 2,
    })
    dispatcher_length = len(body) + 4
    payload = bytes((V11_PROTOCOL_VERSION, 0, dispatcher_length, 0)) + body + app
    return f"{len(payload) * 2 + 5:04X}1" + payload.hex().upper()

def _decode_v21(raw: str) -> tuple[dict, bytes | None]:
    if len(raw) < 5 or raw[0] != "1":
        raise ValueError("unexpected TAP v2.1 framing")
    data = bytes.fromhex(raw[5:])
    dispatcher_length = data[1]
    dispatcher_end = TAP_RESERVED_SIZE + dispatcher_length
    dispatcher = codec21().decode("MPDispatcherBody", data[19:dispatcher_end])
    app_length = dispatcher.get("applicationDataLength", 0) or 0
    if not app_length:
        return dispatcher, None
    app = data[dispatcher_end:dispatcher_end + app_length]
    return dispatcher, app

def decode_status_response(raw: str):
    disp, app = _decode_v21(raw)
    return disp, codec21().decode("OTARVMVehicleStatusResp513", app) if app else None

def decode_control_response(raw: str):
    disp, app = _decode_v21(raw)
    return disp, codec21().decode("OTARVCStatus513", app) if app else None

def decode_pin_response(raw: str) -> dict:
    payload = bytes.fromhex(raw[5:] if len(raw) >= 5 and raw[4] == "1" else raw)
    dispatcher_length = payload[2]
    return codec11().decode("MPDispatcherBodyV11", payload[4:dispatcher_length])

def encode_login_app(password: str, device_id: str) -> bytes:
    w = PackedBitWriter()
    w.write(1, 1)
    w.write_string(password, 6, 30)
    w.write_string(device_id, 1, 200)
    return w.bytes()

def decode_login_response(raw: str) -> tuple[str, str]:
    if len(raw) < 5 or raw[4] != "1":
        raise MgIndiaApiError("Unexpected TAP login response framing")
    payload = bytes.fromhex(raw[5:])
    dispatcher_len = payload[2] + (payload[3] << 8)
    dispatcher, app = payload[:dispatcher_len], payload[dispatcher_len:]
    uid = read_fixed_7bit(dispatcher, 300, 14).rjust(50, "0")
    r = PackedBitReader(app)
    r.read(6)
    token = r.read_string(40, 40)
    refresh = r.read_string(40, 40)
    if token != refresh:
        raise MgIndiaApiError("Login token and refresh token differ")
    return uid, token

# ---------------------------------------------------------------- models
@dataclass(slots=True)
class Vehicle:
    vin: str
    name: str
    brand: str | None = None
    model: str | None = None
    model_year: str | None = None
    raw: dict = field(default_factory=dict)

@dataclass(slots=True)
class Status:
    raw: dict = field(default_factory=dict)

# ---------------------------------------------------------------- client
class MgIndiaClient:
    def __init__(self, phone: str, password: str, vin: str | None = None, pin: str | None = None):
        self.phone = normalize_phone(phone)
        self.password = password
        self.vin = vin
        self.pin_hash = hash_control_pin(pin) if pin else None
        self.device_id = make_device_id(self.phone)
        self.uid, self.token = _load_cached_auth(self.phone)
        self._event = 1
        self.s = requests.Session()
        self.s.headers.update({"User-Agent": USER_AGENT})

    def _next_event(self) -> int:
        self._event = (self._event + 1) & 0x7FFFFFFF
        return self._event

    def _build_login_body(self) -> str:
        dispatcher = bytearray.fromhex(LOGIN_DISPATCHER_TEMPLATE_HEX)
        app = encode_login_app(self.password, self.device_id)
        set_fixed_7bit(dispatcher, 48, self.phone.rjust(50, "0"))
        set_msb_bits(dispatcher, 419, 32, int(time.time()))
        dispatcher[-7:-3] = (len(app) * 2).to_bytes(4, "big")
        dispatcher[-3] = 1
        dispatcher[-2:] = (160).to_bytes(2, "big")
        payload = bytes(dispatcher) + app
        raw_without_length = "1" + payload.hex().upper()
        return f"{len(raw_without_length) + 4:04X}{raw_without_length}"

    def login(self) -> None:
        body = self._build_login_body()
        r = self.s.post(TAP_LOGIN_URL, data=body, headers={
            "Content-Type": "text/plain", "Accept": "*/*",
            "APP-SIGNATURE": tap_signature(body), "SIGNATURE": "1"}, timeout=30)
        if r.status_code >= 400:
            raise MgIndiaApiError(f"Login failed: HTTP {r.status_code} {r.text[:200]}")
        self.uid, self.token = decode_login_response(r.text)
        _save_cached_auth(self.phone, self.uid, self.token)

    def gateway_get(self, path: str, params: dict | None = None, auto_login: bool = True) -> dict:
        if not self.token or not self.uid:
            if not auto_login:
                raise SessionTakenError("No cached session and auto-login is off")
            self.login()
        clean_path = "/" + path.lstrip("/")
        query = urlencode(params or {})
        signing_path = clean_path + (f"?{query}" if query else "")
        ts = str(int(time.time() * 1000))
        ct = "application/json"
        h = {"Content-Type": ct, "APP-CONTENT-ENCRYPTED": "1", "APP-LANGUAGE-TYPE": "en-us",
             "APP-LOGIN-TOKEN": self.token or "", "APP-USER-ID": self.uid or "",
             "APP-SEND-DATE": ts,
             "APP-VERIFICATION-STRING": gateway_signature(signing_path, ts, ct),
             "ORIGINAL-CONTENT-TYPE": ct}
        r = self.s.get(GATEWAY_BASE + clean_path, params=params, headers=h, timeout=30)
        if r.status_code >= 400:
            raise MgIndiaApiError(f"Gateway {clean_path} failed: HTTP {r.status_code}")
        parsed = json.loads(decrypt_gateway_body(r.text, r.headers))
        if parsed.get("code") == 7:  # token expired / session taken
            if not auto_login:
                raise SessionTakenError("Session is held by another client")
            self.login()
            return self.gateway_get(path, params, auto_login)
        if parsed.get("code") not in (0, None):
            raise MgIndiaApiError(parsed.get("message") or f"Gateway error {parsed.get('code')}")
        return parsed

    @staticmethod
    def _as_list(data: Any) -> list:
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for key in ("list", "vehicleList", "vehicles", "vinList", "result"):
                if isinstance(data.get(key), list):
                    return data[key]
            nested = data.get("data")
            if isinstance(nested, (dict, list)):
                return MgIndiaClient._as_list(nested)
        return []

    def vehicles(self, auto_login: bool = True) -> list[Vehicle]:
        data = self.gateway_get("/vehicle/userVinList", auto_login=auto_login)
        out = []
        for x in self._as_list(data):
            if not isinstance(x, dict):
                continue
            vin = x.get("vin") or x.get("VIN") or x.get("vinNo") or x.get("vehicleVin")
            if not vin:
                continue
            out.append(Vehicle(str(vin), str(x.get("series") or x.get("modelName") or x.get("brandName") or str(vin)[-6:]),
                               x.get("brandName"), x.get("modelName") or x.get("series"),
                               str(x.get("modelYear") or "") or None, x))
        if self.vin and out:
            if not any(v.vin == self.vin for v in out):
                self.vin = out[0].vin
        elif out and not self.vin:
            self.vin = out[0].vin
        return out

    def status(self, auto_login: bool = True) -> dict:
        if not self.token:
            if not auto_login:
                raise SessionTakenError("No cached session and auto-login is off")
            self.login()
        if not self.vin:
            self.vehicles(auto_login=auto_login)
        base = {"User-Agent": USER_AGENT, "Content-Type": "text/plain", "Accept": "*/*", "SIGNATURE": "1"}
        event_id = 0
        for attempt in range(10):
            body = encode_status_request(self.uid or "0" * 50, self.token or "0" * 40, self.vin or "", event_id)
            h = dict(base); h["APP-SIGNATURE"] = tap_signature(body)
            r = self.s.post(TAP_STATUS_URL, data=body, headers=h, timeout=30)
            if r.status_code >= 400:
                raise MgIndiaApiError(f"Status failed: HTTP {r.status_code}")
            disp, payload = decode_status_response(r.text)
            result = disp.get("result", 0)
            if result == 2:
                if not auto_login:
                    raise SessionTakenError("Session is held by another client")
                self.login()
                event_id = 0
                continue
            if payload:
                # flatten to JSON-serializable dict (bytes -> hex)
                return json.loads(json.dumps(payload, default=lambda o: o.hex() if isinstance(o, (bytes, bytearray)) else str(o)))
            if result not in (0, 4, 6):
                raise MgIndiaApiError(f"Status failed: result {result}")
            event_id = disp.get("eventID", event_id)
            time.sleep(1.5)
        raise MgIndiaApiError("Vehicle status not ready after polling")

    def verify_pin(self) -> None:
        if not self.pin_hash:
            raise MgIndiaApiError("Control PIN not configured (--pin)")
        if not self.token or not self.uid:
            self.login()
        if not self.vin:
            self.vehicles()
        body = encode_pin_request(self.uid or "0" * 50, self.token or "0" * 40, self.vin or "", self._next_event(), self.pin_hash)
        r = self.s.post(TAP_LOGIN_URL, data=body, headers={
            "Content-Type": "text/plain", "Accept": "*/*",
            "APP-SIGNATURE": tap_signature(body), "SIGNATURE": "1"}, timeout=30)
        if r.status_code >= 400:
            raise MgIndiaApiError(f"PIN verify failed: HTTP {r.status_code}")
        if decode_pin_response(r.text).get("result", 0) != 0:
            raise MgIndiaApiError("PIN verification failed (wrong PIN?)")

    def _control(self, name: str, typ: int, params: list[tuple[int, bytes]]) -> None:
        self.verify_pin()
        event_id = 0
        for _ in range(15):
            body = encode_control_request(self.uid or "0" * 50, self.token or "0" * 40, self.vin or "", event_id, typ, params)
            r = self.s.post(TAP_STATUS_URL, data=body, headers={
                "Content-Type": "text/plain", "Accept": "*/*",
                "APP-SIGNATURE": tap_signature(body), "SIGNATURE": "1"}, timeout=30)
            if r.status_code >= 400:
                raise MgIndiaApiError(f"{name} failed: HTTP {r.status_code}")
            disp, ctrl = decode_control_response(r.text)
            result = disp.get("result", 0)
            if ctrl:
                st = ctrl.get("rvcReqSts")
                if st == b"\x02":
                    return
                if st not in (None, b"\x01"):
                    raise MgIndiaApiError(f"{name} failed: status {st!r}")
            if result not in (0, 4, 6):
                raise MgIndiaApiError(f"{name} failed: result {result}")
            event_id = disp.get("eventID", event_id)
            time.sleep(2.0)
        # lock/unlock sometimes applies without terminal status — verify
        if name == "Door lock":
            s = self.status()
            locked = s.get("basicVehicleStatus", s).get("lockStatus")
            if locked is not None:
                return
        raise MgIndiaApiError(f"{name} did not complete")

    # -- commands (param maps from john-lazarus RE) --
    def lock(self): self._control("Door lock", 1, [])
    def unlock(self): self._control("Door lock", 2, [(4, b"\x00"), (5, b"\x00"), (6, b"\x00"), (7, b"\x03"), (255, b"\x00")])
    def climate_on(self): self._control("Climate", 6, [(19, b"\x03"), (20, b"\x03"), (255, b"\x00")])
    def climate_off(self): self._control("Climate", 6, [(19, b"\x00"), (20, b"\x00"), (255, b"\x00")])
    def find_my_car(self): self._control("Find my car", 0, [(1, b"\x01"), (2, b"\x01"), (3, b"\x01"), (255, b"\x00")])
    def tailgate(self): self._control("Tailgate", 2, [(4, b"\x00"), (5, b"\x00"), (6, b"\x00"), (7, b"\x02"), (255, b"\x00")])

# ---------------------------------------------------------------- CLI
def _load_env_file(path: str) -> dict:
    data: dict[str, str] = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip("'").strip('"')
                if k:
                    data[k] = v
    except FileNotFoundError:
        pass
    return data


def _load_env_config(explicit: str | None) -> dict:
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = []
    if explicit:
        candidates.append(explicit)
    candidates.append(os.path.join(os.getcwd(), ".env"))
    candidates.append(os.path.join(here, ".env"))
    merged: dict[str, str] = {}
    for p in candidates:
        merged.update(_load_env_file(p))
    merged.update({k: v for k, v in os.environ.items() if k.startswith("MG_")})
    return merged


def main() -> None:
    ap = argparse.ArgumentParser(description="Lightweight MG iSMART India client (.env supported)")
    ap.add_argument("--phone", help="10-digit India mobile number (or MG_PHONE in .env)")
    ap.add_argument("--password", help="iSMART password (or MG_PASSWORD in .env; prompted if omitted)")
    ap.add_argument("--vin", help="Vehicle VIN (or MG_VIN in .env; auto-selected if omitted)")
    ap.add_argument("--pin", help="Vehicle control PIN, 4-8 digits (or MG_PIN in .env)")
    ap.add_argument("--env", help="Path to .env file (default: ./.env then script dir/.env)")
    ap.add_argument("cmd", choices=["vehicles", "status", "lock", "unlock", "climate-on", "climate-off", "find-car", "tailgate", "endpoints"])
    args = ap.parse_args()
    if args.cmd == "endpoints":
        print(json.dumps({"tap_login": TAP_LOGIN_URL, "tap_status_control": TAP_STATUS_URL,
                          "gateway_base": GATEWAY_BASE,
                          "gateway_paths": ["/vehicle/userVinList", "/vehicle/feature/list",
                                            "/vehicle/service/subscription", "/navi/vehicle/co2info",
                                            "/navi/vehicle/co2info/supplementInfo"]}, indent=2))
        return
    cfg = _load_env_config(args.env)
    phone = args.phone or cfg.get("MG_PHONE")
    password = args.password or cfg.get("MG_PASSWORD")
    vin = args.vin or cfg.get("MG_VIN") or None
    pin = args.pin or cfg.get("MG_PIN") or None
    if not phone:
        ap.error("--phone or MG_PHONE in .env is required")
    if not password:
        password = getpass.getpass("iSMART password: ")
    c = MgIndiaClient(phone, password, vin, pin)
    if args.cmd == "vehicles":
        c.login()
        for v in c.vehicles():
            print(json.dumps({"vin": v.vin, "name": v.name, "brand": v.brand, "model": v.model, "year": v.model_year}))
    elif args.cmd == "status":
        print(json.dumps(c.status(), indent=2))
    else:
        {"lock": c.lock, "unlock": c.unlock, "climate-on": c.climate_on,
         "climate-off": c.climate_off, "find-car": c.find_my_car, "tailgate": c.tailgate}[args.cmd]()
        print("OK")

if __name__ == "__main__":
    main()
