#!/usr/bin/env python3
"""Waybar car-ETA module for MG iSMART India.

Modes:
  show   Read cache only (NEVER networks, safe for hover/tooltip).
         If the cache is stale per the adaptive interval, spawns a detached
         `poll` in the background and renders cached data with a refresh mark.
  poll   Full network poll: MG status -> GPS -> Mapbox route to home ->
         Nominatim placename -> write cache. Prints waybar JSON.

Adaptive interval: 5 min while the car is moving (GPS shifted >150m between
polls), else 5 hours. Click (on-click=poll) forces an immediate poll.
Home geofence: within GEOFENCE_M (default 500m) of HOME_LAT/HOME_LON = home.

Config via ~/mg-ismart-india/.env: MG_PHONE, MG_PASSWORD, MAPBOX_TOKEN,
HOME_LAT, HOME_LON, GEOFENCE_M (optional).
"""
from __future__ import annotations
import json
import math
import os
import subprocess
import sys
import time
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import mg_ismart_india as mg  # noqa: E402

CACHE = os.path.expanduser("~/.cache/mg-car-waybar.json")
MOVE_THRESHOLD_M = 150
INTERVAL_MOVING_S = 5 * 60
INTERVAL_IDLE_S = 5 * 3600


def haversine_m(lat1, lon1, lat2, lon2) -> float:
    r = 6371000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def out(text, tooltip, cls):
    print(json.dumps({"text": text, "tooltip": tooltip, "class": cls}))


def load_cache() -> dict:
    try:
        with open(CACHE) as f:
            return json.load(f)
    except (FileNotFoundError, ValueError):
        return {}


def save_cache(data: dict) -> None:
    tmp = CACHE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f)
    os.replace(tmp, CACHE)
    os.chmod(CACHE, 0o600)


def http_get_json(url, headers=None, timeout=20) -> dict:
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def placename(lat, lon) -> str:
    try:
        q = urllib.parse.urlencode({"lat": lat, "lon": lon, "format": "jsonv2", "zoom": "14"})
        d = http_get_json(f"https://nominatim.openstreetmap.org/reverse?{q}",
                          {"User-Agent": "mg-car-waybar/1.0"}, timeout=15)
        a = d.get("address", {})
        bits = [a.get("suburb") or a.get("neighbourhood") or a.get("road") or "",
                a.get("city") or a.get("town") or a.get("village") or ""]
        place = ", ".join(b for b in bits if b)
        return place or d.get("display_name", "").split(",")[0]
    except Exception:
        return ""


def mapbox_route(token, car_lon, car_lat, home_lon, home_lat):
    url = (f"https://api.mapbox.com/directions/v5/mapbox/driving-traffic/"
           f"{car_lon},{car_lat};{home_lon},{home_lat}"
           f"?access_token={token}&overview=false")
    d = http_get_json(url, timeout=20)
    r = d["routes"][0]
    return r["distance"], r["duration"]  # metres, seconds


def do_poll(cfg, soft: bool = False) -> dict:
    home_lat = float(cfg["HOME_LAT"])
    home_lon = float(cfg["HOME_LON"])
    fence = float(cfg.get("GEOFENCE_M", "500"))
    token = cfg.get("MAPBOX_TOKEN", "")

    prev = load_cache()
    c = mg.MgIndiaClient(cfg["MG_PHONE"], cfg["MG_PASSWORD"],
                         cfg.get("MG_VIN") or prev.get("vin") or None,
                         cfg.get("MG_PIN") or None)
    # Soft polls never steal the session: reuse our token, and if the phone
    # has taken it, report taken instead of logging the phone out. A soft
    # poll with no cached token at all is still allowed to log in.
    auto = (not soft) or (c.token is None)
    try:
        s = c.status(auto_login=auto)
    except mg.SessionTakenError:
        now = int(time.time())
        data = dict(prev) if prev else {}
        data.update({"session_taken": True, "last_attempt": now})
        if data:
            save_cache(data)
        return data
    basic = s.get("basicVehicleStatus", {})
    gps = s.get("gpsPosition", {})
    wp = gps.get("wayPoint", {})
    pos = wp.get("position", {})

    lat = pos.get("latitude", 0) / 1e6
    lon = pos.get("longitude", 0) / 1e6
    speed_raw = wp.get("speed")
    heading = wp.get("heading")

    moved_m = None
    if prev.get("lat") is not None:
        moved_m = haversine_m(prev["lat"], prev["lon"], lat, lon)
    moving = moved_m is not None and moved_m > MOVE_THRESHOLD_M

    dist_home = haversine_m(lat, lon, home_lat, home_lon)
    at_home = dist_home <= fence

    route_m = route_s = None
    if not at_home and token:
        try:
            route_m, route_s = mapbox_route(token, lon, lat, home_lon, home_lat)
        except Exception:
            pass

    place = placename(lat, lon) if (moved_m is None or moved_m > 500) else prev.get("place", "")
    if not place:
        place = prev.get("place", "")

    now = int(time.time())
    data = {
        "lat": lat, "lon": lon, "speed_raw": speed_raw, "heading": heading,
        "gps_status": gps.get("gpsStatus"),
        "charge_pct": basic.get("fuelLevelPrc"),
        "range_km": (basic.get("fuelRange") / 10) if basic.get("fuelRange") is not None else None,
        "odometer_km": (basic.get("mileage") / 10) if basic.get("mileage") is not None else None,
        "aux_v": (basic.get("batteryVoltage") / 10) if basic.get("batteryVoltage") is not None else None,
        "locked": basic.get("lockStatus"),
        "climate": basic.get("remoteClimateStatus"),
        "engine": basic.get("engineStatus"),
        "interior_c": basic.get("interiorTemperature"),
        "exterior_c": basic.get("exteriorTemperature"),
        "dist_home_m": round(dist_home),
        "at_home": at_home,
        "route_m": route_m, "route_s": route_s,
        "place": place, "moving": moving, "moved_m": round(moved_m) if moved_m is not None else None,
        "last_poll": now, "last_attempt": now, "session_taken": False,
        "vin": c.vin,
    }
    save_cache(data)
    return data


def fmt_eta(seconds) -> str:
    m = math.ceil(seconds / 60)
    clock = time.strftime("%I:%M %p", time.localtime(time.time() + seconds))
    return m, clock


def render(data: dict, stale: bool):
    mark = " ⟳" if stale else ""
    if not data:
        out("🚗 …", "No data yet — click to poll", "no-data")
        return
    if data.get("at_home"):
        text, tip, cls = (f"🏠 🚗{mark}",
                          tooltip(data, "Car is HOME (inside geofence)") + mark, "at-home")
    elif data.get("route_s") is not None:
        m, clock = fmt_eta(data["route_s"])
        km = data["route_m"] / 1000
        cls = "high-traffic" if m > 45 else "medium-traffic" if m > 30 else "low-traffic"
        text = f"🚗 {km:.1f} km · {m}m{mark}"
        tip = tooltip(data, f"{km:.1f} km by road · {m} min · ETA {clock}")
    else:
        km = (data.get("dist_home_m") or 0) / 1000  # straight-line fallback
        text, cls = f"🚗 ≈{km:.1f} km{mark}", "no-route"
        tip = tooltip(data, f"≈{km:.1f} km straight-line (road ETA unavailable)")
    if data.get("session_taken"):
        text += " 📱"
        tip = "📱 Phone app holds the session — right-click to take it back\n" + tip
        cls = "session-taken"
    out(text, tip, cls)


def tooltip(data: dict, route_line: str) -> str:
    la, lo = data.get("lat"), data.get("lon")
    lines = [
        route_line,
        f"📍 {data.get('place') or 'unknown area'} (~{la:.2f}, {lo:.2f})" if la is not None else "📍 no fix",
        f"🧭 {data.get('heading')}° · speed raw {data.get('speed_raw')}",
        f"🔋 charge {data.get('charge_pct')}% · range {data.get('range_km')} km · aux {data.get('aux_v')} V",
        f"🌡 in {data.get('interior_c')}°C / out {data.get('exterior_c')}°C · odo {data.get('odometer_km')} km",
        f"🔒 {'locked' if data.get('locked') else 'unlocked'} · updated {time.strftime('%I:%M %p', time.localtime(data.get('last_poll', 0)))}",
    ]
    return "\n".join(lines)


def cmd_show():
    data = load_cache()
    now = time.time()
    interval = INTERVAL_MOVING_S if data.get("moving") else INTERVAL_IDLE_S
    due = not data or (now - data.get("last_attempt", 0) > interval)
    stale = not data or (now - data.get("last_poll", 0) > interval)
    if due:
        try:  # soft refresh in background; never steals the phone session.
            subprocess.Popen([sys.executable, os.path.abspath(__file__), "poll", "--soft"],
                             start_new_session=True,
                             stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
    render(data, stale=bool(stale and data))


def cmd_poll():
    soft = "--soft" in sys.argv
    cfg = mg._load_env_config(None)
    for k in ("MG_PHONE", "MG_PASSWORD", "HOME_LAT", "HOME_LON"):
        if not cfg.get(k):
            out("🚗 ⚠", f"Missing {k} in ~/mg-ismart-india/.env", "error")
            return
    try:
        render(do_poll(cfg, soft=soft), stale=False)
    except Exception as e:
        data = load_cache()
        if data:  # bound retries to the adaptive interval even during outages
            data["last_attempt"] = int(time.time())
            save_cache(data)
        err = f"{type(e).__name__}: {e}"[:160]
        if data:
            data["tooltip_err"] = err
            out_tip = tooltip(data, "Poll failed — showing cached data") + f"\n⚠ {err}"
            cls = "error-stale"
            text = "🚗 ⚠"
            out(text, out_tip, cls)
        else:
            out("🚗 ⚠", f"Poll failed: {err}", "error")


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "show"
    (cmd_poll if mode == "poll" else cmd_show)()
