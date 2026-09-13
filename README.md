# mg-ismart-client-waybar

Lightweight MG iSMART India client + Waybar car-ETA module.

## Requirements

- Python 3.10+ (tested on 3.14)
- `pip install -r requirements.txt` → `requests`, `asn1tools`, `pycryptodome`
  (`car_waybar.py` itself is stdlib-only; it imports the client above)
- Waybar (only for the bar module, not the CLI)
- `MAPBOX_TOKEN` (optional; without it you get straight-line distance, no road ETA)

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env  # then fill in values, never commit .env
```

`.env` keys: `MG_PHONE`, `MG_PASSWORD`, `HOME_LAT`, `HOME_LON`,
`MAPBOX_TOKEN` (road ETA), optional `MG_VIN`, `MG_PIN`, `GEOFENCE_M`.
`MG_VIN` is not normally needed: the first vehicle on the account is selected
automatically. Set it only when the account has more than one vehicle.

CLI:

```bash
python mg_ismart_india.py vehicles
python mg_ismart_india.py status
```

Waybar (`~/.config/waybar/config`):

```json
"custom/car": {
  "exec": "/path/to/car_waybar.py show",
  "return-type": "json",
  "interval": 30,
  "on-click": "/path/to/car_waybar.py poll"
}
```

`show` is cache-only (safe to run often). Click forces a fresh `poll`.

## How the Waybar module behaves

- At home (inside `GEOFENCE_M`, default 500m): shows `🏠 🚗`.
- Away: shows road distance + drive minutes, e.g. `🚗 12.3 km · 25m`.
- Hover tooltip: area name, battery/range, lock, temps, last update.
- `⟳` means data is stale and a background refresh started.
- `📱` means the phone app holds the MG session; click to take it back.

Polls every 5 min while the car is moving, every 5 hours when idle.

## Second account (recommended)

MG allows one active session per login. If Waybar uses the same
number as your phone app, they kick each other out.

Fix: add a second driver in the iSMART app (family/share), and put
that second number + password in `.env`. Waybar then has its own
session and never logs your phone out.

One account also works: Waybar uses soft polls that reuse its cached
token and back off with `📱` instead of stealing the phone's session.
