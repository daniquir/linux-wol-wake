# WoL Manager Pro

> Scan your local network, wake devices with Wake-on-LAN, and preview IP cameras — all from your browser, in Docker.

![Python](https://img.shields.io/badge/python-3.10+-blue)
![Flask](https://img.shields.io/badge/flask-3.0-000?logo=flask&logoColor=white)
![Docker](https://img.shields.io/badge/docker-compose-2496ED?logo=docker&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)

Web dashboard to **scan your local network**, manage devices, and send **Wake-on-LAN (WoL)** packets. Includes **IP camera** preview (RTSP/ONVIF) and basic **PTZ** control.

Built for homelab / LAN use. Runs in Docker with host network access.

## Features

- Device discovery (nmap, ARP, mDNS, NetBIOS)
- Automatic categorization (PC, server, camera, IoT, etc.)
- Per-device WoL enable/disable and wake
- Login with brute-force protection
- Cameras: RTSP URL probing, MJPEG streaming in the browser, ONVIF PTZ

## Requirements

- Docker and Docker Compose
- Linux (`network_mode: host` recommended for ARP scanning)

## Quick start

```bash
git clone https://github.com/YOUR_USER/linux-wol-wake.git
cd linux-wol-wake
cp .env.example .env
# Edit .env: set APP_USER and a strong APP_PASSWORD
docker compose build
docker compose up -d
```

Open in your browser: **http://localhost:5055**

> If `APP_PASSWORD` is not set, a temporary password is printed in the logs:  
> `docker compose logs wol-app`

## Configuration

| Variable | Description |
|----------|-------------|
| `APP_USER` | Login username (default: `admin`) |
| `APP_PASSWORD` | Password (min. 12 chars, upper, lower, digit, symbol) |
| `SECRET_KEY` | Optional Flask session key; stored in `.secret_key` if unset |
| `SESSION_COOKIE_SECURE` | `true` behind HTTPS; `false` for plain HTTP on LAN |

Persistent files (not committed to git):

- `devices.db` — device inventory
- `.secret_key` — session key when `SECRET_KEY` is not set

## Security

- **Do not expose port 5055 to the Internet** without a TLS reverse proxy and rate limiting.
- The container needs `NET_RAW`, `NET_ADMIN`, and `network_mode: host` to scan; use only on trusted networks.
- ONVIF camera passwords are stored in SQLite in plain text; restrict host and database access.
- Change default credentials in `.env` before production use.

## Project layout

```
app/
  main.py          # Flask routes and API
  models.py        # Device model (SQLite)
  scanner.py       # Network scanning
  wol.py           # WoL magic packet
  onvif_helper.py  # ONVIF / RTSP
  security.py      # Validation (ranges, RTSP URLs)
  static/          # Frontend
  templates/
Dockerfile
docker-compose.yml
```

## Local development (without Docker)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
# Requires nmap, ffmpeg, and scapy permissions (root or cap_net_raw)
export APP_USER=admin APP_PASSWORD='YourSecurePassword123!'
python -m app.main
```

## Continuous deploy (kanda-server)

Lab CD uses **Jenkins** on the LAN (`LINUX-WOL-WAKE-CD`), not GitHub Actions:

1. Poll SCM on `main` (public clone).
2. `docker build` → `kanda/linux-wol-wake:latest`.
3. `/docker/composes/linux-wol-wake/up.sh --force-recreate` (secrets from Vault).
4. Smoke check on `http://127.0.0.1:5055/login`.

Persistent inventory (`devices.db`) lives only on the host volume and is never rebuilt by the pipeline. See Memory-Stack `servicios/linux-wol-wake.md`.

## License

MIT — see [LICENSE](LICENSE).
