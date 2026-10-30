# Deploy (Docker)

1. Copy folder to server, e.g. `/opt/lab03`.
2. (Optional) `cp .env.example .env` and set `NVD_API_KEY`, `ALLOWED_CIDRS`.
3. `docker compose up -d --build`
4. Open `http://<server-ip>:8000` from any machine on the LAN.
5. Enter target IP/CIDR, click Start Scan. Report renders in-page; CSV downloadable.

Notes:
- Requires Linux host for `network_mode: host` (nmap LAN scanning + ping sweeps).
- Container needs `NET_ADMIN`/`NET_RAW` capabilities (already in compose).
- Reports and CVE cache persist in `./data` volume.
- Only scan hosts you are authorized to test. ALLOWED_CIDRS restricts targets.
