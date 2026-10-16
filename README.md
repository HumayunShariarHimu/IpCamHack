# IpCamHack

A monochrome, animated dashboard for authorized IP-camera/network inventory and basic TCP service checks.

## Features

- Premium black-and-white cyber-terminal UI with subtle animated grid/scanlines and reduced-motion support.
- IPv4 single-host, CIDR (/24 to /32), and explicit address-range inputs.
- Bounded read-only TCP checks for common web and camera-service ports, plus passive HTTP banner and camera-brand fingerprinting (Hikvision, Dahua, TP-Link, Xiaomi, Axis, Sony, Panasonic, Bosch, Samsung, Vivotek, Reolink, Amcrest, Ubiquiti and Hanwha). No login attempts or stream access.
- Filterable results, scan statistics, clear action, CSV export, and health endpoint.
- Restored APNIC country-code selector (45 entries) with select/deselect controls.
- Manual public IPv4 geolocation lookup (country, region, city, ISP, ASN, coordinates) with country-selection comparison.
- Bounded authorized public IPv4 range assessment (single IP, explicit range, or CIDR /24–/32; maximum 256 addresses) with explicit authorization confirmation and optional country-code filter.
- Bounded assessment of up to 20 explicitly supplied public IPv4 addresses with a required authorization confirmation and optional country-code filter; checks ports and performs passive HTTP banner fingerprinting without authentication.
- Browser-local scan history (last 20 scans) with restore and clear controls; history remains on that browser/device.
- Rejects public IP targets and scan ranges larger than 256 addresses.
- No credential guessing, password collection, or camera-feed interception.

## Requirements

- Node.js 18 or newer
- npm

## Run locally

Run the scanner on a computer connected to the network you own or are authorized to assess. A hosted Vercel function cannot reach devices on your private LAN, so the scan endpoint is intentionally disabled in serverless mode.

```bash
npm install
npm start
```

Open http://localhost:3000.

For development with automatic restarts:

```bash
npm run dev
```

## Tests

```bash
npm test
```

## Deploying the dashboard

The Vercel deployment can host the dashboard and health/status API, but it cannot scan your home/office LAN. Run the app locally to use the scan feature. Avoid exposing a local scanner directly to the public internet.

## API

- `GET /api/health` — service status and runtime environment.
- `GET /api/status` — latest in-memory scan results and statistics.
- `GET /api/countries` — APNIC region country-code/name catalog.
- `GET /api/geo?ip=8.8.8.8` — geolocation for one manually supplied public IPv4 address; uses the external ipwho.is service. Private/reserved targets are rejected.
- `POST /api/scan/range` — local-only TCP port inventory; JSON body: `{"range":"192.168.1.0/24"}`.
- `POST /api/scan/public-range` — local-only assessment of an explicitly authorized public IPv4 single address, start-end range, or CIDR `/24` to `/32` (up to 256 addresses); JSON body: `{"range":"203.0.113.0/28","countries":["US"],"authorized":true}`. The example range is documentation-only and will be rejected as reserved; supply a real range you are authorized to assess.
- `POST /api/scan/targets` — bounded checks and passive HTTP brand/service fingerprinting for 1–20 explicitly supplied public IPv4 addresses; JSON body: `{"ips":["8.8.8.8"],"countries":["US"],"authorized":true}`. Requires explicit authorization confirmation and does not accept CIDRs, random targets, or credentials.
- `POST /api/clear` — clear in-memory results.

Scan history is stored in the browser's local storage and does not sync between devices. Geolocation lookups send the entered public IP to ipwho.is; do not submit an address you do not want shared with that provider. Country selection compares manually looked-up IPs and filters only explicitly scoped assessment targets/ranges; it never starts a country-wide scan.

Detected open ports and HTTP banners are indicators only. A brand signature or camera-related port does not prove that a host is an IP camera. Historical random-public-IP generation and automated default-password guessing are intentionally not re-enabled; random sampling works only from a user-provided authorized target list.
