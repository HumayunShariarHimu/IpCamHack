# IpCamHack

A monochrome, animated dashboard for authorized IP-camera/network inventory and basic TCP service checks.

## Features

- Premium black-and-white cyber-terminal UI with subtle animated grid/scanlines and reduced-motion support.
- IPv4 single-host, CIDR (/24 to /32), and explicit address-range inputs.
- Bounded read-only TCP checks for common web and camera-service ports.
- Filterable results, scan statistics, clear action, CSV export, and health endpoint.
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
- `POST /api/scan/range` — local-only TCP port inventory; JSON body: `{"range":"192.168.1.0/24"}`.
- `POST /api/clear` — clear in-memory results.

Detected open ports are indicators only. An open port does not prove that a host is an IP camera, and this tool does not authenticate to devices.
