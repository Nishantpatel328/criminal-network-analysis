# CNA — Merged Kimi + Claude frontend

## Quick start

Requires Node.js 20+.

### Option A — VS Code terminal

```powershell
cd web
npm install
npm run dev
```

Then open the URL printed by Vite (normally http://localhost:5173).

### Option B — Windows

Double-click `../RUN_DEMO.bat` from the project root. It installs dependencies and starts Vite.

## Demo account

`a.rahman@intel.demo`

`demo1234`

## Current data mode

`VITE_USE_MOCK=true` is intentional. The project currently has no real investigation dataset, so the fictional Kimi dataset powers the complete dashboard: entities, relationships, cases, events, CDR, financial transactions, locations, alerts, reports and data sources.

## Architecture

- Claude repository remains the base and keeps its Python API/analytics/security/graph implementation and documentation.
- Kimi dashboard screens and fictional dataset are integrated into `web/src`.
- `web/src/services/apiService.ts` is the switch point between mock and HTTP adapters.
- Set `VITE_USE_MOCK=false` and configure `VITE_API_BASE_URL` when wiring the frontend to a compatible live API.

The mock records are fictional demo data only.
