# Criminal Network Analysis — Kimi + Claude merged build

This build keeps the original Claude repository (backend, analytics, graph and security documentation) and integrates the Kimi investigation dashboard frontend plus its fictional mock investigation dataset.

## Run the dashboard

Prerequisite: Node.js 20+

```powershell
cd web
npm install
npm run dev
```

Open the Vite URL, normally http://localhost:5173.

### Demo login

Email: `a.rahman@intel.demo`

Password: `demo1234`

The frontend uses the Kimi fictional mock dataset by default, so it works without Neo4j, an identity provider or a live API.

## Production/backend mode

Set `VITE_USE_MOCK=false` and `VITE_API_BASE_URL` to the API base path/URL before running. The HTTP adapter is isolated under `web/src/services/api/` so the frontend can be wired to the Claude service endpoints later.

## Original Claude backend

The original Python services, graph/Cypher files, analytics, tests and security/compliance documentation remain in this repository. They are not replaced by the demo mock layer.
