# Criminal Network Analysis

## Run the React workstation

Prerequisite: Node.js 20 or later.

In PowerShell, open the `web` folder and run:

```powershell
npm install
npm run dev
```

Open the local address printed by Vite (normally `http://localhost:5173`). The
workstation opens without a backend so its protected empty state can be reviewed.
To retrieve records, run the authorised API deployment and sign in through the
organisation's identity provider; paste a short-lived session token, declare a
case and purpose, then request a record reference.

For a production bundle:

```powershell
npm run typecheck
npm run build
```

## Verify the Python security suite

From the project root:

```powershell
python tests/run_tests.py
```

The suite is intentionally able to use its included test shim when `pytest` is
not installed. It does not start a live API, Neo4j database, identity provider,
or key-management service.

## Production requirements

This repository is not a self-contained production deployment. Before serving
investigative data, provide the configured Neo4j store, OIDC/mTLS identity
boundary, audit signing and key-management service, tenant regime, lawful-basis
controls, monitoring, and the release gates in `docs/compliance.md`. Do not use
development credentials or a local browser-only session for operational data.
