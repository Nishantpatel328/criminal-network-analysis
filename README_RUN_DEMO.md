# Criminal Network Analysis — Kimi + Claude Demo

This merged demo connects the Kimi frontend to a local FastAPI demo backend that serves the fictional Kimi dataset. Claude's original backend/security/analytics code remains in `services/api/app/`; the demo API is isolated in `services/api/app/demo_api.py` so it can be replaced by the real evidence-store integration later.

## One-click-ish Windows run

From the project root, double-click `run-demo.bat`.

Or manually:

Terminal 1:
```powershell
cd services/api
python -m pip install -r requirements.txt
python run_demo.py
```

Terminal 2:
```powershell
cd web
npm install
npm run dev
```

Open `http://localhost:5173`.

Demo login:
- Email: `a.rahman@intel.demo`
- Password: `demo1234`

## Architecture

`Kimi React UI -> /api -> FastAPI demo_api.py -> Kimi fictional dataset`

The original Claude production-oriented API remains separate and is not silently presented as a complete real-data backend. When a real Neo4j/evidence store is ready, the demo router can be replaced/mapped endpoint-by-endpoint.
