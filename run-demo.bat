@echo off
setlocal
cd /d "%~dp0"
echo [1/2] Starting backend at http://127.0.0.1:8000 ...
start "CNA Backend" cmd /k "cd /d "%~dp0services\api" && python -m pip install -r requirements.txt && python run_demo.py"
timeout /t 3 /nobreak >nul
echo [2/2] Starting frontend at http://localhost:5173 ...
cd /d "%~dp0web"
if not exist node_modules npm install
npm run dev
endlocal
