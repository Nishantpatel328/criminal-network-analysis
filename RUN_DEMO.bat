@echo off
cd /d "%~dp0web"
echo Installing frontend dependencies...
npm install
if errorlevel 1 pause & exit /b 1
echo Starting Criminal Network Analysis dashboard...
npm run dev
pause
