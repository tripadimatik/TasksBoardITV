@echo off
echo Starting Bureau Task Manager Development Environment...
echo.

REM Check if node_modules exists, if not install dependencies
if not exist "node_modules" (
    echo Installing dependencies...
    npm install
    echo.
)

REM Start server and frontend concurrently
echo Starting server and frontend...
start "Server" cmd /k "cd server && node index.js"
start "Frontend" cmd /k "npm run dev"

echo.
echo Development environment started!
echo Server: http://localhost:3001
echo Frontend: http://localhost:3000
echo.
pause