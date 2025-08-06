# Bureau Task Manager Development Environment Starter
Write-Host "Starting Bureau Task Manager Development Environment..." -ForegroundColor Green
Write-Host ""

# Check if node_modules exists, if not install dependencies
if (-not (Test-Path "node_modules")) {
    Write-Host "Installing dependencies..." -ForegroundColor Yellow
    npm install
    Write-Host ""
}

# Start server and frontend concurrently
Write-Host "Starting server and frontend..." -ForegroundColor Cyan

# Start server in new window
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd server; node index.js"

# Start frontend in new window
Start-Process powershell -ArgumentList "-NoExit", "-Command", "npm run dev"

Write-Host ""
Write-Host "Development environment started!" -ForegroundColor Green
Write-Host "Server: http://localhost:3001" -ForegroundColor Cyan
Write-Host "Frontend: http://localhost:3000" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press any key to exit..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")