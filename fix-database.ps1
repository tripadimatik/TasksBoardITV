# Simple script to create PostgreSQL user and database

Write-Host "Setting up PostgreSQL database and user..."
Write-Host "This script will:"
Write-Host "1. Create database 'taskmanager'"
Write-Host "2. Create user 'taskmanager_user' with password 'taskmanager123'"
Write-Host "3. Grant necessary permissions"
Write-Host ""

# PostgreSQL path
$psqlPath = "C:\Program Files\PostgreSQL\16\bin\psql.exe"

if (-not (Test-Path $psqlPath)) {
    Write-Host "ERROR: PostgreSQL not found at $psqlPath" -ForegroundColor Red
    Write-Host "Please make sure PostgreSQL 16 is installed" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# Request admin password
$pgPassword = Read-Host "Enter PostgreSQL admin password (for user 'postgres')" -AsSecureString
$pgPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pgPassword))

if ([string]::IsNullOrWhiteSpace($pgPasswordPlain)) {
    Write-Host "Password cannot be empty!" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# Set password environment variable
$env:PGPASSWORD = $pgPasswordPlain

try {
    Write-Host "Testing connection to PostgreSQL..." -ForegroundColor Yellow
    
    # Test connection
    $testResult = & $psqlPath -h localhost -p 5432 -U postgres -d postgres -c "SELECT version();" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Cannot connect to PostgreSQL" -ForegroundColor Red
        Write-Host "Details: $testResult" -ForegroundColor Red
        Write-Host "Please check:" -ForegroundColor Yellow
        Write-Host "- PostgreSQL service is running" -ForegroundColor Yellow
        Write-Host "- Password is correct" -ForegroundColor Yellow
        Write-Host "- Port 5432 is accessible" -ForegroundColor Yellow
        Read-Host "Press Enter to exit"
        exit 1
    }
    
    Write-Host "Connection successful!" -ForegroundColor Green
    
    # Drop and create database
    Write-Host "Creating database 'taskmanager'..." -ForegroundColor Yellow
    & $psqlPath -h localhost -p 5432 -U postgres -d postgres -c "DROP DATABASE IF EXISTS taskmanager;" 2>$null
    $createDbResult = & $psqlPath -h localhost -p 5432 -U postgres -d postgres -c "CREATE DATABASE taskmanager;" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Database 'taskmanager' created successfully!" -ForegroundColor Green
    } else {
        Write-Host "Warning: Database creation failed: $createDbResult" -ForegroundColor Yellow
    }
    
    # Drop and create user
    Write-Host "Creating user 'taskmanager_user'..." -ForegroundColor Yellow
    & $psqlPath -h localhost -p 5432 -U postgres -d postgres -c "DROP USER IF EXISTS taskmanager_user;" 2>$null
    $createUserResult = & $psqlPath -h localhost -p 5432 -U postgres -d postgres -c "CREATE USER taskmanager_user WITH PASSWORD 'taskmanager123';" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "User 'taskmanager_user' created successfully!" -ForegroundColor Green
    } else {
        Write-Host "ERROR: User creation failed: $createUserResult" -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
    
    # Grant permissions
    Write-Host "Granting permissions..." -ForegroundColor Yellow
    & $psqlPath -h localhost -p 5432 -U postgres -d postgres -c "GRANT ALL PRIVILEGES ON DATABASE taskmanager TO taskmanager_user;" 2>$null
    & $psqlPath -h localhost -p 5432 -U postgres -d postgres -c "ALTER USER taskmanager_user CREATEDB;" 2>$null
    Write-Host "Permissions granted!" -ForegroundColor Green
    
    # Test user connection
    Write-Host "Testing user connection..." -ForegroundColor Yellow
    $env:PGPASSWORD = "taskmanager123"
    $testUserResult = & $psqlPath -h localhost -p 5432 -U taskmanager_user -d taskmanager -c "SELECT current_user, current_database();" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "User connection test successful!" -ForegroundColor Green
        Write-Host "Result: $testUserResult" -ForegroundColor Gray
    } else {
        Write-Host "Warning: User connection test failed: $testUserResult" -ForegroundColor Yellow
    }
    
} catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
} finally {
    # Clear password environment variable
    $env:PGPASSWORD = $null
}

Write-Host ""
Write-Host "=== SETUP COMPLETE ===" -ForegroundColor Green
Write-Host "Database: taskmanager" -ForegroundColor Gray
Write-Host "User: taskmanager_user" -ForegroundColor Gray
Write-Host "Password: taskmanager123" -ForegroundColor Gray
Write-Host ""
Write-Host "Your .env file should contain:" -ForegroundColor Yellow
Write-Host 'DATABASE_URL="postgresql://taskmanager_user:taskmanager123@localhost:5432/taskmanager"' -ForegroundColor Gray
Write-Host ""
Write-Host "Now you can run: npx prisma db push" -ForegroundColor Green
Read-Host "Press Enter to exit"