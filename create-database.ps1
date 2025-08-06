# Автоматическое создание базы данных PostgreSQL для Task Manager
# Этот скрипт создаст базу данных и пользователя автоматически

Write-Host "=== Создание базы данных PostgreSQL ===" -ForegroundColor Green
Write-Host ""

# Функция для проверки команды
function Test-Command($command) {
    try {
        if (Get-Command $command -ErrorAction Stop) { return $true }
    } catch {
        return $false
    }
}

# Проверка PostgreSQL
if (-not (Test-Command "psql")) {
    Write-Host "❌ PostgreSQL не найден!" -ForegroundColor Red
    Write-Host "Установите PostgreSQL с: https://www.postgresql.org/download/windows/" -ForegroundColor Yellow
    Write-Host "После установки перезапустите этот скрипт" -ForegroundColor Yellow
    Read-Host "Нажмите Enter для выхода"
    exit 1
}

Write-Host "✅ PostgreSQL найден" -ForegroundColor Green

# Запрос данных для подключения
Write-Host "\n📝 Настройка подключения к PostgreSQL:" -ForegroundColor Cyan
Write-Host "(Если не знаете что вводить, просто нажимайте Enter для значений по умолчанию)" -ForegroundColor Gray
Write-Host ""

$pgHost = Read-Host "Хост PostgreSQL (по умолчанию: localhost)"
if ([string]::IsNullOrWhiteSpace($pgHost)) { $pgHost = "localhost" }

$pgPort = Read-Host "Порт PostgreSQL (по умолчанию: 5432)"
if ([string]::IsNullOrWhiteSpace($pgPort)) { $pgPort = "5432" }

$pgUser = Read-Host "Администратор PostgreSQL (по умолчанию: postgres)"
if ([string]::IsNullOrWhiteSpace($pgUser)) { $pgUser = "postgres" }

$pgPassword = Read-Host "Пароль администратора PostgreSQL" -AsSecureString
$pgPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pgPassword))

if ([string]::IsNullOrWhiteSpace($pgPasswordPlain)) {
    Write-Host "❌ Пароль не может быть пустым!" -ForegroundColor Red
    Read-Host "Нажмите Enter для выхода"
    exit 1
}

# Проверка подключения
Write-Host "\n🔍 Проверка подключения к PostgreSQL..." -ForegroundColor Cyan

$env:PGPASSWORD = $pgPasswordPlain
try {
    $testConnection = psql -h $pgHost -p $pgPort -U $pgUser -d postgres -c "SELECT version();" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Не удалось подключиться к PostgreSQL" -ForegroundColor Red
        Write-Host "Проверьте данные подключения:" -ForegroundColor Yellow
        Write-Host "- Хост: $pgHost" -ForegroundColor Gray
        Write-Host "- Порт: $pgPort" -ForegroundColor Gray
        Write-Host "- Пользователь: $pgUser" -ForegroundColor Gray
        Write-Host "- Пароль: [скрыт]" -ForegroundColor Gray
        Read-Host "Нажмите Enter для выхода"
        exit 1
    }
    Write-Host "✅ Подключение к PostgreSQL успешно" -ForegroundColor Green
} catch {
    Write-Host "❌ Ошибка подключения: $($_.Exception.Message)" -ForegroundColor Red
    Read-Host "Нажмите Enter для выхода"
    exit 1
}

# Проверка существования базы данных
Write-Host "\n🗄️  Проверка базы данных taskmanager..." -ForegroundColor Cyan

$checkDb = psql -h $pgHost -p $pgPort -U $pgUser -d postgres -t -c "SELECT 1 FROM pg_database WHERE datname='taskmanager';" 2>&1
if ($checkDb -match "1") {
    Write-Host "✅ База данных taskmanager уже существует" -ForegroundColor Green
    
    $recreate = Read-Host "Пересоздать базу данных? (y/N)"
    if ($recreate -eq "y" -or $recreate -eq "Y") {
        Write-Host "🗑️  Удаление существующей базы данных..." -ForegroundColor Yellow
        $dropDb = psql -h $pgHost -p $pgPort -U $pgUser -d postgres -c "DROP DATABASE IF EXISTS taskmanager;" 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ База данных удалена" -ForegroundColor Green
        } else {
            Write-Host "❌ Ошибка удаления базы данных: $dropDb" -ForegroundColor Red
            Read-Host "Нажмите Enter для выхода"
            exit 1
        }
    } else {
        Write-Host "ℹ️  Используется существующая база данных" -ForegroundColor Blue
        $dbExists = $true
    }
}

# Создание базы данных
if (-not $dbExists) {
    Write-Host "\n🔧 Создание базы данных taskmanager..." -ForegroundColor Cyan
    
    $createDb = psql -h $pgHost -p $pgPort -U $pgUser -d postgres -c "CREATE DATABASE taskmanager WITH ENCODING='UTF8' LC_COLLATE='C' LC_CTYPE='C' TEMPLATE=template0;" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ База данных taskmanager создана" -ForegroundColor Green
    } else {
        Write-Host "❌ Ошибка создания базы данных: $createDb" -ForegroundColor Red
        Read-Host "Нажмите Enter для выхода"
        exit 1
    }
}

# Создание пользователя для приложения (опционально)
Write-Host "\n👤 Создание пользователя для приложения..." -ForegroundColor Cyan

$createAppUser = Read-Host "Создать отдельного пользователя taskmanager_user? (Y/n)"
if ($createAppUser -ne "n" -and $createAppUser -ne "N") {
    $appPassword = Read-Host "Пароль для пользователя taskmanager_user (по умолчанию: taskmanager123)"
    if ([string]::IsNullOrWhiteSpace($appPassword)) { $appPassword = "taskmanager123" }
    
    # Проверка существования пользователя
    $checkUser = psql -h $pgHost -p $pgPort -U $pgUser -d postgres -t -c "SELECT 1 FROM pg_user WHERE usename='taskmanager_user';" 2>&1
    if ($checkUser -match "1") {
        Write-Host "⚠️  Пользователь taskmanager_user уже существует" -ForegroundColor Yellow
        $dropUser = psql -h $pgHost -p $pgPort -U $pgUser -d postgres -c "DROP USER IF EXISTS taskmanager_user;" 2>&1
    }
    
    # Создание пользователя
    $createUser = psql -h $pgHost -p $pgPort -U $pgUser -d postgres -c "CREATE USER taskmanager_user WITH PASSWORD '$appPassword';" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Пользователь taskmanager_user создан" -ForegroundColor Green
        
        # Выдача прав
        $grantRights = psql -h $pgHost -p $pgPort -U $pgUser -d postgres -c "GRANT ALL PRIVILEGES ON DATABASE taskmanager TO taskmanager_user; ALTER USER taskmanager_user CREATEDB;" 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ Права пользователю выданы" -ForegroundColor Green
            $useAppUser = $true
            $finalUser = "taskmanager_user"
            $finalPassword = $appPassword
        } else {
            Write-Host "⚠️  Ошибка выдачи прав: $grantRights" -ForegroundColor Yellow
            Write-Host "Будет использован пользователь postgres" -ForegroundColor Yellow
            $finalUser = $pgUser
            $finalPassword = $pgPasswordPlain
        }
    } else {
        Write-Host "⚠️  Ошибка создания пользователя: $createUser" -ForegroundColor Yellow
        Write-Host "Будет использован пользователь postgres" -ForegroundColor Yellow
        $finalUser = $pgUser
        $finalPassword = $pgPasswordPlain
    }
} else {
    Write-Host "ℹ️  Будет использован пользователь postgres" -ForegroundColor Blue
    $finalUser = $pgUser
    $finalPassword = $pgPasswordPlain
}

# Создание/обновление .env файла
Write-Host "\n📝 Настройка .env файла..." -ForegroundColor Cyan

$databaseUrl = "postgresql://$finalUser`:$finalPassword@$pgHost`:$pgPort/taskmanager"

if (Test-Path ".env") {
    Write-Host "⚠️  .env файл уже существует" -ForegroundColor Yellow
    $updateEnv = Read-Host "Обновить DATABASE_URL в .env файле? (Y/n)"
    if ($updateEnv -ne "n" -and $updateEnv -ne "N") {
        $envContent = Get-Content ".env"
        $envContent = $envContent -replace 'DATABASE_URL=".*"', "DATABASE_URL=\"$databaseUrl\""
        $envContent | Set-Content ".env"
        Write-Host "✅ .env файл обновлен" -ForegroundColor Green
    }
} else {
    if (Test-Path ".env.example") {
        Copy-Item ".env.example" ".env"
        $envContent = Get-Content ".env"
        $envContent = $envContent -replace 'DATABASE_URL=".*"', "DATABASE_URL=\"$databaseUrl\""
        
        # Генерация JWT секрета
        $jwtSecret = -join ((1..32) | ForEach {[char]((65..90) + (97..122) + (48..57) | Get-Random)})
        $envContent = $envContent -replace 'JWT_SECRET=".*"', "JWT_SECRET=`"$jwtSecret`""
        
        $envContent | Set-Content ".env"
        Write-Host "✅ .env файл создан и настроен" -ForegroundColor Green
    } else {
        Write-Host "❌ .env.example не найден" -ForegroundColor Red
        Write-Host "Создайте .env файл вручную с содержимым:" -ForegroundColor Yellow
        Write-Host "DATABASE_URL=\"$databaseUrl\"" -ForegroundColor Gray
    }
}

# Тестирование подключения к созданной базе
Write-Host "\n🧪 Тестирование подключения к базе taskmanager..." -ForegroundColor Cyan

$env:PGPASSWORD = $finalPassword
$testAppConnection = psql -h $pgHost -p $pgPort -U $finalUser -d taskmanager -c "SELECT current_database(), current_user;" 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Подключение к базе taskmanager успешно" -ForegroundColor Green
} else {
    Write-Host "❌ Ошибка подключения к базе: $testAppConnection" -ForegroundColor Red
}

# Очистка переменной окружения
$env:PGPASSWORD = $null

# Итоговый отчет
Write-Host "\n=== НАСТРОЙКА ЗАВЕРШЕНА ===" -ForegroundColor Green
Write-Host "\n📋 Информация о базе данных:" -ForegroundColor Cyan
Write-Host "   Хост: $pgHost" -ForegroundColor Gray
Write-Host "   Порт: $pgPort" -ForegroundColor Gray
Write-Host "   База данных: taskmanager" -ForegroundColor Gray
Write-Host "   Пользователь: $finalUser" -ForegroundColor Gray
Write-Host "   Пароль: [настроен в .env]" -ForegroundColor Gray

Write-Host "\n🔗 Строка подключения:" -ForegroundColor Cyan
Write-Host "   $databaseUrl" -ForegroundColor Gray

Write-Host "\n📋 Следующие шаги:" -ForegroundColor Cyan
Write-Host "1. Запустите setup-windows.ps1 для настройки проекта" -ForegroundColor White
Write-Host "2. Или запустите start-project.bat для запуска" -ForegroundColor White

Write-Host "\n🎉 База данных готова к использованию!" -ForegroundColor Green
Read-Host "Нажмите Enter для выхода"