# Task Manager - Автоматическая настройка для Windows
# Этот скрипт проверит систему и настроит проект автоматически

Write-Host "=== Task Manager - Автоматическая настройка ==="
Write-Host ""

# Проверка версии PowerShell
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Host "❌ Требуется PowerShell 5.0 или выше" -ForegroundColor Red
    Write-Host "Текущая версия: $($PSVersionTable.PSVersion)" -ForegroundColor Yellow
    exit 1
}
Write-Host "✅ PowerShell версия: $($PSVersionTable.PSVersion)" -ForegroundColor Green

# Функция для проверки команды
function Test-Command($command) {
    try {
        if (Get-Command $command -ErrorAction Stop) { return $true }
    } catch {
        return $false
    }
}

# Функция для проверки порта
function Test-Port($port) {
    $connection = Test-NetConnection -ComputerName localhost -Port $port -InformationLevel Quiet -WarningAction SilentlyContinue
    return $connection
}

# Проверка Node.js
Write-Host "🔍 Проверка Node.js..." -ForegroundColor Cyan
if (Test-Command "node") {
    $nodeVersion = node --version
    Write-Host "✅ Node.js установлен: $nodeVersion" -ForegroundColor Green
    
    # Проверка версии Node.js
    $versionNumber = [int]($nodeVersion -replace 'v(\d+)\..*', '$1')
    if ($versionNumber -lt 16) {
        Write-Host "⚠️  Рекомендуется Node.js версии 16 или выше" -ForegroundColor Yellow
        Write-Host "Скачайте с: https://nodejs.org/" -ForegroundColor Yellow
    }
} else {
    Write-Host "❌ Node.js не найден" -ForegroundColor Red
    Write-Host "Скачайте и установите с: https://nodejs.org/" -ForegroundColor Yellow
    Write-Host "После установки перезапустите этот скрипт" -ForegroundColor Yellow
    exit 1
}

# Проверка npm
Write-Host "🔍 Проверка npm..." -ForegroundColor Cyan
if (Test-Command "npm") {
    $npmVersion = npm --version
    Write-Host "✅ npm установлен: v$npmVersion" -ForegroundColor Green
} else {
    Write-Host "❌ npm не найден" -ForegroundColor Red
    exit 1
}

# Проверка Git
Write-Host "🔍 Проверка Git..." -ForegroundColor Cyan
if (Test-Command "git") {
    $gitVersion = git --version
    Write-Host "✅ Git установлен: $gitVersion" -ForegroundColor Green
} else {
    Write-Host "⚠️  Git не найден" -ForegroundColor Yellow
    Write-Host "Скачайте с: https://git-scm.com/download/win" -ForegroundColor Yellow
}

# Проверка PostgreSQL
Write-Host "🔍 Проверка PostgreSQL..." -ForegroundColor Cyan
if (Test-Command "psql") {
    try {
        $pgVersion = psql --version
        Write-Host "✅ PostgreSQL установлен: $pgVersion" -ForegroundColor Green
        
        # Проверка службы PostgreSQL
        $pgService = Get-Service -Name "postgresql*" -ErrorAction SilentlyContinue
        if ($pgService) {
            if ($pgService.Status -eq "Running") {
                Write-Host "✅ Служба PostgreSQL запущена" -ForegroundColor Green
            } else {
                Write-Host "⚠️  Служба PostgreSQL остановлена. Попытка запуска..." -ForegroundColor Yellow
                try {
                    Start-Service $pgService.Name
                    Write-Host "✅ Служба PostgreSQL запущена" -ForegroundColor Green
                } catch {
                    Write-Host "❌ Не удалось запустить службу PostgreSQL" -ForegroundColor Red
                    Write-Host "Запустите службу вручную или перезагрузите компьютер" -ForegroundColor Yellow
                }
            }
        } else {
            Write-Host "⚠️  Служба PostgreSQL не найдена" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "⚠️  PostgreSQL установлен, но возможны проблемы с настройкой" -ForegroundColor Yellow
    }
} else {
    Write-Host "❌ PostgreSQL не найден" -ForegroundColor Red
    Write-Host "Скачайте и установите с: https://www.postgresql.org/download/windows/" -ForegroundColor Yellow
    Write-Host "После установки перезапустите этот скрипт" -ForegroundColor Yellow
    
    $continue = Read-Host "Продолжить без PostgreSQL? (y/N)"
    if ($continue -ne "y" -and $continue -ne "Y") {
        exit 1
    }
}

# Проверка Docker (опционально)
Write-Host "🔍 Проверка Docker..." -ForegroundColor Cyan
if (Test-Command "docker") {
    try {
        $dockerVersion = docker --version
        Write-Host "✅ Docker установлен: $dockerVersion" -ForegroundColor Green
    } catch {
        Write-Host "⚠️  Docker установлен, но не запущен" -ForegroundColor Yellow
    }
} else {
    Write-Host "ℹ️  Docker не найден (опционально)" -ForegroundColor Gray
}

# Проверка портов
Write-Host "🔍 Проверка портов..." -ForegroundColor Cyan
$ports = @(3001, 5432, 5173)
foreach ($port in $ports) {
    if (Test-Port $port) {
        Write-Host "⚠️  Порт $port занят" -ForegroundColor Yellow
        $processes = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue | Select-Object OwningProcess
        if ($processes) {
            foreach ($proc in $processes) {
                $processName = (Get-Process -Id $proc.OwningProcess -ErrorAction SilentlyContinue).ProcessName
                Write-Host "   Процесс: $processName (PID: $($proc.OwningProcess))" -ForegroundColor Gray
            }
        }
    } else {
        Write-Host "✅ Порт $port свободен" -ForegroundColor Green
    }
}

# Проверка файлов проекта
Write-Host "🔍 Проверка файлов проекта..." -ForegroundColor Cyan
$requiredFiles = @(
    "package.json",
    "server/package.json",
    "server/index.js",
    "prisma/schema.prisma",
    ".env.example"
)

$missingFiles = @()
foreach ($file in $requiredFiles) {
    if (Test-Path $file) {
        Write-Host "✅ $file" -ForegroundColor Green
    } else {
        Write-Host "❌ $file" -ForegroundColor Red
        $missingFiles += $file
    }
}

if ($missingFiles.Count -gt 0) {
    Write-Host "❌ Отсутствуют важные файлы проекта" -ForegroundColor Red
    Write-Host "Убедитесь, что вы находитесь в корневой папке проекта" -ForegroundColor Yellow
    exit 1
}

# Создание .env файла
Write-Host "🔧 Настройка .env файла..." -ForegroundColor Cyan
if (-not (Test-Path ".env")) {
    if (Test-Path ".env.example") {
        Copy-Item ".env.example" ".env"
        Write-Host "✅ Создан .env файл из .env.example" -ForegroundColor Green
        
        # Интерактивная настройка .env
        Write-Host "\n📝 Настройка базы данных:" -ForegroundColor Cyan
        
        $dbHost = Read-Host "Хост базы данных (по умолчанию: localhost)"
        if ([string]::IsNullOrWhiteSpace($dbHost)) { $dbHost = "localhost" }
        
        $dbPort = Read-Host "Порт базы данных (по умолчанию: 5432)"
        if ([string]::IsNullOrWhiteSpace($dbPort)) { $dbPort = "5432" }
        
        $dbName = Read-Host "Имя базы данных (по умолчанию: taskmanager)"
        if ([string]::IsNullOrWhiteSpace($dbName)) { $dbName = "taskmanager" }
        
        $dbUser = Read-Host "Пользователь базы данных (по умолчанию: postgres)"
        if ([string]::IsNullOrWhiteSpace($dbUser)) { $dbUser = "postgres" }
        
        $dbPassword = Read-Host "Пароль базы данных" -AsSecureString
        $dbPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($dbPassword))
        
        if ([string]::IsNullOrWhiteSpace($dbPasswordPlain)) {
            Write-Host "⚠️  Пароль не может быть пустым" -ForegroundColor Yellow
            $dbPasswordPlain = "admin123"
            Write-Host "Используется пароль по умолчанию: admin123" -ForegroundColor Yellow
        }
        
        # Генерация JWT секрета
        $jwtSecret = -join ((1..32) | ForEach {[char]((65..90) + (97..122) + (48..57) | Get-Random)})
        
        # Обновление .env файла
        $envContent = Get-Content ".env"
        $envContent = $envContent -replace 'DATABASE_URL=".*"', "DATABASE_URL=\"postgresql://$dbUser`:$dbPasswordPlain@$dbHost`:$dbPort/$dbName\""
        $envContent = $envContent -replace 'JWT_SECRET=".*"', "JWT_SECRET=\"$jwtSecret\""
        $envContent | Set-Content ".env"
        
        Write-Host "✅ .env файл настроен" -ForegroundColor Green
    } else {
        Write-Host "❌ .env.example не найден" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "✅ .env файл уже существует" -ForegroundColor Green
}

# Установка зависимостей
Write-Host "📦 Установка зависимостей..." -ForegroundColor Cyan

# Фронтенд
Write-Host "Установка зависимостей фронтенда..." -ForegroundColor Gray
try {
    npm install
    Write-Host "✅ Зависимости фронтенда установлены" -ForegroundColor Green
} catch {
    Write-Host "❌ Ошибка установки зависимостей фронтенда" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
}

# Бэкенд
Write-Host "Установка зависимостей бэкенда..." -ForegroundColor Gray
try {
    Set-Location "server"
    npm install
    Set-Location ".."
    Write-Host "✅ Зависимости бэкенда установлены" -ForegroundColor Green
} catch {
    Write-Host "❌ Ошибка установки зависимостей бэкенда" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Set-Location ".."
}

# Настройка Prisma
Write-Host "🗄️ Настройка базы данных..." -ForegroundColor Cyan

try {
    Write-Host "Генерация Prisma клиента..." -ForegroundColor Gray
    npx prisma generate
    Write-Host "✅ Prisma клиент сгенерирован" -ForegroundColor Green
    
    Write-Host "Применение схемы базы данных..." -ForegroundColor Gray
    npx prisma db push
    Write-Host "✅ Схема базы данных применена" -ForegroundColor Green
} catch {
    Write-Host "❌ Ошибка настройки базы данных" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host "\nВозможные причины:" -ForegroundColor Yellow
    Write-Host "1. PostgreSQL не запущен" -ForegroundColor Yellow
    Write-Host "2. Неверные данные подключения в .env" -ForegroundColor Yellow
    Write-Host "3. База данных не создана" -ForegroundColor Yellow
    Write-Host "\nПопробуйте создать базу данных вручную:" -ForegroundColor Yellow
    Write-Host "psql -U postgres -c \"CREATE DATABASE taskmanager;\"" -ForegroundColor Gray
}

# Создание папки uploads
if (-not (Test-Path "uploads")) {
    New-Item -ItemType Directory -Path "uploads" | Out-Null
    Write-Host "✅ Создана папка uploads" -ForegroundColor Green
}

# Итоговый отчет
Write-Host "\n=== НАСТРОЙКА ЗАВЕРШЕНА ===" -ForegroundColor Green
Write-Host "\n📋 Следующие шаги:" -ForegroundColor Cyan
Write-Host "\n1. Запуск проекта:" -ForegroundColor White
Write-Host "   start-project.bat" -ForegroundColor Gray
Write-Host "\n2. Или ручной запуск:" -ForegroundColor White
Write-Host "   # Терминал 1 - Бэкенд:" -ForegroundColor Gray
Write-Host "   cd server && node index.js" -ForegroundColor Gray
Write-Host "   # Терминал 2 - Фронтенд:" -ForegroundColor Gray
Write-Host "   npm run dev" -ForegroundColor Gray

Write-Host "\n🌐 После запуска:" -ForegroundColor Cyan
Write-Host "   Фронтенд: http://localhost:5173" -ForegroundColor Gray
Write-Host "   Бэкенд:   http://localhost:3001" -ForegroundColor Gray
Write-Host "   Prisma:   http://localhost:5555 (npm run db:studio)" -ForegroundColor Gray

Write-Host "\n📚 Документация:" -ForegroundColor Cyan
Write-Host "   README.md - Полное руководство по установке и запуску" -ForegroundColor Gray

Write-Host "\n🎉 Удачи с проектом!" -ForegroundColor Green