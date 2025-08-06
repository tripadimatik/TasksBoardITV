@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

echo ===============================================
echo    Task Manager - Автоматический запуск
echo ===============================================
echo.

REM Проверка наличия Node.js
node --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Node.js не найден!
    echo Установите Node.js с https://nodejs.org/
    pause
    exit /b 1
)

REM Проверка наличия файлов проекта
if not exist "package.json" (
    echo ❌ package.json не найден!
    echo Убедитесь, что вы находитесь в корневой папке проекта
    pause
    exit /b 1
)

if not exist "server\package.json" (
    echo ❌ server\package.json не найден!
    echo Убедитесь, что вы находитесь в корневой папке проекта
    pause
    exit /b 1
)

REM Проверка .env файла
if not exist ".env" (
    echo ⚠️  .env файл не найден!
    if exist ".env.example" (
        echo Создание .env файла из .env.example...
        copy ".env.example" ".env" >nul
        echo ✅ .env файл создан
        echo ⚠️  Не забудьте настроить DATABASE_URL в .env файле
    ) else (
        echo ❌ .env.example не найден!
        pause
        exit /b 1
    )
)

REM Проверка PostgreSQL
echo 🔍 Проверка PostgreSQL...
psql --version >nul 2>&1
if errorlevel 1 (
    echo ❌ PostgreSQL не найден!
    echo Установите PostgreSQL с https://www.postgresql.org/download/windows/
    echo Или используйте Docker: docker run --name postgres -e POSTGRES_PASSWORD=admin123 -p 5432:5432 -d postgres
    pause
    exit /b 1
) else (
    echo ✅ PostgreSQL найден
)

REM Попытка создать базу данных, если она не существует
echo 🗄️  Проверка базы данных...
psql -U postgres -lqt | cut -d ^| -f 1 | findstr /r "^[[:space:]]*taskmanager[[:space:]]*$" >nul 2>&1
if errorlevel 1 (
    echo ⚠️  База данных taskmanager не найдена
    echo Попытка создания базы данных...
    psql -U postgres -c "CREATE DATABASE taskmanager;" >nul 2>&1
    if errorlevel 1 (
        echo ❌ Не удалось создать базу данных автоматически
        echo Создайте базу данных вручную:
        echo psql -U postgres -c "CREATE DATABASE taskmanager;"
        pause
        exit /b 1
    ) else (
        echo ✅ База данных taskmanager создана
    )
) else (
    echo ✅ База данных taskmanager найдена
)

REM Проверка зависимостей
echo 📦 Проверка зависимостей...
if not exist "node_modules" (
    echo Установка зависимостей фронтенда...
    npm install
    if errorlevel 1 (
        echo ❌ Ошибка установки зависимостей фронтенда
        pause
        exit /b 1
    )
)

if not exist "server\node_modules" (
    echo Установка зависимостей бэкенда...
    cd server
    npm install
    if errorlevel 1 (
        echo ❌ Ошибка установки зависимостей бэкенда
        cd ..
        pause
        exit /b 1
    )
    cd ..
)

REM Настройка Prisma
echo 🔧 Настройка Prisma...
npx prisma generate >nul 2>&1
if errorlevel 1 (
    echo ❌ Ошибка генерации Prisma клиента
    pause
    exit /b 1
)

npx prisma db push >nul 2>&1
if errorlevel 1 (
    echo ❌ Ошибка применения схемы базы данных
    echo Проверьте настройки DATABASE_URL в .env файле
    pause
    exit /b 1
)

REM Создание папки uploads
if not exist "uploads" (
    mkdir uploads
    echo ✅ Создана папка uploads
)

echo.
echo ✅ Все проверки пройдены!
echo.
echo 🚀 Запуск серверов...
echo.
echo 📍 Адреса:
echo    Фронтенд: http://localhost:5173
echo    Бэкенд:   http://localhost:3001
echo    Prisma:   http://localhost:5555 (npm run db:studio)
echo.
echo 🛑 Для остановки нажмите Ctrl+C в каждом окне
echo.

REM Запуск бэкенда в новом окне
echo Запуск бэкенда...
start "Task Manager - Backend" cmd /k "cd /d "%~dp0server" && echo 🔧 Запуск бэкенда на http://localhost:3001 && node index.js"

REM Небольшая задержка
timeout /t 3 /nobreak >nul

REM Запуск фронтенда в новом окне
echo Запуск фронтенда...
start "Task Manager - Frontend" cmd /k "cd /d "%~dp0" && echo 🎨 Запуск фронтенда на http://localhost:5173 && npm run dev"

echo.
echo 🎉 Серверы запущены!
echo.
echo 📋 Полезные команды:
echo    npm run db:studio  - Открыть Prisma Studio
echo    npm run db:reset   - Сброс базы данных
echo.
echo 📚 Документация:
echo    README.md - Полное руководство по установке и запуску
echo.
echo Нажмите любую клавишу для выхода...
pause >nul