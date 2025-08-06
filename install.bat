@echo off
chcp 65001 >nul
echo ========================================
echo    Bureau Task Manager - Установка
echo ========================================
echo.

echo [1/6] Проверка Node.js...
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Node.js не найден! Установите Node.js с https://nodejs.org/
    pause
    exit /b 1
)
echo ✅ Node.js найден

echo [2/6] Установка зависимостей фронтенда...
npm install
if %errorlevel% neq 0 (
    echo ❌ Ошибка установки зависимостей фронтенда
    pause
    exit /b 1
)
echo ✅ Зависимости фронтенда установлены

echo [3/6] Установка зависимостей бэкенда...
cd server
npm install
if %errorlevel% neq 0 (
    echo ❌ Ошибка установки зависимостей бэкенда
    cd ..
    pause
    exit /b 1
)
cd ..
echo ✅ Зависимости бэкенда установлены

echo [4/6] Проверка файла .env...
if not exist ".env" (
    echo 📝 Создание .env файла из шаблона...
    copy ".env.example" ".env" >nul
    echo ⚠️  ВАЖНО: Отредактируйте .env файл с вашими настройками базы данных!
    echo    DATABASE_URL="postgresql://username:password@localhost:5432/task_manager"
) else (
    echo ✅ Файл .env уже существует
)

echo [5/6] Инициализация базы данных...
cd server
echo Генерация Prisma клиента...
npx prisma generate
if %errorlevel% neq 0 (
    echo ❌ Ошибка генерации Prisma клиента
    cd ..
    pause
    exit /b 1
)

echo Применение схемы базы данных...
npx prisma db push
if %errorlevel% neq 0 (
    echo ❌ Ошибка применения схемы базы данных
    echo    Убедитесь, что PostgreSQL запущен и настройки в .env корректны
    cd ..
    pause
    exit /b 1
)
cd ..
echo ✅ База данных инициализирована

echo [6/6] Создание скрипта запуска...
echo @echo off > start.bat
echo chcp 65001 ^>nul >> start.bat
echo echo Запуск Bureau Task Manager... >> start.bat
echo echo. >> start.bat
echo echo Запуск бэкенда... >> start.bat
echo start "Backend Server" cmd /k "cd server ^&^& npm start" >> start.bat
echo timeout /t 3 /nobreak ^>nul >> start.bat
echo echo Запуск фронтенда... >> start.bat
echo start "Frontend Dev Server" cmd /k "npm run dev" >> start.bat
echo echo. >> start.bat
echo echo ✅ Серверы запущены! >> start.bat
echo echo 🌐 Фронтенд: http://localhost:5173 >> start.bat
echo echo 🔧 API: http://localhost:3001/api >> start.bat
echo pause >> start.bat

echo.
echo ========================================
echo ✅ Установка завершена успешно!
echo ========================================
echo.
echo 🚀 Для запуска проекта:
echo    1. Убедитесь, что PostgreSQL запущен
echo    2. Проверьте настройки в .env файле
echo    3. Запустите: start.bat
echo.
echo 🌐 После запуска откройте: http://localhost:5173
echo.
pause