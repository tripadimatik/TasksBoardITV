# Bureau Task Manager

## Описание проекта

Bureau Task Manager - это современная система управления задачами с real-time обновлениями, разработанная для эффективного управления рабочими процессами в организации.

## Технологический стек

### Frontend
- **React 18** - основная библиотека для UI
- **TypeScript** - типизированный JavaScript
- **Vite** - сборщик и dev-сервер
- **Tailwind CSS** - CSS фреймворк для стилизации
- **Shadcn/ui** - компоненты UI
- **Socket.io-client** - WebSocket клиент для real-time обновлений
- **React Router** - маршрутизация
- **Lucide React** - иконки

### Backend
- **Node.js** - серверная среда выполнения
- **Express.js** - веб-фреймворк
- **Socket.io** - WebSocket сервер
- **Prisma** - ORM для работы с базой данных
- **PostgreSQL** - основная база данных
- **JWT** - аутентификация
- **Multer** - загрузка файлов
- **HTTPS** - безопасное соединение

## Системные требования

- **Node.js** версии 18 или выше
- **npm** или **yarn**
- **PostgreSQL** версии 12 или выше
- **Git**

## Установка и настройка

### 1. Клонирование репозитория

```bash
git clone <repository-url>
cd bureau-task-manager-main
```

### 2. Установка зависимостей

#### Frontend
```bash
npm install
```

#### Backend
```bash
cd server
npm install
cd ..
```

### 3. Настройка базы данных PostgreSQL

#### Установка PostgreSQL
1. Скачайте и установите PostgreSQL с официального сайта
2. Создайте новую базу данных:

```sql
CREATE DATABASE bureau_task_manager;
CREATE USER bureau_user WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE bureau_task_manager TO bureau_user;
```

### 4. Настройка переменных окружения

#### Frontend (.env)
Создайте файл `.env` в корневой папке проекта:

```env
VITE_API_URL=https://localhost:3002
VITE_WS_URL=https://localhost:3002
```

#### Backend (server/.env)
Создайте файл `server/.env`:

```env
# База данных
DATABASE_URL="postgresql://bureau_user:your_password@localhost:5432/bureau_task_manager?schema=public"

# JWT секрет
JWT_SECRET="your-super-secret-jwt-key-here"

# Порт сервера
PORT=3002

# HTTPS сертификаты (опционально)
HTTPS_KEY_PATH="./certs/key.pem"
HTTPS_CERT_PATH="./certs/cert.pem"

# Настройки CORS
CORS_ORIGIN="https://localhost:8080"

# Папка для загрузки файлов
UPLOADS_DIR="./uploads"
```

### 5. Генерация HTTPS сертификатов (для разработки)

```bash
# Windows
.\generate-certs.bat

# PowerShell
.\generate-certs.ps1

# Или вручную с OpenSSL
openssl req -x509 -newkey rsa:4096 -keyout server/certs/key.pem -out server/certs/cert.pem -days 365 -nodes
```

### 6. Инициализация базы данных

```bash
cd server
npx prisma generate
npx prisma db push
cd ..
```

### 7. Создание тестового пользователя (опционально)

```bash
cd server
node create-test-user.js
cd ..
```

## Запуск проекта

### Вариант 1: Автоматический запуск (рекомендуется)

```bash
# Windows
start-project.bat

# Или PowerShell
.\scripts\start-dev.ps1
```

### Вариант 2: Ручной запуск

#### Запуск backend сервера
```bash
cd server
npm start
```

#### Запуск frontend (в новом терминале)
```bash
npm run dev
```

### Доступ к приложению

- **Frontend**: https://localhost:8080
- **Backend API**: https://localhost:3002
- **WebSocket**: wss://localhost:3002

## Структура проекта

```
bureau-task-manager-main/
├── src/                    # Frontend исходный код
│   ├── components/         # React компоненты
│   │   ├── auth/          # Компоненты аутентификации
│   │   ├── dashboard/     # Компоненты дашборда
│   │   ├── tasks/         # Компоненты задач
│   │   └── ui/            # UI компоненты
│   ├── hooks/             # React хуки
│   ├── lib/               # Утилиты и API
│   ├── pages/             # Страницы приложения
│   └── utils/             # Вспомогательные функции
├── server/                # Backend исходный код
│   ├── prisma/           # Схема базы данных
│   ├── certs/            # HTTPS сертификаты
│   ├── uploads/          # Загруженные файлы
│   └── index.js          # Основной файл сервера
├── public/               # Статические файлы
└── scripts/              # Скрипты для запуска
```

## Основные функции

### Управление задачами
- ✅ Создание, редактирование и удаление задач
- ✅ Kanban доска с drag & drop
- ✅ Фильтрация и поиск задач
- ✅ Приоритеты и статусы задач
- ✅ Назначение исполнителей
- ✅ Загрузка файлов к задачам

### Real-time обновления
- ✅ WebSocket соединение
- ✅ Мгновенные обновления при изменении задач
- ✅ Уведомления о новых задачах
- ✅ Статус подключения пользователей

### Аутентификация и авторизация
- ✅ JWT токены
- ✅ Роли пользователей (USER, ADMIN, BOSS)
- ✅ Защищенные маршруты
- ✅ Управление профилем

### Дашборд и аналитика
- ✅ Статистика по задачам
- ✅ Графики и диаграммы
- ✅ Фильтрация по периодам
- ✅ Экспорт отчетов

## Роли пользователей

### USER (Пользователь)
- Просмотр назначенных задач
- Изменение статуса своих задач
- Загрузка файлов к задачам
- Просмотр статистики своих задач

### ADMIN (Администратор)
- Все права пользователя
- Создание и редактирование задач
- Назначение исполнителей
- Управление пользователями
- Просмотр всех задач

### BOSS (Руководитель)
- Все права администратора
- Полный доступ к аналитике
- Управление системными настройками
- Экспорт отчетов

## API Endpoints

### Аутентификация
- `POST /api/auth/login` - Вход в систему
- `POST /api/auth/register` - Регистрация
- `POST /api/auth/logout` - Выход из системы
- `GET /api/auth/me` - Получение текущего пользователя

### Задачи
- `GET /api/tasks` - Получение списка задач
- `POST /api/tasks` - Создание задачи
- `PUT /api/tasks/:id` - Обновление задачи
- `DELETE /api/tasks/:id` - Удаление задачи
- `POST /api/tasks/:id/upload` - Загрузка файла к задаче

### Пользователи
- `GET /api/users` - Получение списка пользователей
- `GET /api/users/status` - Статус пользователей онлайн

## WebSocket события

### Клиент → Сервер
- `join_room` - Присоединение к комнате
- `task_action` - Действие с задачей

### Сервер → Клиент
- `task_created` - Новая задача создана
- `task_updated` - Задача обновлена
- `task_deleted` - Задача удалена
- `users_status_updated` - Обновление статуса пользователей

## Отладка и разработка

### Логи
- Frontend: Консоль браузера
- Backend: Консоль сервера
- WebSocket: Отдельные логи соединений

### Тестирование WebSocket
Используйте файлы для тестирования:
- `websocket-test.html` - Базовое тестирование
- `websocket-debug.html` - Расширенная отладка
- `realtime-test.html` - Тестирование real-time обновлений

### Полезные команды

```bash
# Проверка пользователей в БД
node server/check-users.js

# Обновление паролей
node server/update-passwords.js

# Проверка ролей пользователей
node check-user-roles.js

# Сброс базы данных
cd server && npx prisma db push --force-reset
```

## Решение проблем

### Проблемы с сертификатами
1. Перегенерируйте сертификаты: `./generate-certs.bat`
2. Добавьте исключение в браузере для localhost
3. Проверьте пути к сертификатам в `.env`

### Проблемы с базой данных
1. Проверьте подключение к PostgreSQL
2. Убедитесь в правильности `DATABASE_URL`
3. Выполните `npx prisma db push`

### Проблемы с WebSocket
1. Проверьте, что сервер запущен на правильном порту
2. Убедитесь в правильности `VITE_WS_URL`
3. Проверьте настройки CORS

### Проблемы с аутентификацией
1. Проверьте `JWT_SECRET` в server/.env
2. Очистите localStorage браузера
3. Создайте нового тестового пользователя

## Контакты и поддержка

Для получения помощи или сообщения об ошибках создайте issue в репозитории проекта.

## Лицензия

Этот проект распространяется под лицензией MIT.