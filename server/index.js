const express = require('express');
const https = require('https');
const http = require('http');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { Server } = require('socket.io');
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const mongoSanitize = require('express-mongo-sanitize');
const hpp = require('hpp');
const xss = require('xss');
const validator = require('validator');

// Импорт модулей безопасности
const securityConfig = require('./security/security-config');
const securityMiddleware = require('./security/security-middleware');
const cryptoUtils = require('./security/crypto-utils');
const validators = require('./security/validators');

require('dotenv').config();

const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

const app = express();
const PORT = process.env.PORT || 3001;

// Безопасный WebSocket для real-time уведомлений
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: function(origin, callback) {
      // Используем нашу функцию валидации CORS
      if (securityConfig.validateCORSOrigin && securityConfig.validateCORSOrigin(origin)) {
        callback(null, true);
      } else {
        // Fallback к старой логике если функция не доступна
        if (!origin) {
          return callback(null, true);
        }
        
        if (origin.includes('localhost') || origin.includes('127.0.0.1')) {
          return callback(null, true);
        }
        
        if (origin.match(/^https?:\/\/(192\.168\.|10\.)/)) {
          return callback(null, true);
        }
        
        if (process.env.FRONTEND_URL && origin === process.env.FRONTEND_URL) {
          return callback(null, true);
        }
        
        callback(null, true); // Разрешаем все для разработки
      }
    },
    methods: ['GET', 'POST'],
    credentials: true
  },
  // Дополнительные настройки безопасности
  allowEIO3: false, // Отключаем старые версии Engine.IO
  transports: ['websocket', 'polling'],
  pingTimeout: 60000,
  pingInterval: 25000
});

// Хранилище активных соединений пользователей с дополнительной информацией
const userSockets = new Map(); // userId -> Set of socket ids
const connectionAttempts = new Map(); // Для отслеживания попыток подключения

// Middleware для WebSocket аутентификации
io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth.token || socket.handshake.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
      return next(new Error('Токен не предоставлен'));
    }
    
    // Проверяем токен с помощью нашей безопасной функции
    const decoded = cryptoUtils.verifyJWT ? cryptoUtils.verifyJWT(token) : 
      { isValid: true, payload: jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key') };
    
    if (!decoded.isValid) {
      return next(new Error('Неверный токен'));
    }
    
    socket.userId = decoded.payload.userId;
    socket.userEmail = decoded.payload.email;
    socket.userRole = decoded.payload.role;
    
    // Проверяем лимит подключений для пользователя
    const userConnections = userSockets.get(decoded.payload.userId)?.size || 0;
    
    if (userConnections >= 3) { // Максимум 3 соединения на пользователя
      return next(new Error('Превышен лимит подключений'));
    }
    
    next();
  } catch (error) {
    console.error('❌ Ошибка WebSocket middleware:', error);
    next(new Error('Ошибка аутентификации'));
  }
});

// Socket.io обработчики
io.on('connection', (socket) => {
  const clientIP = socket.handshake.address;
  console.log(`🔌 Новое WebSocket соединение: ${socket.id} от ${clientIP}`);
  
  // Проверяем количество попыток подключения с этого IP
  const attempts = connectionAttempts.get(clientIP) || 0;
  if (attempts > 10) { // Максимум 10 попыток в час
    console.log(`🚫 Заблокировано подключение с IP ${clientIP} (слишком много попыток)`);
    socket.disconnect();
    return;
  }
  connectionAttempts.set(clientIP, attempts + 1);
  
  // Добавляем сокет в карту пользователей
  if (!userSockets.has(socket.userId)) {
    userSockets.set(socket.userId, new Set());
  }
  userSockets.get(socket.userId).add(socket.id);
  
  console.log(`✅ Пользователь ${socket.userId} аутентифицирован через WebSocket`);
  socket.emit('authenticated', { success: true });
  
  // Отправляем всем клиентам обновленный список онлайн пользователей
  broadcastOnlineUsers();
  
  // Аутентификация пользователя через WebSocket (для обратной совместимости)
  socket.on('authenticate', (token) => {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
      socket.userId = decoded.userId;
      
      // Добавляем сокет в карту пользователей
      if (!userSockets.has(decoded.userId)) {
        userSockets.set(decoded.userId, new Set());
      }
      userSockets.get(decoded.userId).add(socket.id);
      
      console.log(`✅ Пользователь ${decoded.userId} аутентифицирован через WebSocket`);
      socket.emit('authenticated', { success: true });
      
      // Отправляем всем клиентам обновленный список онлайн пользователей
      broadcastOnlineUsers();
    } catch (error) {
      console.error('❌ Ошибка аутентификации WebSocket:', error);
      socket.emit('authentication_error', { error: 'Неверный токен' });
    }
  });
  
  // Обработка ping для поддержания соединения
  socket.on('ping', () => {
    console.log('🏓 Получен ping от клиента:', socket.id);
    socket.emit('pong');
  });
  
  // Обработка отключения
  socket.on('disconnect', (reason) => {
    console.log(`🔌 WebSocket соединение закрыто: ${socket.id} (причина: ${reason})`);
    
    // Удаляем сокет из карты пользователей
    if (socket.userId && userSockets.has(socket.userId)) {
      userSockets.get(socket.userId).delete(socket.id);
      if (userSockets.get(socket.userId).size === 0) {
        userSockets.delete(socket.userId);
      }
      
      // Отправляем всем клиентам обновленный список онлайн пользователей
      broadcastOnlineUsers();
    }
  });
  
  // Обработка ошибок
  socket.on('error', (error) => {
    console.error(`❌ WebSocket ошибка для ${socket.userEmail || socket.userId}:`, error);
    if (securityConfig.logSuspiciousActivity) {
      securityConfig.logSuspiciousActivity(
        { ip: clientIP, headers: socket.handshake.headers },
        'WEBSOCKET_ERROR',
        { error: error.message, userId: socket.userId }
      );
    }
  });
});

// Очистка старых попыток подключения каждый час
setInterval(() => {
  connectionAttempts.clear();
  console.log('🧹 Очищены счетчики попыток подключения');
}, 60 * 60 * 1000);

// Функция для отправки всем клиентам списка пользователей онлайн
const broadcastOnlineUsers = async () => {
  try {
    // Получаем список всех пользователей из базы данных
    const allUsers = await prisma.user.findMany({
      select: {
        id: true,
        firstName: true,
        lastName: true,
        patronymic: true,
        role: true
      }
    });
    
    // Формируем список пользователей с их онлайн-статусом
    const usersWithStatus = allUsers.map(user => ({
      ...user,
      isOnline: userSockets.has(user.id)
    }));
    
    // Отправляем список всем подключенным клиентам
    io.emit('users_status_updated', usersWithStatus);
    
    console.log('📡 Отправлен обновленный список пользователей онлайн:', 
      usersWithStatus.filter(u => u.isOnline).length, 'из', usersWithStatus.length);
  } catch (error) {
    console.error('❌ Ошибка при отправке статусов пользователей:', error);
  }
};

// Функция для отправки обновлений всем пользователям
const notifyAll = (event, data) => {
  console.log(`📡 WebSocket broadcast: ${event} to ${io.engine.clientsCount} clients`);
  io.emit(event, data);
};

const notifyUser = (userId, event, data) => {
  const userSocketIds = userSockets.get(userId);
  if (userSocketIds && userSocketIds.size > 0) {
    console.log(`📡 WebSocket notify user ${userId}: ${event} to ${userSocketIds.size} sockets`);
    userSocketIds.forEach(socketId => {
      const socket = io.sockets.sockets.get(socketId);
      if (socket) {
        socket.emit(event, data);
      }
    });
  } else {
    console.log(`⚠️ User ${userId} not found in active sockets for event: ${event}`);
  }
};

// Применяем основные middleware безопасности
app.use(securityMiddleware.setupHelmet());
app.use(securityMiddleware.setupCORS());
app.use(securityConfig.apiRateLimit);
app.use(securityConfig.speedLimiter);
app.use(securityConfig.noSQLSanitize);
app.use(securityConfig.hppProtection);
app.use(securityMiddleware.securityLogger);
app.use(securityMiddleware.validateAndSanitize);

// Настройка CORS (дополнительная)
const corsOptions = {
  origin: function (origin, callback) {
    console.log('🌐 CORS запрос от origin:', origin);
    
    // Разрешаем запросы без origin (например, мобильные приложения)
    if (!origin) {
      console.log('✅ Разрешен запрос без origin');
      return callback(null, true);
    }
    
    // Разрешаем localhost и 127.0.0.1
    if (origin.includes('localhost') || origin.includes('127.0.0.1')) {
      console.log('✅ Разрешен localhost/127.0.0.1');
      return callback(null, true);
    }
    
    // Разрешаем IP-адреса локальной сети
    if (origin.match(/^https?:\/\/(192\.168\.|10\.)/)) {
      console.log('✅ Разрешен IP локальной сети');
      return callback(null, true);
    }
    
    // Разрешаем указанный в переменной окружения URL
    if (process.env.FRONTEND_URL && origin === process.env.FRONTEND_URL) {
      console.log('✅ Разрешен FRONTEND_URL');
      return callback(null, true);
    }
    
    console.log('❌ CORS запрещен для origin:', origin);
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Middleware для правильной обработки кодировки файлов
app.use((req, res, next) => {
  // Устанавливаем правильную кодировку для обработки имен файлов
  if (req.headers['content-type'] && req.headers['content-type'].includes('multipart/form-data')) {
    // Для multipart/form-data запросов устанавливаем UTF-8 кодировку
    req.setEncoding = req.setEncoding || (() => {});
  }
  next();
});

// Дополнительные заголовки безопасности
app.use((req, res, next) => {
  // Защита от clickjacking
  res.setHeader('X-Frame-Options', 'DENY');
  
  // Защита от MIME-type sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');
  
  // Включаем XSS защиту браузера
  res.setHeader('X-XSS-Protection', '1; mode=block');
  
  // Строгая транспортная безопасность (для HTTPS)
  if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  }
  
  // Политика содержимого (CSP)
  res.setHeader('Content-Security-Policy', 
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
    "style-src 'self' 'unsafe-inline'; " +
    "img-src 'self' data: blob:; " +
    "font-src 'self'; " +
    "connect-src 'self' ws: wss:; " +
    "frame-ancestors 'none';"
  );
  
  // Политика разрешений
  res.setHeader('Permissions-Policy', 
    'geolocation=(), microphone=(), camera=(), payment=(), usb=()'
  );
  
  // Удаляем заголовки, раскрывающие информацию о сервере
  res.removeHeader('X-Powered-By');
  res.removeHeader('Server');
  
  next();
});

// Middleware для логирования запросов с дополнительной безопасностью
app.use((req, res, next) => {
  const suspiciousPatterns = [
    /\.\.[\/\\]/,  // Directory traversal
    /<script/i,      // XSS attempts
    /union.*select/i, // SQL injection
    /javascript:/i,   // JavaScript protocol
    /vbscript:/i,     // VBScript protocol
    /data:text\/html/i // Data URI XSS
  ];
  
  const requestData = {
    method: req.method,
    path: req.path,
    origin: req.get('Origin'),
    userAgent: req.get('User-Agent'),
    ip: req.ip,
    timestamp: new Date().toISOString()
  };
  
  // Проверяем на подозрительные паттерны
  const fullUrl = req.originalUrl || req.url;
  const isSuspicious = suspiciousPatterns.some(pattern => 
    pattern.test(fullUrl) || 
    (req.body && typeof req.body === 'object' && 
     JSON.stringify(req.body).match(pattern))
  );
  
  if (isSuspicious) {
    console.log('🚨 ПОДОЗРИТЕЛЬНЫЙ ЗАПРОС:', requestData);
    if (securityConfig.logSuspiciousActivity) {
      securityConfig.logSuspiciousActivity(req, 'SUSPICIOUS_REQUEST', {
        url: fullUrl,
        body: req.body
      });
    }
  } else {
    console.log(`📨 ${req.method} ${req.path}`, {
      origin: req.get('Origin'),
      userAgent: req.get('User-Agent')?.substring(0, 50),
      ip: req.ip
    });
  }
  
  next();
});

// Создаем папку для загрузки файлов с правильными разрешениями
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true, mode: 0o755 });
  console.log('📁 Создана папка uploads с безопасными разрешениями');
}

// Проверяем и устанавливаем безопасные разрешения для папки uploads
try {
  fs.chmodSync(uploadsDir, 0o755); // rwxr-xr-x
  console.log('🔒 Установлены безопасные разрешения для папки uploads');
} catch (error) {
  console.warn('⚠️ Не удалось установить разрешения для папки uploads:', error.message);
}

// Middleware для защиты от атак перебора
const bruteForceProtection = new Map();
const BRUTE_FORCE_WINDOW = 15 * 60 * 1000; // 15 минут
const MAX_ATTEMPTS = 5;

const checkBruteForce = (req, res, next) => {
  const key = req.ip + ':' + req.path;
  const now = Date.now();
  
  if (!bruteForceProtection.has(key)) {
    bruteForceProtection.set(key, { attempts: 0, lastAttempt: now });
  }
  
  const record = bruteForceProtection.get(key);
  
  // Сбрасываем счетчик если прошло достаточно времени
  if (now - record.lastAttempt > BRUTE_FORCE_WINDOW) {
    record.attempts = 0;
  }
  
  if (record.attempts >= MAX_ATTEMPTS) {
    console.log(`🚫 Заблокирован IP ${req.ip} за превышение лимита попыток на ${req.path}`);
    if (securityConfig.logSuspiciousActivity) {
      securityConfig.logSuspiciousActivity(req, 'BRUTE_FORCE_ATTEMPT', {
        attempts: record.attempts,
        path: req.path
      });
    }
    return res.status(429).json({ 
      error: 'Слишком много попыток. Попробуйте позже.',
      retryAfter: Math.ceil(BRUTE_FORCE_WINDOW / 1000)
    });
  }
  
  next();
};

// Очистка старых записей защиты от перебора каждые 30 минут
setInterval(() => {
  const now = Date.now();
  for (const [key, record] of bruteForceProtection.entries()) {
    if (now - record.lastAttempt > BRUTE_FORCE_WINDOW * 2) {
      bruteForceProtection.delete(key);
    }
  }
  console.log('🧹 Очищены старые записи защиты от перебора');
}, 30 * 60 * 1000);

// Безопасная настройка multer для загрузки файлов
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    // Генерируем безопасное имя файла
    const safeFileName = cryptoUtils.generateSecureToken(16);
    const fileExtension = path.extname(file.originalname).toLowerCase();
    
    // Проверяем расширение файла
    const allowedExtensions = [
      '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg', '.tiff', '.ico',
      '.pdf', '.doc', '.docx', '.txt', '.rtf', '.odt',
      '.xls', '.xlsx', '.ods', '.csv',
      '.ppt', '.pptx', '.odp',
      '.zip', '.rar', '.7z', '.tar', '.gz'
    ];
    if (!allowedExtensions.includes(fileExtension)) {
      return cb(new Error('Недопустимый тип файла'));
    }
    
    cb(null, safeFileName + fileExtension);
  }
});

// Фильтр файлов для дополнительной безопасности
const fileFilter = (req, file, cb) => {
  // Проверяем MIME-тип
  const allowedMimeTypes = [
    // Изображения
    'image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/bmp', 
    'image/webp', 'image/svg+xml', 'image/tiff', 'image/x-icon',
    // Документы
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'text/plain', 'text/rtf',
    'application/vnd.oasis.opendocument.text',
    // Таблицы
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.oasis.opendocument.spreadsheet',
    'text/csv',
    // Презентации
    'application/vnd.ms-powerpoint',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'application/vnd.oasis.opendocument.presentation',
    // Архивы
    'application/zip', 'application/x-rar-compressed', 'application/x-7z-compressed',
    'application/x-tar', 'application/gzip'
  ];
  
  // Проверяем расширение файла для дополнительной безопасности
  const fileExtension = path.extname(file.originalname).toLowerCase();
  const allowedExtensions = [
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg', '.tiff', '.ico',
    '.pdf', '.doc', '.docx', '.txt', '.rtf', '.odt',
    '.xls', '.xlsx', '.ods', '.csv',
    '.ppt', '.pptx', '.odp',
    '.zip', '.rar', '.7z', '.tar', '.gz'
  ];
  
  if (allowedMimeTypes.includes(file.mimetype) || allowedExtensions.includes(fileExtension)) {
    cb(null, true);
  } else {
    cb(new Error('Недопустимый MIME-тип файла'), false);
  }
};

const upload = multer({ 
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB для соответствия клиентской части
    files: 1, // Только один файл за раз
    fieldSize: 1024 * 1024 // 1MB для полей формы
  }
});

// Middleware для аутентификации (заменен на улучшенную версию)
const authenticateToken = securityMiddleware.authenticateToken;

// Middleware для проверки ролей
const requireRole = securityMiddleware.requireRole;

// Безопасная раздача статических файлов
app.use('/uploads', 
  securityConfig.apiRateLimit, // Ограничение частоты запросов
  (req, res, next) => {
    // Проверяем расширение файла
    const allowedExtensions = [
      '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg', '.tiff', '.ico',
      '.pdf', '.doc', '.docx', '.txt', '.rtf', '.odt',
      '.xls', '.xlsx', '.ods', '.csv',
      '.ppt', '.pptx', '.odp',
      '.zip', '.rar', '.7z', '.tar', '.gz'
    ];
    const fileExtension = path.extname(req.path).toLowerCase();
    
    if (!allowedExtensions.includes(fileExtension)) {
      console.log(`🚫 Заблокирован доступ к файлу с недопустимым расширением: ${req.path}`);
      return res.status(403).json({ error: 'Тип файла не разрешен' });
    }
    
    // Предотвращаем directory traversal атаки
    const safePath = path.normalize(req.path).replace(/^(\.\.[\/\\])+/, '');
    req.url = safePath;
    
    // Добавляем заголовки безопасности для файлов
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Disposition', 'inline');
    
    // Логируем доступ к файлам
    console.log(`📁 Доступ к файлу: ${req.path} от IP: ${req.ip}`);
    
    next();
  },
  express.static(uploadsDir, {
    dotfiles: 'deny', // Запрещаем доступ к скрытым файлам
    index: false, // Отключаем листинг директорий
    maxAge: '1d', // Кеширование на 1 день
    setHeaders: (res, path) => {
      // Дополнительные заголовки безопасности
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('X-Frame-Options', 'DENY');
    }
  })
);

// === AUTH ROUTES ===

// Регистрация с улучшенной безопасностью
app.post('/api/auth/register', 
  checkBruteForce,
  securityConfig.authRateLimit,
  securityMiddleware.validateRegistration,
  async (req, res) => {
    console.log('📝 Запрос на регистрацию получен');
    try {
      const { email, password, firstName, lastName, patronymic, role = 'USER' } = req.body;
      console.log('📝 Данные регистрации:', { email, firstName, lastName, role });
      
      // Дополнительная валидация
      const emailValidation = validators.user.email(email);
      if (!emailValidation.isValid) {
        return res.status(400).json({ error: emailValidation.error });
      }

      const passwordValidation = validators.user.password(password);
      if (!passwordValidation.isValid) {
        return res.status(400).json({ error: passwordValidation.error });
      }

      const nameValidation = validators.user.name(firstName);
      if (!nameValidation.isValid) {
        return res.status(400).json({ error: nameValidation.error });
      }
      
      // Проверяем, существует ли пользователь
      const existingUser = await prisma.user.findUnique({ where: { email: email.toLowerCase() } });
      if (existingUser) {
        console.log('❌ Пользователь уже существует:', email);
        
        // Увеличиваем счетчик попыток для защиты от перебора
        const key = req.ip + ':' + req.path;
        const record = bruteForceProtection.get(key);
        if (record) {
          record.attempts++;
          record.lastAttempt = Date.now();
        }
        
        securityConfig.logSuspiciousActivity(req, 'DUPLICATE_REGISTRATION_ATTEMPT', { email });
        return res.status(400).json({ error: 'Пользователь с таким email уже существует' });
      }
      
      // Безопасное хеширование пароля
      const passwordHash = await cryptoUtils.hashPassword(password);
      
      // Создаем пользователя
      const user = await prisma.user.create({
        data: {
          email: email.toLowerCase(),
          passwordHash,
          firstName: firstName ? firstName.trim() : '',
          lastName: lastName ? lastName.trim() : '',
          patronymic: patronymic ? patronymic.trim() : '',
          role: role.toUpperCase()
        }
      });
      
      console.log('✅ Пользователь создан:', user.id);
      
      // Создаем безопасный JWT токен
      const token = cryptoUtils.generateJWT({
        id: user.id,
        userId: user.id, 
        email: user.email, 
        role: user.role 
      });
      
      console.log('✅ JWT токен создан');
      
      res.json({ 
        token, 
        user: { 
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          patronymic: user.patronymic,
          role: user.role
        } 
      });
    } catch (error) {
      console.error('❌ Ошибка регистрации:', error);
      securityConfig.logSuspiciousActivity(req, 'REGISTRATION_ERROR', { error: error.message });
      res.status(500).json({ error: 'Ошибка при регистрации' });
    }
  }
);

// Вход в систему с улучшенной безопасностью
app.post('/api/auth/login', 
  checkBruteForce,
  securityConfig.authRateLimit,
  securityMiddleware.validateLogin,
  async (req, res) => {
    console.log('🔐 Запрос на вход получен');
    try {
      const { email, password } = req.body;
      console.log('🔐 Попытка входа для:', email);
      
      // Дополнительная валидация
      const emailValidation = validators.user.email(email);
      if (!emailValidation.isValid) {
        securityConfig.logSuspiciousActivity(req, 'INVALID_LOGIN_EMAIL', { email });
        return res.status(400).json({ error: 'Неверный формат email' });
      }
      
      // Находим пользователя
      const user = await prisma.user.findUnique({ where: { email: email.toLowerCase() } });
      if (!user) {
        console.log('❌ Пользователь не найден:', email);
        
        // Увеличиваем счетчик попыток для защиты от перебора
        const key = req.ip + ':' + req.path;
        const record = bruteForceProtection.get(key);
        if (record) {
          record.attempts++;
          record.lastAttempt = Date.now();
        }
        
        securityConfig.logSuspiciousActivity(req, 'LOGIN_USER_NOT_FOUND', { email });
        return res.status(401).json({ error: 'Неверные учетные данные' });
      }
      
      console.log('✅ Пользователь найден:', user.id);
      
      // Безопасная проверка пароля
      const isValidPassword = await cryptoUtils.verifyPassword(password, user.passwordHash);
      if (!isValidPassword) {
        console.log('❌ Неверный пароль для:', email);
        
        // Увеличиваем счетчик попыток для защиты от перебора
        const key = req.ip + ':' + req.path;
        const record = bruteForceProtection.get(key);
        if (record) {
          record.attempts++;
          record.lastAttempt = Date.now();
        }
        
        securityConfig.logSuspiciousActivity(req, 'LOGIN_INVALID_PASSWORD', { email, userId: user.id });
        return res.status(401).json({ error: 'Неверные учетные данные' });
      }
      
      console.log('✅ Пароль верный');
      
      // Создаем безопасный токен
      const token = cryptoUtils.generateJWT({
        id: user.id,
        userId: user.id, 
        email: user.email, 
        role: user.role 
      });
      
      console.log('✅ JWT токен создан для входа');
      
      res.json({ 
        token, 
        user: { 
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          patronymic: user.patronymic,
          role: user.role
        } 
      });
    } catch (error) {
      console.error('❌ Ошибка входа:', error);
      securityConfig.logSuspiciousActivity(req, 'LOGIN_ERROR', { error: error.message });
      res.status(500).json({ error: 'Ошибка при входе' });
    }
  }
);

// Получение текущего пользователя
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.userId },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        patronymic: true,
        role: true,
        createdAt: true,
        updatedAt: true
      }
    });
    
    if (!user) {
      return res.status(404).json({ error: 'Пользователь не найден' });
    }
    
    res.json(user);
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Ошибка при получении данных пользователя' });
  }
});

// === USER ROUTES ===

// Обновить пользователя
app.put('/api/users/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { role, firstName, lastName, patronymic } = req.body;
    
    // Проверяем права доступа
    const currentUser = await prisma.user.findUnique({
      where: { id: req.userId }
    });
    
    if (!currentUser || (currentUser.role !== 'ADMIN' && currentUser.role !== 'BOSS')) {
      return res.status(403).json({ error: 'Недостаточно прав для обновления пользователя' });
    }
    
    const updatedUser = await prisma.user.update({
      where: { id },
      data: {
        ...(role && { role }),
        ...(firstName && { firstName }),
        ...(lastName && { lastName }),
        ...(patronymic !== undefined && { patronymic })
      }
    });
    
    const { password: _, ...userWithoutPassword } = updatedUser;
    res.json(userWithoutPassword);
  } catch (error) {
    console.error('Update user error:', error);
    res.status(500).json({ error: 'Ошибка при обновлении пользователя' });
  }
});

// Получить всех пользователей с пагинацией и фильтрацией
app.get('/api/users', 
  securityConfig.apiRateLimit,
  securityMiddleware.authenticateToken,
  requireRole(['ADMIN', 'BOSS']),
  async (req, res) => {
    try {
      const { role, page = 1, limit = 50, search } = req.query;
      
      // Валидация параметров запроса
      const pageNum = parseInt(page);
      const limitNum = parseInt(limit);
      
      if (isNaN(pageNum) || pageNum < 1) {
        return res.status(400).json({ error: 'Неверный номер страницы' });
      }
      
      if (isNaN(limitNum) || limitNum < 1 || limitNum > 100) {
        return res.status(400).json({ error: 'Неверный лимит (1-100)' });
      }
      
      // Построение фильтров
      const where = {};
      
      if (role) {
        if (!['USER', 'ADMIN', 'BOSS'].includes(role.toUpperCase())) {
          return res.status(400).json({ error: 'Неверная роль' });
        }
        where.role = role.toUpperCase();
      }
      
      if (search) {
        const searchTerm = search.trim();
        if (searchTerm.length > 0) {
          where.OR = [
            { firstName: { contains: searchTerm, mode: 'insensitive' } },
            { lastName: { contains: searchTerm, mode: 'insensitive' } },
            { email: { contains: searchTerm, mode: 'insensitive' } }
          ];
        }
      }
      
      const skip = (pageNum - 1) * limitNum;
      
      const [users, total] = await Promise.all([
        prisma.user.findMany({
          where,
          select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
            patronymic: true,
            role: true,
            createdAt: true
          },
          orderBy: { createdAt: 'desc' },
          skip,
          take: limitNum
        }),
        prisma.user.count({ where })
      ]);
      
      res.json({
        users,
        pagination: {
          page: pageNum,
          limit: limitNum,
          total,
          pages: Math.ceil(total / limitNum)
        }
      });
    } catch (error) {
      console.error('Get users error:', error);
      securityConfig.logSuspiciousActivity(req, 'USERS_FETCH_ERROR', { error: error.message });
      res.status(500).json({ error: 'Ошибка при получении пользователей' });
    }
  }
);

// Получить статус пользователей (онлайн/оффлайн)
app.get('/api/users/status', authenticateToken, async (req, res) => {
  try {
    const users = await prisma.user.findMany({
      select: {
        id: true,
        firstName: true,
        lastName: true,
        patronymic: true,
        role: true
      }
    });
    
    // Добавляем информацию об онлайн-статусе
    const usersWithStatus = users.map(user => ({
      ...user,
      isOnline: userSockets.has(user.id)
    }));
    
    res.json(usersWithStatus);
  } catch (error) {
    console.error('Get users status error:', error);
    res.status(500).json({ error: 'Ошибка при получении статуса пользователей' });
  }
});

// === TASK ROUTES ===

// Получение задач с пагинацией и фильтрацией
app.get('/api/tasks', 
  securityConfig.apiRateLimit,
  securityMiddleware.authenticateToken, 
  async (req, res) => {
    try {
      const { role, userId } = req.user;
      const { page = 1, limit = 50, status, priority, assigneeId, includeArchived } = req.query;
      console.log('GET /api/tasks - User:', { role, userId, includeArchived });
      
      // Валидация параметров запроса
      const pageNum = parseInt(page);
      const limitNum = parseInt(limit);
      
      if (isNaN(pageNum) || pageNum < 1) {
        return res.status(400).json({ error: 'Неверный номер страницы' });
      }
      
      if (isNaN(limitNum) || limitNum < 1 || limitNum > 100) {
        return res.status(400).json({ error: 'Неверный лимит (1-100)' });
      }
      
      // Построение фильтров
      let where = {};
      
      // Если пользователь не boss или admin, показываем только его задачи
      if (role !== 'BOSS' && role !== 'ADMIN') {
        where.assigneeId = userId;
      }
      
      // По умолчанию исключаем архивированные задачи, если не указано обратное
      if (includeArchived !== 'true') {
        where.archived = { not: true };
      }
      
      if (status) {
        const statusValidation = validators.task.status(status);
        if (!statusValidation.isValid) {
          return res.status(400).json({ error: statusValidation.error });
        }
        where.status = status.toUpperCase();
      }
      
      if (priority) {
        const priorityValidation = validators.task.priority(priority);
        if (!priorityValidation.isValid) {
          return res.status(400).json({ error: priorityValidation.error });
        }
        where.priority = priority.toUpperCase();
      }
      
      if (assigneeId && (role === 'BOSS' || role === 'ADMIN')) {
        const assigneeValidation = await validators.task.assigneeId(assigneeId);
        if (!assigneeValidation.isValid) {
          return res.status(400).json({ error: assigneeValidation.error });
        }
        where.assigneeId = assigneeId;
      }
      
      console.log('Query where condition:', where);
      
      const skip = (pageNum - 1) * limitNum;
      
      const [tasks, total] = await Promise.all([
        prisma.task.findMany({
          where,
          include: {
            assignee: {
              select: {
                id: true,
                email: true,
                firstName: true,
                lastName: true,
                patronymic: true
              }
            },
            creator: {
              select: {
                id: true,
                email: true,
                firstName: true,
                lastName: true
              }
            }
          },
          orderBy: { createdAt: 'desc' },
          skip,
          take: limitNum
        }),
        prisma.task.count({ where })
      ]);
      
      console.log('Found tasks:', tasks.length, 'of', total);
      
      // Преобразуем статусы и приоритеты в русский язык для фронтенда
      const tasksWithRussianLabels = tasks.map(task => ({
        ...task,
        status: mapStatusToRussian(task.status),
        priority: mapPriorityToRussian(task.priority)
      }));
      
      res.json({
        tasks: tasksWithRussianLabels,
        pagination: {
          page: pageNum,
          limit: limitNum,
          total,
          pages: Math.ceil(total / limitNum)
        }
      });
    } catch (error) {
      console.error('Get tasks error:', error);
      securityConfig.logSuspiciousActivity(req, 'TASKS_FETCH_ERROR', { error: error.message });
      res.status(500).json({ error: 'Ошибка при получении задач' });
    }
  }
);

// Создание задачи с валидацией
app.post('/api/tasks', 
  securityConfig.authRateLimit,
  securityMiddleware.authenticateToken, 
  async (req, res) => {
    try {
      const { title, description, priority, deadline, assigneeId, assigneeName } = req.body;
      
      // Валидация данных задачи
      const titleValidation = validators.task.title(title);
      if (!titleValidation.isValid) {
        return res.status(400).json({ error: titleValidation.error });
      }

      const descriptionValidation = validators.task.description(description);
      if (!descriptionValidation.isValid) {
        return res.status(400).json({ error: descriptionValidation.error });
      }

      const priorityValidation = validators.task.priority(priority);
      if (!priorityValidation.isValid) {
        return res.status(400).json({ error: priorityValidation.error });
      }

      if (deadline) {
        const deadlineValidation = validators.task.deadlineForCreate(deadline);
        if (!deadlineValidation.isValid) {
          return res.status(400).json({ error: deadlineValidation.error });
        }
      }

      if (assigneeId) {
        const assigneeValidation = await validators.task.assigneeId(assigneeId);
        if (!assigneeValidation.isValid) {
          return res.status(400).json({ error: assigneeValidation.error });
        }
      }
      
      const task = await prisma.task.create({
        data: {
          title: title.trim(),
          description: description ? description.trim() : '',
          priority: priority?.toUpperCase() || 'MEDIUM',
          deadline: deadline ? new Date(deadline) : null,
          status: 'ASSIGNED',
          assigneeId,
          assigneeName: assigneeName ? assigneeName.trim() : '',
          createdBy: req.user.userId
        },
        include: {
          assignee: {
            select: {
              id: true,
              email: true,
              firstName: true,
              lastName: true,
              patronymic: true
            }
          }
        }
      });
      
      // Преобразуем статусы и приоритеты в русский язык для фронтенда
      const taskWithRussianLabels = {
        ...task,
        status: mapStatusToRussian(task.status),
        priority: mapPriorityToRussian(task.priority)
      };
      
      // Отправляем real-time уведомление всем пользователям о новой задаче
      notifyAll('task_created', taskWithRussianLabels);
      
      res.json(taskWithRussianLabels);
    } catch (error) {
      console.error('Create task error:', error);
      securityConfig.logSuspiciousActivity(req, 'TASK_CREATION_ERROR', { error: error.message });
      res.status(500).json({ error: 'Ошибка при создании задачи' });
    }
  }
);

// Обновление задачи с валидацией
app.put('/api/tasks/:id', 
  securityConfig.authRateLimit,
  securityMiddleware.authenticateToken, 
  async (req, res) => {
    try {
      const { id } = req.params;
      const updates = req.body;
      
      // Валидация ID задачи
      if (!id || typeof id !== 'string' || id.trim().length === 0) {
        return res.status(400).json({ error: 'ID задачи обязателен' });
      }
      
      // Валидация обновляемых полей
      if (updates.title) {
        const titleValidation = validators.task.title(updates.title);
        if (!titleValidation.isValid) {
          return res.status(400).json({ error: titleValidation.error });
        }
        updates.title = updates.title.trim();
      }
      
      if (updates.description !== undefined) {
        const descriptionValidation = validators.task.description(updates.description);
        if (!descriptionValidation.isValid) {
          return res.status(400).json({ error: descriptionValidation.error });
        }
        updates.description = updates.description ? updates.description.trim() : '';
      }
      
      if (updates.priority) {
        const priorityValidation = validators.task.priority(updates.priority);
        if (!priorityValidation.isValid) {
          return res.status(400).json({ error: priorityValidation.error });
        }
      }
      
      if (updates.status) {
        const statusValidation = validators.task.status(updates.status);
        if (!statusValidation.isValid) {
          return res.status(400).json({ error: statusValidation.error });
        }
      }
      
      if (updates.deadline) {
        const deadlineValidation = validators.task.deadline(updates.deadline);
        if (!deadlineValidation.isValid) {
          return res.status(400).json({ error: deadlineValidation.error });
        }
      }
      
      if (updates.assigneeId) {
        const assigneeValidation = await validators.task.assigneeId(updates.assigneeId);
        if (!assigneeValidation.isValid) {
          return res.status(400).json({ error: assigneeValidation.error });
        }
      }
      
      // Преобразуем статус и приоритет в верхний регистр если они есть
      if (updates.status) {
        updates.status = updates.status.toUpperCase();
      }
      if (updates.priority) {
        updates.priority = updates.priority.toUpperCase();
      }
      if (updates.deadline) {
        updates.deadline = new Date(updates.deadline);
      }
      if (updates.assigneeName) {
        updates.assigneeName = updates.assigneeName.trim();
      }
      
      const task = await prisma.task.update({
        where: { id },
        data: {
          ...updates,
          updatedBy: req.user.userId
        },
        include: {
          assignee: {
            select: {
              id: true,
              email: true,
              firstName: true,
              lastName: true,
              patronymic: true
            }
          }
        }
      });
      
      // Преобразуем статусы и приоритеты в русский язык для фронтенда
      const taskWithRussianLabels = {
        ...task,
        status: mapStatusToRussian(task.status),
        priority: mapPriorityToRussian(task.priority)
      };
      
      // Отправляем real-time уведомление всем пользователям об обновлении задачи
      console.log('📡 Отправка WebSocket уведомления task_updated для задачи:', task.id, 'статус:', taskWithRussianLabels.status);
      notifyAll('task_updated', taskWithRussianLabels);
      
      res.json(taskWithRussianLabels);
    } catch (error) {
      console.error('Update task error:', error);
      securityConfig.logSuspiciousActivity(req, 'TASK_UPDATE_ERROR', { error: error.message, taskId: req.params.id });
      res.status(500).json({ error: 'Ошибка при обновлении задачи' });
    }
  }
);

// Удаление задачи с проверкой прав
app.delete('/api/tasks/:id', 
  securityConfig.authRateLimit,
  securityMiddleware.authenticateToken,
  requireRole(['ADMIN', 'BOSS']),
  async (req, res) => {
    try {
      const { id } = req.params;
      
      // Валидация ID задачи
      if (!id || typeof id !== 'string' || id.trim().length === 0) {
        return res.status(400).json({ error: 'ID задачи обязателен' });
      }
      
      // Проверяем существование задачи
      const existingTask = await prisma.task.findUnique({ where: { id } });
      if (!existingTask) {
        return res.status(404).json({ error: 'Задача не найдена' });
      }
      
      await prisma.task.delete({
        where: { id }
      });
      
      // Отправляем real-time уведомление об удалении задачи
      notifyAll('task_deleted', { taskId: id });
      
      res.json({ message: 'Задача удалена' });
    } catch (error) {
      console.error('Delete task error:', error);
      securityConfig.logSuspiciousActivity(req, 'TASK_DELETE_ERROR', { error: error.message, taskId: req.params.id });
      res.status(500).json({ error: 'Ошибка при удалении задачи' });
    }
  }
);

// Архивирование задачи
app.put('/api/tasks/:id/archive', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.userId;
    
    // Проверяем права пользователя (только менеджеры и админы могут архивировать)
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user || (user.role !== 'ADMIN' && user.role !== 'BOSS')) {
      return res.status(403).json({ error: 'Недостаточно прав для архивирования задач' });
    }
    
    const task = await prisma.task.update({
      where: { id },
      data: {
        archived: true,
        updatedBy: userId
      },
      include: {
        assignee: {
          select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
            patronymic: true
          }
        }
      }
    });
    
    // Преобразуем статусы и приоритеты в русский язык для фронтенда
    const taskWithRussianLabels = {
      ...task,
      status: mapStatusToRussian(task.status),
      priority: mapPriorityToRussian(task.priority)
    };
    
    // Отправляем real-time уведомление об архивировании задачи
    notifyAll('task_archived', taskWithRussianLabels);
    
    res.json(taskWithRussianLabels);
  } catch (error) {
    console.error('Archive task error:', error);
    res.status(500).json({ error: 'Ошибка при архивировании задачи' });
  }
});

// Загрузка файлов с улучшенной безопасностью
app.post('/api/upload', 
  securityConfig.apiRateLimit,
  securityMiddleware.authenticateToken,
  securityMiddleware.validateFileUpload,
  upload.single('file'), 
  (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: 'Файл не выбран' });
      }
      
      // Дополнительная валидация загруженного файла
      const fileValidation = validators.file.validateFile(req.file);
      if (!fileValidation.isValid) {
        // Удаляем небезопасный файл
        const fs = require('fs');
        const path = require('path');
        try {
          fs.unlinkSync(path.join(__dirname, 'uploads', req.file.filename));
        } catch (deleteError) {
          console.error('Ошибка удаления небезопасного файла:', deleteError);
        }
        return res.status(400).json({ error: fileValidation.error });
      }
      
      const fileUrl = `/uploads/${req.file.filename}`;
      
      console.log(`✅ Файл безопасно загружен: ${req.file.originalname} -> ${req.file.filename}`);
      
      res.json({ 
        message: 'Файл успешно загружен',
        filename: req.file.filename,
        originalName: req.file.originalname,
        url: fileUrl,
        size: req.file.size,
        mimetype: req.file.mimetype
      });
    } catch (error) {
      console.error('Upload error:', error);
      securityConfig.logSuspiciousActivity(req, 'FILE_UPLOAD_ERROR', { 
        error: error.message,
        filename: req.file?.filename,
        originalname: req.file?.originalname
      });
      res.status(500).json({ error: 'Ошибка при загрузке файла' });
    }
  }
);

// Загрузка файла для задачи
app.post('/api/tasks/:id/upload', authenticateToken, upload.single('file'), async (req, res) => {
  try {
    const { id } = req.params;
    const { comment, textContent, reportType } = req.body;
    
    console.log('Upload request:', { id, reportType, hasFile: !!req.file, hasTextContent: !!textContent });
    
    let reportFile;
    
    if (reportType === 'text' && textContent) {
      // Обработка текстового отчета
      reportFile = {
        type: 'text',
        content: textContent,
        uploadedAt: new Date().toISOString(),
        comment: comment || '',
        isTextReport: true
      };
    } else if (req.file) {
      // Обработка файлового отчета
      const fileUrl = `/uploads/${req.file.filename}`;
      
      // Правильное декодирование имени файла для поддержки кириллицы
      let originalFileName = req.file.originalname;
      try {
        // Проверяем, нужно ли декодировать имя файла
        // Если имя файла содержит некорректные символы, пытаемся его исправить
        if (originalFileName.includes('Ð') || originalFileName.includes('Ñ') || originalFileName.includes('Ã')) {
          // Пытаемся декодировать из Latin-1 в UTF-8
          const buffer = Buffer.from(originalFileName, 'latin1');
          originalFileName = buffer.toString('utf8');
          console.log('Decoded filename from latin1 to utf8:', originalFileName);
        }
      } catch (decodeError) {
        console.warn('Failed to decode filename, using original:', decodeError);
        // Если декодирование не удалось, используем оригинальное имя
      }
      
      reportFile = {
        type: 'file',
        name: originalFileName,
        url: fileUrl,
        uploadedAt: new Date().toISOString(),
        size: req.file.size,
        comment: comment || '',
        isTextReport: false
      };
    } else {
      console.log('No file or text content provided');
      return res.status(400).json({ error: 'Не предоставлен ни файл, ни текстовый контент' });
    }
    
    const task = await prisma.task.update({
      where: { id },
      data: {
        reportFile,
        status: 'UNDER_REVIEW', // Автоматически меняем статус на "на проверке"
        updatedBy: req.user.userId
      },
      include: {
        assignee: {
          select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
            patronymic: true
          }
        }
      }
    });
    
    console.log('Task updated successfully:', task.id);
    
    // Преобразуем статусы и приоритеты в русский язык для фронтенда
    const taskWithRussianLabels = {
      ...task,
      status: mapStatusToRussian(task.status),
      priority: mapPriorityToRussian(task.priority)
    };
    
    // Отправляем real-time уведомление всем пользователям о загрузке отчета и изменении статуса
    console.log('📡 Отправка WebSocket уведомления task_updated для загрузки отчета, задача:', task.id, 'статус:', taskWithRussianLabels.status);
    notifyAll('task_updated', {
      ...taskWithRussianLabels,
      reportFile: {
        ...taskWithRussianLabels.reportFile,
        // Добавляем флаг для фронтенда, что отчет был только что загружен
        isNew: true
      }
    });
    
    res.json({ task: taskWithRussianLabels, fileUrl: reportFile.url || null });
  } catch (error) {
    console.error('File upload error:', error);
    res.status(500).json({ error: 'Ошибка при загрузке файла' });
  }
});

// Скачивание файла отчета
app.get('/api/tasks/:id/download', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const task = await prisma.task.findUnique({ where: { id } });

    if (!task || !task.reportFile) {
      return res.status(404).json({ error: 'Отчет не найден' });
    }

    const reportFile = task.reportFile;

    if (reportFile.isTextReport) {
      // Отдаем текстовый отчет
      res.setHeader('Content-Disposition', 'attachment; filename="report.txt"');
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      res.send(reportFile.content);
    } else {
      // Отдаем файл
      const filePath = path.join(__dirname, reportFile.url);
      if (fs.existsSync(filePath)) {
        // Правильно кодируем имя файла для заголовка Content-Disposition
        // Используем RFC 5987 для поддержки Unicode символов
        const encodedFilename = encodeURIComponent(reportFile.name);
        const contentDisposition = `attachment; filename*=UTF-8''${encodedFilename}`;
        
        res.setHeader('Content-Disposition', contentDisposition);
        res.setHeader('Content-Type', 'application/octet-stream');
        
        // Отправляем файл
        res.sendFile(filePath, (err) => {
          if (err) {
            console.error('Error sending file:', err);
            if (!res.headersSent) {
              res.status(500).json({ error: 'Ошибка при отправке файла' });
            }
          }
        });
      } else {
        res.status(404).json({ error: 'Файл отчета не найден на сервере' });
      }
    }
  } catch (error) {
    console.error('File download error:', error);
    res.status(500).json({ error: 'Ошибка при скачивании файла' });
  }
});

// Утилиты для преобразования данных
const mapStatusToRussian = (status) => {
  const statusMap = {
    'ASSIGNED': 'назначено',
    'IN_PROGRESS': 'в работе',
    'UNDER_REVIEW': 'на проверке',
    'COMPLETED': 'выполнено',
    'REVISION': 'доработка'
  };
  return statusMap[status] || status;
};

const mapPriorityToRussian = (priority) => {
  const priorityMap = {
    'LOW': 'низкий',
    'MEDIUM': 'средний',
    'HIGH': 'высокий'
  };
  return priorityMap[priority] || priority;
};

// Обработка ошибок
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Внутренняя ошибка сервера' });
});

// 404 обработчик
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Маршрут не найден' });
});

// Функция для получения локального IP
const getLocalIP = () => {
  const os = require('os');
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        return iface.address;
      }
    }
  }
  return 'localhost';
};

// Функция для запуска серверов
const startServers = () => {
  const HTTP_PORT = PORT;
  const HTTPS_PORT = parseInt(PORT) + 1; // HTTPS на следующем порту
  const localIP = getLocalIP();
  
  // Запуск HTTP сервера с Socket.io
  server.listen(HTTP_PORT, '0.0.0.0', () => {
    console.log(`🚀 HTTP сервер с WebSocket запущен на порту ${HTTP_PORT}`);
    console.log(`📊 API доступно по адресу: http://localhost:${HTTP_PORT}/api`);
    console.log(`📊 API доступно по адресу: http://${localIP}:${HTTP_PORT}/api`);
    console.log(`🔌 WebSocket доступен по адресу: ws://localhost:${HTTP_PORT}`);
    console.log(`🔌 WebSocket доступен по адресу: ws://${localIP}:${HTTP_PORT}`);
  });
  
  // Попытка запуска HTTPS сервера
  const certsPath = path.join(__dirname, 'certs');
  const keyPath = path.join(certsPath, 'key.pem');
  const certPath = path.join(certsPath, 'cert.pem');
  
  if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
    try {
      const httpsOptions = {
        key: fs.readFileSync(keyPath),
        cert: fs.readFileSync(certPath)
      };
      
      const httpsServer = https.createServer(httpsOptions, app);
      httpsServer.listen(HTTPS_PORT, '0.0.0.0', () => {
        console.log(`🔐 HTTPS сервер запущен на порту ${HTTPS_PORT}`);
        console.log(`📊 Безопасное API: https://localhost:${HTTPS_PORT}/api`);
        console.log(`📊 Безопасное API: https://${localIP}:${HTTPS_PORT}/api`);
        console.log('');
        console.log('✅ HTTPS включен - браузерные уведомления будут работать!');
        console.log('⚠️  При первом подключении браузер покажет предупреждение о сертификате.');
        console.log('   Нажмите "Дополнительно" → "Перейти на сайт" для продолжения.');
        console.log('');
        console.log('🌐 Доступные адреса:');
        console.log(`   ➜  API HTTP:  http://localhost:${HTTP_PORT}/api`);
        console.log(`   ➜  API HTTP:  http://${localIP}:${HTTP_PORT}/api`);
        console.log(`   ➜  API HTTPS: https://localhost:${HTTPS_PORT}/api`);
        console.log(`   ➜  API HTTPS: https://${localIP}:${HTTPS_PORT}/api`);
      });
    } catch (error) {
      console.error('❌ Ошибка запуска HTTPS сервера:', error.message);
      console.log('💡 Запущен только HTTP сервер. Для HTTPS выполните: node generate-ssl.js');
    }
  } else {
    console.log('⚠️  SSL сертификаты не найдены.');
    console.log('💡 Для включения HTTPS выполните: node generate-ssl.js');
    console.log('📱 Без HTTPS браузерные уведомления работать не будут!');
  }
  
  console.log('');
  console.log('📱 Для работы уведомлений используйте HTTPS версию!');
};

// Запуск серверов
startServers();

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('\n🛑 Получен сигнал SIGINT, завершаем работу...');
  await prisma.$disconnect();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('\n🛑 Получен сигнал SIGTERM, завершаем работу...');
  await prisma.$disconnect();
  process.exit(0);
});