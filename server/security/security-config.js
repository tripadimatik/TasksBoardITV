const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const validator = require('validator');
const xss = require('xss');
const hpp = require('hpp');
const mongoSanitize = require('express-mongo-sanitize');

// Конфигурация безопасности
const securityConfig = {
  // Rate limiting для API
  apiRateLimit: rateLimit({
    windowMs: 15 * 60 * 1000, // 15 минут
    max: 100, // максимум 100 запросов с одного IP за 15 минут
    message: {
      error: 'Слишком много запросов с вашего IP, попробуйте позже'
    },
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => {
      // Пропускаем rate limiting для локальных IP
      const ip = req.ip || req.connection.remoteAddress;
      return ip === '127.0.0.1' || ip === '::1' || ip.startsWith('192.168.') || ip.startsWith('10.');
    }
  }),

  // Строгий rate limiting для аутентификации
  authRateLimit: rateLimit({
    windowMs: 15 * 60 * 1000, // 15 минут
    max: 5, // максимум 5 попыток входа за 15 минут
    message: {
      error: 'Слишком много попыток входа, попробуйте через 15 минут'
    },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true
  }),

  // Замедление запросов при превышении лимита
  speedLimiter: slowDown({
    windowMs: 15 * 60 * 1000, // 15 минут
    delayAfter: 50, // замедлять после 50 запросов
    delayMs: () => 500, // добавлять 500мс задержки за каждый запрос (новый формат v2)
    validate: { delayMs: false } // отключаем предупреждение о миграции
  }),

  // Настройки Helmet для безопасности заголовков
  helmetConfig: {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        imgSrc: ["'self'", "data:", "https:"],
        scriptSrc: ["'self'"],
        connectSrc: ["'self'", "ws:", "wss:"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"]
      }
    },
    crossOriginEmbedderPolicy: false,
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true
    }
  },

  // Валидация и санитизация входных данных
  sanitizeInput: (data) => {
    if (typeof data === 'string') {
      // Удаляем XSS
      data = xss(data, {
        whiteList: {}, // Не разрешаем никаких HTML тегов
        stripIgnoreTag: true,
        stripIgnoreTagBody: ['script']
      });
      
      // Экранируем HTML
      data = validator.escape(data);
    }
    
    if (typeof data === 'object' && data !== null) {
      for (const key in data) {
        if (data.hasOwnProperty(key)) {
          data[key] = securityConfig.sanitizeInput(data[key]);
        }
      }
    }
    
    return data;
  },

  // Валидация email
  validateEmail: (email) => {
    return validator.isEmail(email) && validator.isLength(email, { max: 254 });
  },

  // Валидация пароля
  validatePassword: (password) => {
    return validator.isLength(password, { min: 8, max: 128 }) &&
           /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/.test(password);
  },

  // Проверка на SQL инъекции
  detectSQLInjection: (input) => {
    const sqlPatterns = [
      /('|(\-\-)|(;)|(\||\|)|(\*|\*))/i,
      /(union|select|insert|delete|update|drop|create|alter|exec|execute)/i,
      /(script|javascript|vbscript|onload|onerror|onclick)/i
    ];
    
    return sqlPatterns.some(pattern => pattern.test(input));
  },

  // Middleware для защиты от NoSQL инъекций
  noSQLSanitize: mongoSanitize({
    replaceWith: '_'
  }),

  // Защита от HTTP Parameter Pollution
  hppProtection: hpp({
    whitelist: ['tags', 'categories'] // разрешенные дублирующиеся параметры
  }),

  // Проверка CORS origin
  validateOrigin: (origin) => {
    if (!origin) return true; // Разрешаем запросы без origin
    
    const allowedOrigins = [
      'http://localhost:5173',
      'http://localhost:8080',
      'https://localhost:8080',
      'http://127.0.0.1:5173',
      'http://127.0.0.1:8080',
      'https://127.0.0.1:8080'
    ];
    
    // Разрешаем localhost и локальные IP
    if (origin.includes('localhost') || origin.includes('127.0.0.1')) {
      return true;
    }
    
    // Разрешаем IP-адреса локальной сети
    if (origin.match(/^https?:\/\/(192\.168\.|10\.)/)) {
      return true;
    }
    
    // Проверяем список разрешенных origins
    return allowedOrigins.includes(origin) || 
           (process.env.FRONTEND_URL && origin === process.env.FRONTEND_URL);
  },

  // Логирование подозрительной активности
  logSuspiciousActivity: (req, type, details) => {
    const logEntry = {
      timestamp: new Date().toISOString(),
      type: type,
      ip: req.ip || req.connection.remoteAddress,
      userAgent: req.get('User-Agent'),
      url: req.originalUrl,
      method: req.method,
      details: details
    };
    
    console.warn('🚨 ПОДОЗРИТЕЛЬНАЯ АКТИВНОСТЬ:', JSON.stringify(logEntry, null, 2));
    
    // Здесь можно добавить отправку в систему мониторинга
    // или сохранение в файл логов
  }
};

module.exports = securityConfig;