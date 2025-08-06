const helmet = require('helmet');
const cors = require('cors');
const securityConfig = require('./security-config');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// Middleware для безопасности
const securityMiddleware = {
  // Основные заголовки безопасности
  setupHelmet: () => {
    return helmet(securityConfig.helmetConfig);
  },

  // Настройка CORS
  setupCORS: () => {
    return cors({
      origin: (origin, callback) => {
        if (securityConfig.validateOrigin(origin)) {
          callback(null, true);
        } else {
          console.warn(`🚨 Заблокирован CORS запрос с origin: ${origin}`);
          callback(new Error('Не разрешено CORS политикой'));
        }
      },
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
      maxAge: 86400 // 24 часа
    });
  },

  // Валидация и санитизация входных данных
  validateAndSanitize: (req, res, next) => {
    try {
      // Проверяем на SQL инъекции
      const checkForSQLInjection = (obj) => {
        for (const key in obj) {
          if (typeof obj[key] === 'string') {
            if (securityConfig.detectSQLInjection(obj[key])) {
              securityConfig.logSuspiciousActivity(req, 'SQL_INJECTION_ATTEMPT', {
                field: key,
                value: obj[key]
              });
              return res.status(400).json({ 
                error: 'Обнаружена попытка SQL инъекции' 
              });
            }
          } else if (typeof obj[key] === 'object' && obj[key] !== null) {
            checkForSQLInjection(obj[key]);
          }
        }
      };

      // Проверяем body, query и params
      if (req.body) checkForSQLInjection(req.body);
      if (req.query) checkForSQLInjection(req.query);
      if (req.params) checkForSQLInjection(req.params);

      // Санитизируем данные
      if (req.body) {
        req.body = securityConfig.sanitizeInput(req.body);
      }
      if (req.query) {
        req.query = securityConfig.sanitizeInput(req.query);
      }

      next();
    } catch (error) {
      console.error('Ошибка валидации:', error);
      res.status(500).json({ error: 'Ошибка обработки данных' });
    }
  },

  // Улучшенная аутентификация JWT
  authenticateToken: (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'Токен доступа отсутствует' });
    }

    try {
      // Проверяем формат токена
      if (!token.match(/^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$/)) {
        securityConfig.logSuspiciousActivity(req, 'INVALID_TOKEN_FORMAT', { token });
        return res.status(401).json({ error: 'Неверный формат токена' });
      }

      jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
          if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Токен истек' });
          } else if (err.name === 'JsonWebTokenError') {
            securityConfig.logSuspiciousActivity(req, 'INVALID_TOKEN', { error: err.message });
            return res.status(401).json({ error: 'Недействительный токен' });
          }
          return res.status(403).json({ error: 'Ошибка проверки токена' });
        }

        // Проверяем обязательные поля в токене
        if (!user.id || !user.email) {
          securityConfig.logSuspiciousActivity(req, 'MALFORMED_TOKEN_PAYLOAD', { user });
          return res.status(401).json({ error: 'Некорректные данные в токене' });
        }

        req.user = user;
        next();
      });
    } catch (error) {
      console.error('Ошибка аутентификации:', error);
      res.status(500).json({ error: 'Ошибка сервера при аутентификации' });
    }
  },

  // Проверка ролей с улучшенной безопасностью
  requireRole: (allowedRoles) => {
    return (req, res, next) => {
      if (!req.user) {
        return res.status(401).json({ error: 'Пользователь не аутентифицирован' });
      }

      if (!req.user.role || !allowedRoles.includes(req.user.role)) {
        securityConfig.logSuspiciousActivity(req, 'UNAUTHORIZED_ROLE_ACCESS', {
          userRole: req.user.role,
          requiredRoles: allowedRoles,
          userId: req.user.id
        });
        return res.status(403).json({ error: 'Недостаточно прав доступа' });
      }

      next();
    };
  },

  // Валидация данных регистрации
  validateRegistration: (req, res, next) => {
    const { email, password, firstName, lastName } = req.body;

    // Проверка email
    if (!email || !securityConfig.validateEmail(email)) {
      return res.status(400).json({ 
        error: 'Некорректный email адрес' 
      });
    }

    // Проверка пароля
    if (!password || !securityConfig.validatePassword(password)) {
      return res.status(400).json({ 
        error: 'Пароль должен содержать минимум 8 символов, включая заглавные и строчные буквы, цифры и специальные символы' 
      });
    }

    // Проверка имени
    if (!firstName || firstName.trim().length < 2 || firstName.trim().length > 50) {
      return res.status(400).json({ 
        error: 'Имя должно содержать от 2 до 50 символов' 
      });
    }

    // Проверка фамилии
    if (!lastName || lastName.trim().length < 2 || lastName.trim().length > 50) {
      return res.status(400).json({ 
        error: 'Фамилия должна содержать от 2 до 50 символов' 
      });
    }

    // Проверка на подозрительные символы в имени
    if (!/^[a-zA-Zа-яА-Я\s\-']+$/.test(firstName.trim())) {
      return res.status(400).json({ 
        error: 'Имя содержит недопустимые символы' 
      });
    }

    // Проверка на подозрительные символы в фамилии
    if (!/^[a-zA-Zа-яА-Я\s\-']+$/.test(lastName.trim())) {
      return res.status(400).json({ 
        error: 'Фамилия содержит недопустимые символы' 
      });
    }

    next();
  },

  // Валидация данных входа
  validateLogin: (req, res, next) => {
    const { email, password } = req.body;

    if (!email || !securityConfig.validateEmail(email)) {
      return res.status(400).json({ 
        error: 'Некорректный email адрес' 
      });
    }

    if (!password || password.length < 1) {
      return res.status(400).json({ 
        error: 'Пароль не может быть пустым' 
      });
    }

    next();
  },

  // Защита от брутфорса паролей
  bruteForceProtection: (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress;
    const key = `login_attempts_${ip}`;
    
    // Здесь можно использовать Redis или in-memory store
    // Для простоты используем простой объект (в продакшене лучше Redis)
    if (!global.loginAttempts) {
      global.loginAttempts = new Map();
    }

    const attempts = global.loginAttempts.get(key) || { count: 0, lastAttempt: Date.now() };
    const now = Date.now();
    const timeDiff = now - attempts.lastAttempt;

    // Сбрасываем счетчик через 15 минут
    if (timeDiff > 15 * 60 * 1000) {
      attempts.count = 0;
    }

    if (attempts.count >= 5) {
      securityConfig.logSuspiciousActivity(req, 'BRUTE_FORCE_ATTEMPT', {
        ip: ip,
        attempts: attempts.count
      });
      return res.status(429).json({ 
        error: 'Слишком много неудачных попыток входа. Попробуйте через 15 минут.' 
      });
    }

    // Увеличиваем счетчик при неудачной попытке
    req.incrementLoginAttempts = () => {
      attempts.count++;
      attempts.lastAttempt = now;
      global.loginAttempts.set(key, attempts);
    };

    // Сбрасываем счетчик при успешном входе
    req.resetLoginAttempts = () => {
      global.loginAttempts.delete(key);
    };

    next();
  },

  // Логирование безопасности
  securityLogger: (req, res, next) => {
    const startTime = Date.now();
    
    res.on('finish', () => {
      const duration = Date.now() - startTime;
      const logData = {
        timestamp: new Date().toISOString(),
        method: req.method,
        url: req.originalUrl,
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent'),
        statusCode: res.statusCode,
        duration: duration,
        userId: req.user ? req.user.id : null
      };

      // Логируем подозрительные запросы
      if (res.statusCode >= 400 || duration > 5000) {
        console.warn('⚠️ Подозрительный запрос:', JSON.stringify(logData, null, 2));
      }
    });

    next();
  },

  // Проверка размера файлов
  validateFileUpload: (req, res, next) => {
    if (req.file) {
      // Проверяем размер файла (максимум 10MB)
      if (req.file.size > 10 * 1024 * 1024) {
        return res.status(400).json({ 
          error: 'Файл слишком большой. Максимальный размер: 10MB' 
        });
      }

      // Проверяем тип файла
      const allowedMimeTypes = [
        'text/plain',
        'application/pdf',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'image/jpeg',
        'image/png',
        'image/gif'
      ];

      if (!allowedMimeTypes.includes(req.file.mimetype)) {
        return res.status(400).json({ 
          error: 'Недопустимый тип файла' 
        });
      }

      // Проверяем имя файла на подозрительные символы
      if (!/^[a-zA-Z0-9._\-\s()]+$/.test(req.file.originalname)) {
        return res.status(400).json({ 
          error: 'Недопустимые символы в имени файла' 
        });
      }
    }

    next();
  }
};

module.exports = securityMiddleware;