const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Утилиты для криптографии и безопасности
const cryptoUtils = {
  // Генерация безопасного случайного токена
  generateSecureToken: (length = 32) => {
    return crypto.randomBytes(length).toString('hex');
  },

  // Генерация соли для хеширования
  generateSalt: (rounds = 12) => {
    return bcrypt.genSaltSync(rounds);
  },

  // Безопасное хеширование пароля
  hashPassword: async (password) => {
    try {
      const salt = await bcrypt.genSalt(12);
      return await bcrypt.hash(password, salt);
    } catch (error) {
      throw new Error('Ошибка хеширования пароля');
    }
  },

  // Проверка пароля
  verifyPassword: async (password, hashedPassword) => {
    try {
      return await bcrypt.compare(password, hashedPassword);
    } catch (error) {
      throw new Error('Ошибка проверки пароля');
    }
  },

  // Генерация JWT токена с дополнительной безопасностью
  generateJWT: (payload, expiresIn = '24h') => {
    try {
      // Добавляем дополнительные поля безопасности
      const enhancedPayload = {
        ...payload,
        iat: Math.floor(Date.now() / 1000),
        jti: crypto.randomUUID(), // Уникальный ID токена
        iss: 'bureau-task-manager', // Издатель токена
      };

      return jwt.sign(enhancedPayload, process.env.JWT_SECRET, {
        expiresIn,
        algorithm: 'HS256'
      });
    } catch (error) {
      throw new Error('Ошибка генерации JWT токена');
    }
  },

  // Проверка JWT токена
  verifyJWT: (token) => {
    try {
      return jwt.verify(token, process.env.JWT_SECRET, {
        algorithms: ['HS256']
      });
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        throw new Error('Токен истек');
      } else if (error.name === 'JsonWebTokenError') {
        throw new Error('Недействительный токен');
      }
      throw new Error('Ошибка проверки токена');
    }
  },

  // Шифрование данных (AES-256-GCM)
  encrypt: (text, key = null) => {
    try {
      const algorithm = 'aes-256-gcm';
      const secretKey = key || process.env.ENCRYPTION_KEY || crypto.randomBytes(32);
      const iv = crypto.randomBytes(16);
      
      const cipher = crypto.createCipher(algorithm, secretKey, iv);
      
      let encrypted = cipher.update(text, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      
      const authTag = cipher.getAuthTag();
      
      return {
        encrypted,
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex')
      };
    } catch (error) {
      throw new Error('Ошибка шифрования данных');
    }
  },

  // Расшифровка данных
  decrypt: (encryptedData, key = null) => {
    try {
      const algorithm = 'aes-256-gcm';
      const secretKey = key || process.env.ENCRYPTION_KEY;
      
      if (!secretKey) {
        throw new Error('Ключ шифрования не найден');
      }
      
      const decipher = crypto.createDecipher(algorithm, secretKey, Buffer.from(encryptedData.iv, 'hex'));
      decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
      
      let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      return decrypted;
    } catch (error) {
      throw new Error('Ошибка расшифровки данных');
    }
  },

  // Генерация хеша для проверки целостности
  generateHash: (data, algorithm = 'sha256') => {
    return crypto.createHash(algorithm).update(data).digest('hex');
  },

  // Проверка целостности данных
  verifyHash: (data, hash, algorithm = 'sha256') => {
    const computedHash = cryptoUtils.generateHash(data, algorithm);
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(computedHash, 'hex'));
  },

  // Генерация CSRF токена
  generateCSRFToken: () => {
    return crypto.randomBytes(32).toString('base64');
  },

  // Безопасное сравнение строк (защита от timing attacks)
  safeCompare: (a, b) => {
    if (a.length !== b.length) {
      return false;
    }
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
  },

  // Генерация одноразового пароля (OTP)
  generateOTP: (length = 6) => {
    const digits = '0123456789';
    let otp = '';
    
    for (let i = 0; i < length; i++) {
      const randomIndex = crypto.randomInt(0, digits.length);
      otp += digits[randomIndex];
    }
    
    return otp;
  },

  // Генерация безопасного пароля
  generateSecurePassword: (length = 16) => {
    const lowercase = 'abcdefghijklmnopqrstuvwxyz';
    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const numbers = '0123456789';
    const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';
    
    const allChars = lowercase + uppercase + numbers + symbols;
    let password = '';
    
    // Гарантируем наличие хотя бы одного символа каждого типа
    password += lowercase[crypto.randomInt(0, lowercase.length)];
    password += uppercase[crypto.randomInt(0, uppercase.length)];
    password += numbers[crypto.randomInt(0, numbers.length)];
    password += symbols[crypto.randomInt(0, symbols.length)];
    
    // Заполняем остальные позиции случайными символами
    for (let i = 4; i < length; i++) {
      password += allChars[crypto.randomInt(0, allChars.length)];
    }
    
    // Перемешиваем символы
    return password.split('').sort(() => crypto.randomInt(-1, 2)).join('');
  },

  // Проверка силы пароля
  checkPasswordStrength: (password) => {
    const checks = {
      length: password.length >= 8,
      lowercase: /[a-z]/.test(password),
      uppercase: /[A-Z]/.test(password),
      numbers: /\d/.test(password),
      symbols: /[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(password),
      noCommonPatterns: !/123456|password|qwerty|admin|letmein/.test(password.toLowerCase())
    };
    
    const score = Object.values(checks).filter(Boolean).length;
    
    let strength = 'Очень слабый';
    if (score >= 6) strength = 'Очень сильный';
    else if (score >= 5) strength = 'Сильный';
    else if (score >= 4) strength = 'Средний';
    else if (score >= 3) strength = 'Слабый';
    
    return {
      strength,
      score,
      checks,
      isSecure: score >= 5
    };
  },

  // Маскирование чувствительных данных для логов
  maskSensitiveData: (data, fields = ['password', 'token', 'secret', 'key']) => {
    const masked = { ...data };
    
    fields.forEach(field => {
      if (masked[field]) {
        const value = masked[field].toString();
        if (value.length > 4) {
          masked[field] = value.substring(0, 2) + '*'.repeat(value.length - 4) + value.substring(value.length - 2);
        } else {
          masked[field] = '*'.repeat(value.length);
        }
      }
    });
    
    return masked;
  },

  // Генерация подписи для API запросов
  generateAPISignature: (method, url, body, timestamp, secret) => {
    const message = `${method}${url}${JSON.stringify(body || {})}${timestamp}`;
    return crypto.createHmac('sha256', secret).update(message).digest('hex');
  },

  // Проверка подписи API запроса
  verifyAPISignature: (signature, method, url, body, timestamp, secret, tolerance = 300) => {
    // Проверяем время (защита от replay атак)
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - timestamp) > tolerance) {
      return false;
    }
    
    const expectedSignature = cryptoUtils.generateAPISignature(method, url, body, timestamp, secret);
    return cryptoUtils.safeCompare(signature, expectedSignature);
  }
};

module.exports = cryptoUtils;