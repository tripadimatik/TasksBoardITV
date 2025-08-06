// Утилиты безопасности для фронтенда

/**
 * Санитизация HTML для предотвращения XSS атак
 */
export const sanitizeHtml = (input: string): string => {
  if (!input || typeof input !== 'string') {
    return '';
  }

  // Заменяем опасные символы HTML
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
};

/**
 * Валидация email адреса
 */
export const validateEmail = (email: string): boolean => {
  if (!email || typeof email !== 'string') {
    return false;
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email) && email.length <= 254;
};

/**
 * Валидация пароля
 */
export const validatePassword = (password: string): { isValid: boolean; error?: string } => {
  if (!password || typeof password !== 'string') {
    return { isValid: false, error: 'Пароль обязателен' };
  }

  if (password.length < 8) {
    return { isValid: false, error: 'Пароль должен содержать минимум 8 символов' };
  }

  if (password.length > 128) {
    return { isValid: false, error: 'Пароль слишком длинный' };
  }

  if (!/[a-z]/.test(password)) {
    return { isValid: false, error: 'Пароль должен содержать строчные буквы' };
  }

  if (!/[A-Z]/.test(password)) {
    return { isValid: false, error: 'Пароль должен содержать заглавные буквы' };
  }

  if (!/\d/.test(password)) {
    return { isValid: false, error: 'Пароль должен содержать цифры' };
  }

  return { isValid: true };
};

/**
 * Валидация имени пользователя
 */
export const validateName = (name: string): { isValid: boolean; error?: string } => {
  if (!name || typeof name !== 'string') {
    return { isValid: false, error: 'Имя обязательно' };
  }

  const trimmedName = name.trim();
  
  if (trimmedName.length < 2) {
    return { isValid: false, error: 'Имя должно содержать минимум 2 символа' };
  }

  if (trimmedName.length > 50) {
    return { isValid: false, error: 'Имя слишком длинное' };
  }

  // Разрешаем только буквы, пробелы, дефисы и апострофы
  const nameRegex = /^[a-zA-Zа-яА-ЯёЁ\s\-']+$/;
  if (!nameRegex.test(trimmedName)) {
    return { isValid: false, error: 'Имя содержит недопустимые символы' };
  }

  return { isValid: true };
};

/**
 * Санитизация пользовательского ввода
 */
export const sanitizeInput = (input: string, maxLength: number = 1000): string => {
  if (!input || typeof input !== 'string') {
    return '';
  }

  // Обрезаем до максимальной длины
  let sanitized = input.slice(0, maxLength);
  
  // Удаляем потенциально опасные символы
  sanitized = sanitized.replace(/[<>"'&]/g, '');
  
  // Удаляем лишние пробелы
  sanitized = sanitized.trim().replace(/\s+/g, ' ');
  
  return sanitized;
};

/**
 * Проверка на подозрительные паттерны
 */
export const detectSuspiciousPatterns = (input: string): boolean => {
  if (!input || typeof input !== 'string') {
    return false;
  }

  const suspiciousPatterns = [
    /<script[^>]*>.*?<\/script>/gi,
    /javascript:/gi,
    /on\w+\s*=/gi,
    /data:text\/html/gi,
    /vbscript:/gi,
    /expression\s*\(/gi,
    /url\s*\(/gi,
    /@import/gi,
    /\.\.\/\.\.\/|\.\.\\\.\.\\/gi, // Directory traversal - более строгая проверка
    /union.*select/gi, // SQL injection
    /drop\s+table/gi,
    /insert\s+into/gi,
    /delete\s+from/gi,
    /<\?php/gi, // PHP код
    /<%.*%>/gi, // ASP/JSP код
    /\$\{.*\}/gi // Template injection
  ];

  return suspiciousPatterns.some(pattern => pattern.test(input));
};

/**
 * Проверка имени файла на подозрительные паттерны
 */
export const detectSuspiciousFilePatterns = (fileName: string): boolean => {
  if (!fileName || typeof fileName !== 'string') {
    return false;
  }

  const suspiciousFilePatterns = [
    /\.\.\/|\.\.\\/gi, // Directory traversal
    /<script/gi,
    /javascript:/gi,
    /\.exe$/gi,
    /\.bat$/gi,
    /\.cmd$/gi,
    /\.scr$/gi,
    /\.vbs$/gi,
    /\.js$/gi,
    /\.php$/gi,
    /\.asp$/gi,
    /\.jsp$/gi
  ];

  return suspiciousFilePatterns.some(pattern => pattern.test(fileName));
};

/**
 * Безопасное парсинг JSON
 */
export const safeJsonParse = <T>(jsonString: string, fallback: T): T => {
  try {
    if (!jsonString || typeof jsonString !== 'string') {
      return fallback;
    }
    
    // Проверяем на подозрительные паттерны
    if (detectSuspiciousPatterns(jsonString)) {
      console.warn('Обнаружены подозрительные паттерны в JSON');
      return fallback;
    }
    
    return JSON.parse(jsonString);
  } catch (error) {
    console.error('Ошибка парсинга JSON:', error);
    return fallback;
  }
};

/**
 * Валидация файла
 */
export const validateFile = (file: File): { isValid: boolean; error?: string } => {
  if (!file) {
    return { isValid: false, error: 'Файл не выбран' };
  }

  // Проверяем размер файла (максимум 10MB)
  const maxSize = 10 * 1024 * 1024;
  if (file.size > maxSize) {
    return { isValid: false, error: 'Файл слишком большой. Максимальный размер: 10MB' };
  }

  // Разрешенные типы файлов - расширенный список
  const allowedTypes = [
    'image/jpeg',
    'image/jpg', // Добавлен для совместимости
    'image/png',
    'image/gif',
    'image/webp',
    'image/bmp',
    'image/tiff',
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.ms-powerpoint',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'text/plain',
    'text/csv',
    'application/zip',
    'application/x-zip-compressed',
    'application/rar',
    'application/x-rar-compressed',
    'application/rtf',
    'application/json',
    'text/xml',
    'application/xml'
  ];

  // Проверяем расширение файла - расширенный список
  const allowedExtensions = [
    '.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.tiff',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.txt', '.csv', '.rtf', '.json', '.xml',
    '.zip', '.rar'
  ];
  const fileExtension = file.name.toLowerCase().substring(file.name.lastIndexOf('.'));
  
  // Если MIME тип не определен, проверяем только по расширению
  if (!file.type || file.type === '') {
    if (!allowedExtensions.includes(fileExtension)) {
      return { isValid: false, error: 'Недопустимое расширение файла' };
    }
  } else {
    // Если MIME тип определен, проверяем его
    if (!allowedTypes.includes(file.type)) {
      // Дополнительная проверка по расширению для совместимости
      if (!allowedExtensions.includes(fileExtension)) {
        return { isValid: false, error: 'Неподдерживаемый тип файла' };
      }
    }
  }

  return { isValid: true };
};

/**
 * Генерация безопасного случайного ID
 */
export const generateSecureId = (): string => {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
};

/**
 * Проверка токена на валидность (базовая проверка формата)
 */
export const isValidToken = (token: string): boolean => {
  if (!token || typeof token !== 'string') {
    return false;
  }

  // JWT токен должен состоять из трех частей, разделенных точками
  const parts = token.split('.');
  if (parts.length !== 3) {
    return false;
  }

  // Каждая часть должна быть base64url строкой
  const base64UrlRegex = /^[A-Za-z0-9_-]+$/;
  return parts.every(part => base64UrlRegex.test(part));
};

/**
 * Логирование подозрительной активности
 */
export const logSuspiciousActivity = (activity: string, details?: any): void => {
  console.warn(`🚨 ПОДОЗРИТЕЛЬНАЯ АКТИВНОСТЬ: ${activity}`, details);
  
  // В продакшене здесь можно отправлять данные на сервер для анализа
  if (process.env.NODE_ENV === 'production') {
    // Отправка на сервер мониторинга
  }
};