const validator = require('validator');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

// Валидаторы для различных типов данных
const validators = {
  // Валидация пользователя
  user: {
    // Валидация email
    email: (email) => {
      if (!email || typeof email !== 'string') {
        return { isValid: false, error: 'Email обязателен' };
      }
      
      if (!validator.isEmail(email)) {
        return { isValid: false, error: 'Некорректный формат email' };
      }
      
      if (email.length > 254) {
        return { isValid: false, error: 'Email слишком длинный' };
      }
      
      // Проверка на подозрительные домены
      const suspiciousDomains = ['tempmail.org', '10minutemail.com', 'guerrillamail.com'];
      const domain = email.split('@')[1];
      if (suspiciousDomains.includes(domain)) {
        return { isValid: false, error: 'Использование временных email адресов запрещено' };
      }
      
      return { isValid: true };
    },

    // Валидация пароля
    password: (password) => {
      if (!password || typeof password !== 'string') {
        return { isValid: false, error: 'Пароль обязателен' };
      }
      
      if (password.length < 8) {
        return { isValid: false, error: 'Пароль должен содержать минимум 8 символов' };
      }
      
      if (password.length > 128) {
        return { isValid: false, error: 'Пароль слишком длинный (максимум 128 символов)' };
      }
      
      if (!/(?=.*[a-z])/.test(password)) {
        return { isValid: false, error: 'Пароль должен содержать строчные буквы' };
      }
      
      if (!/(?=.*[A-Z])/.test(password)) {
        return { isValid: false, error: 'Пароль должен содержать заглавные буквы' };
      }
      
      if (!/(?=.*\d)/.test(password)) {
        return { isValid: false, error: 'Пароль должен содержать цифры' };
      }
      
      if (!/(?=.*[@$!%*?&])/.test(password)) {
        return { isValid: false, error: 'Пароль должен содержать специальные символы (@$!%*?&)' };
      }
      
      // Проверка на общие пароли
      const commonPasswords = [
        'password', '123456789', 'qwerty123', 'admin123', 'password123',
        'letmein123', 'welcome123', 'monkey123', '1234567890'
      ];
      
      if (commonPasswords.includes(password.toLowerCase())) {
        return { isValid: false, error: 'Пароль слишком простой' };
      }
      
      return { isValid: true };
    },

    // Валидация имени
    name: (name) => {
      if (!name || typeof name !== 'string') {
        return { isValid: false, error: 'Имя обязательно' };
      }
      
      const trimmedName = name.trim();
      
      if (trimmedName.length < 2) {
        return { isValid: false, error: 'Имя должно содержать минимум 2 символа' };
      }
      
      if (trimmedName.length > 50) {
        return { isValid: false, error: 'Имя слишком длинное (максимум 50 символов)' };
      }
      
      if (!/^[a-zA-Zа-яА-Я\s\-']+$/.test(trimmedName)) {
        return { isValid: false, error: 'Имя содержит недопустимые символы' };
      }
      
      // Проверка на подозрительные паттерны
      if (/admin|root|test|null|undefined|script|alert/.test(trimmedName.toLowerCase())) {
        return { isValid: false, error: 'Недопустимое имя пользователя' };
      }
      
      return { isValid: true };
    },

    // Валидация роли
    role: (role) => {
      const validRoles = ['USER', 'ADMIN', 'BOSS'];
      
      if (!role || !validRoles.includes(role)) {
        return { isValid: false, error: 'Некорректная роль пользователя' };
      }
      
      return { isValid: true };
    }
  },

  // Валидация задач
  task: {
    // Валидация заголовка
    title: (title) => {
      if (!title || typeof title !== 'string') {
        return { isValid: false, error: 'Заголовок задачи обязателен' };
      }
      
      const trimmedTitle = title.trim();
      
      if (trimmedTitle.length < 3) {
        return { isValid: false, error: 'Заголовок должен содержать минимум 3 символа' };
      }
      
      if (trimmedTitle.length > 200) {
        return { isValid: false, error: 'Заголовок слишком длинный (максимум 200 символов)' };
      }
      
      // Проверка на подозрительные символы
      if (/<script|javascript:|data:|vbscript:/i.test(trimmedTitle)) {
        return { isValid: false, error: 'Заголовок содержит недопустимые элементы' };
      }
      
      return { isValid: true };
    },

    // Валидация описания
    description: (description) => {
      if (description && typeof description !== 'string') {
        return { isValid: false, error: 'Описание должно быть строкой' };
      }
      
      if (description && description.length > 2000) {
        return { isValid: false, error: 'Описание слишком длинное (максимум 2000 символов)' };
      }
      
      // Проверка на подозрительные элементы
      if (description && /<script|javascript:|data:|vbscript:/i.test(description)) {
        return { isValid: false, error: 'Описание содержит недопустимые элементы' };
      }
      
      return { isValid: true };
    },

    // Валидация приоритета
    priority: (priority) => {
      const validPriorities = ['LOW', 'MEDIUM', 'HIGH'];
      
      if (!priority || !validPriorities.includes(priority)) {
        return { isValid: false, error: 'Некорректный приоритет задачи' };
      }
      
      return { isValid: true };
    },

    // Валидация статуса
    status: (status) => {
      const validStatuses = ['ASSIGNED', 'IN_PROGRESS', 'UNDER_REVIEW', 'COMPLETED', 'REVISION'];
      
      if (!status || !validStatuses.includes(status)) {
        return { isValid: false, error: 'Некорректный статус задачи' };
      }
      
      return { isValid: true };
    },

    // Валидация даты дедлайна
    deadline: (deadline) => {
      if (!deadline) {
        return { isValid: true }; // Дедлайн необязателен
      }
      
      const deadlineDate = new Date(deadline);
      
      if (isNaN(deadlineDate.getTime())) {
        return { isValid: false, error: 'Некорректная дата дедлайна' };
      }
      
      // Проверяем, что дедлайн не слишком далеко в будущем (максимум 5 лет)
      const maxDate = new Date();
      maxDate.setFullYear(maxDate.getFullYear() + 5);
      
      if (deadlineDate > maxDate) {
        return { isValid: false, error: 'Дедлайн слишком далеко в будущем' };
      }
      
      return { isValid: true };
    },
    
    // Валидация даты дедлайна для создания новой задачи
    deadlineForCreate: (deadline) => {
      if (!deadline) {
        return { isValid: true }; // Дедлайн необязателен
      }
      
      const deadlineDate = new Date(deadline);
      
      if (isNaN(deadlineDate.getTime())) {
        return { isValid: false, error: 'Некорректная дата дедлайна' };
      }
      
      // Проверяем, что дедлайн не в прошлом (только для новых задач)
      const now = new Date();
      if (deadlineDate < now) {
        return { isValid: false, error: 'Дедлайн не может быть в прошлом' };
      }
      
      // Проверяем, что дедлайн не слишком далеко в будущем (максимум 5 лет)
      const maxDate = new Date();
      maxDate.setFullYear(maxDate.getFullYear() + 5);
      
      if (deadlineDate > maxDate) {
        return { isValid: false, error: 'Дедлайн слишком далеко в будущем' };
      }
      
      return { isValid: true };
    },

    // Валидация ID исполнителя
    assigneeId: async (assigneeId) => {
      if (!assigneeId) {
        return { isValid: true }; // Исполнитель необязателен
      }
      
      if (typeof assigneeId !== 'string') {
        return { isValid: false, error: 'Некорректный ID исполнителя' };
      }
      
      try {
        const user = await prisma.user.findUnique({
          where: { id: assigneeId }
        });
        
        if (!user) {
          return { isValid: false, error: 'Пользователь не найден' };
        }
        
        return { isValid: true };
      } catch (error) {
        return { isValid: false, error: 'Ошибка проверки исполнителя' };
      }
    }
  },

  // Валидация файлов
  file: {
    // Валидация загружаемого файла
    upload: (file) => {
      if (!file) {
        return { isValid: false, error: 'Файл не выбран' };
      }
      
      // Проверка размера (максимум 10MB)
      const maxSize = 10 * 1024 * 1024;
      if (file.size > maxSize) {
        return { isValid: false, error: 'Файл слишком большой (максимум 10MB)' };
      }
      
      // Проверка типа файла
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
      const fileExtension = file.originalname.toLowerCase().substring(file.originalname.lastIndexOf('.'));
      const allowedExtensions = [
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg', '.tiff', '.ico',
        '.pdf', '.doc', '.docx', '.txt', '.rtf', '.odt',
        '.xls', '.xlsx', '.ods', '.csv',
        '.ppt', '.pptx', '.odp',
        '.zip', '.rar', '.7z', '.tar', '.gz'
      ];
      
      if (!allowedMimeTypes.includes(file.mimetype) && !allowedExtensions.includes(fileExtension)) {
        return { isValid: false, error: 'Недопустимый тип файла' };
      }
      
      // Проверка имени файла
      if (!file.originalname || file.originalname.length > 255) {
        return { isValid: false, error: 'Некорректное имя файла' };
      }
      
      // Проверка на подозрительные расширения
      const suspiciousExtensions = ['.exe', '.bat', '.cmd', '.scr', '.pif', '.com', '.vbs', '.jar', '.php', '.asp', '.jsp'];
      
      if (suspiciousExtensions.includes(fileExtension)) {
        return { isValid: false, error: 'Недопустимое расширение файла' };
      }
      
      // Проверка имени файла на подозрительные символы
      if (!/^[a-zA-Z0-9._\-\s()]+$/.test(file.originalname)) {
        return { isValid: false, error: 'Имя файла содержит недопустимые символы' };
      }
      
      return { isValid: true };
    }
  },

  // Общие валидаторы
  common: {
    // Валидация ID
    id: (id) => {
      if (!id) {
        return { isValid: false, error: 'ID обязателен' };
      }
      
      const numericId = parseInt(id);
      
      if (isNaN(numericId) || numericId <= 0) {
        return { isValid: false, error: 'Некорректный ID' };
      }
      
      if (numericId > Number.MAX_SAFE_INTEGER) {
        return { isValid: false, error: 'ID слишком большой' };
      }
      
      return { isValid: true };
    },

    // Валидация строки
    string: (value, minLength = 1, maxLength = 1000, fieldName = 'Поле') => {
      if (value === null || value === undefined) {
        return { isValid: false, error: `${fieldName} обязательно` };
      }
      
      if (typeof value !== 'string') {
        return { isValid: false, error: `${fieldName} должно быть строкой` };
      }
      
      if (value.length < minLength) {
        return { isValid: false, error: `${fieldName} должно содержать минимум ${minLength} символов` };
      }
      
      if (value.length > maxLength) {
        return { isValid: false, error: `${fieldName} слишком длинное (максимум ${maxLength} символов)` };
      }
      
      return { isValid: true };
    },

    // Валидация даты
    date: (date, fieldName = 'Дата') => {
      if (!date) {
        return { isValid: false, error: `${fieldName} обязательна` };
      }
      
      const dateObj = new Date(date);
      
      if (isNaN(dateObj.getTime())) {
        return { isValid: false, error: `Некорректная ${fieldName.toLowerCase()}` };
      }
      
      return { isValid: true };
    },

    // Валидация массива
    array: (arr, minLength = 0, maxLength = 100, fieldName = 'Массив') => {
      if (!Array.isArray(arr)) {
        return { isValid: false, error: `${fieldName} должен быть массивом` };
      }
      
      if (arr.length < minLength) {
        return { isValid: false, error: `${fieldName} должен содержать минимум ${minLength} элементов` };
      }
      
      if (arr.length > maxLength) {
        return { isValid: false, error: `${fieldName} содержит слишком много элементов (максимум ${maxLength})` };
      }
      
      return { isValid: true };
    }
  },

  // Комплексная валидация объектов
  validateObject: (obj, schema) => {
    const errors = [];
    
    for (const [field, rules] of Object.entries(schema)) {
      const value = obj[field];
      
      // Проверяем обязательные поля
      if (rules.required && (value === undefined || value === null || value === '')) {
        errors.push(`Поле '${field}' обязательно`);
        continue;
      }
      
      // Пропускаем валидацию для необязательных пустых полей
      if (!rules.required && (value === undefined || value === null || value === '')) {
        continue;
      }
      
      // Применяем валидаторы
      if (rules.validators) {
        for (const validator of rules.validators) {
          const result = validator(value);
          if (!result.isValid) {
            errors.push(`${field}: ${result.error}`);
            break;
          }
        }
      }
    }
    
    return {
      isValid: errors.length === 0,
      errors
    };
  }
};

module.exports = validators;