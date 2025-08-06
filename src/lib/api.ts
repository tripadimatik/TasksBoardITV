// Определяем базовый URL API
const API_BASE_URL = (() => {
  const currentHost = window.location.hostname;
  const currentProtocol = window.location.protocol;
  
  // Логирование для отладки
  console.log('🔍 Определение API URL:');
  console.log('- Текущий хост:', currentHost);
  console.log('- Текущий протокол:', currentProtocol);
  console.log('- VITE_API_URL:', import.meta.env.VITE_API_URL);
  
  // Если фронтенд работает по HTTPS, используем HTTPS для API
  if (currentProtocol === 'https:') {
    const apiUrl = `https://${currentHost}:3002/api`;
    console.log('- Используем HTTPS для API:', apiUrl);
    return apiUrl;
  }
  
  // Если запрос идет с IP-адреса (не localhost), используем тот же IP для API с HTTP
  if (currentHost !== 'localhost' && currentHost !== '127.0.0.1') {
    const apiUrl = `http://${currentHost}:3001/api`;
    console.log('- Используем IP-адрес для API (HTTP):', apiUrl);
    return apiUrl;
  }
  
  // Если задан через переменную окружения, используем его
  if (import.meta.env.VITE_API_URL) {
    console.log('- Используем VITE_API_URL:', import.meta.env.VITE_API_URL);
    return import.meta.env.VITE_API_URL;
  }
  
  // По умолчанию используем localhost с HTTP
  const defaultUrl = 'http://localhost:3001/api';
  console.log('- Используем по умолчанию (HTTP):', defaultUrl);
  return defaultUrl;
})();

console.log('🌐 Итоговый API_BASE_URL:', API_BASE_URL);

import { TaskStatus, TaskPriority, UserRole, TaskStatusEn, TaskPriorityEn, UserRoleEn, TaskStatusRu, TaskPriorityRu, UserRoleRu, isRussianStatus, isRussianPriority } from './types';
import { 
  sanitizeHtml, 
  validateEmail, 
  validatePassword, 
  validateName, 
  sanitizeInput, 
  detectSuspiciousPatterns, 
  safeJsonParse, 
  isValidToken, 
  logSuspiciousActivity 
} from './security';

export interface User {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  patronymic?: string;
  role: UserRole;
  createdAt: string;
  updatedAt: string;
}

export interface Task {
  id: string;
  title: string;
  description: string;
  priority: TaskPriority;
  deadline: string | null;
  status: TaskStatus;
  assigneeId: string | null;
  assigneeName: string | null;
  createdBy: string | null;
  updatedBy: string | null;
  reportFile?: {
    name: string;
    url: string;
    uploadedAt: string;
    size?: number;
    comment?: string;
    isTextReport?: boolean;
    content?: string;
  } | null;
  archived?: boolean;
  createdAt: string;
  updatedAt: string;
  assignee?: User | null;
  creator?: User | null;
}

export interface AuthResponse {
  token: string;
  user: User;
}

class ApiClient {
  private getAuthHeaders(): HeadersInit {
    const token = localStorage.getItem('authToken');
    return {
      'Content-Type': 'application/json',
      ...(token && { Authorization: `Bearer ${token}` })
    };
  }

  private getFormDataHeaders(): HeadersInit {
    const token = localStorage.getItem('authToken');
    return {
      ...(token && { Authorization: `Bearer ${token}` })
    };
  }

  private async handleResponse<T>(response: Response): Promise<T> {
    console.log('🔄 Обработка ответа:', {
      status: response.status,
      statusText: response.statusText,
      url: response.url,
      ok: response.ok
    });
    
    if (!response.ok) {
      let errorData;
      try {
        errorData = await response.json();
        console.error('❌ Ошибка от сервера:', errorData);
      } catch (e) {
        errorData = { message: 'Неизвестная ошибка' };
        console.error('❌ Не удалось распарсить ошибку:', e);
      }
      // Проверяем и error, и message поля для получения детального сообщения
      const errorMessage = errorData.error || errorData.message || `HTTP error! status: ${response.status}`;
      throw new Error(errorMessage);
    }
    
    try {
      const data = await response.json();
      console.log('✅ Успешный ответ получен');
      return data;
    } catch (e) {
      console.error('❌ Ошибка парсинга JSON:', e);
      throw new Error('Ошибка обработки ответа сервера');
    }
  }

  // === AUTH METHODS ===

  async register(userData: {
    email: string;
    password: string;
    firstName: string;
    lastName: string;
    patronymic?: string;
    role?: string;
  }): Promise<AuthResponse> {
    console.log('📝 Попытка регистрации:', { email: userData.email, apiUrl: `${API_BASE_URL}/auth/register` });
    
    // Валидация входных данных
    if (!validateEmail(userData.email)) {
      throw new Error('Некорректный email адрес');
    }

    const passwordValidation = validatePassword(userData.password);
    if (!passwordValidation.isValid) {
      throw new Error(passwordValidation.error || 'Некорректный пароль');
    }

    const firstNameValidation = validateName(userData.firstName);
    if (!firstNameValidation.isValid) {
      throw new Error(firstNameValidation.error || 'Некорректное имя');
    }

    const lastNameValidation = validateName(userData.lastName);
    if (!lastNameValidation.isValid) {
      throw new Error(lastNameValidation.error || 'Некорректная фамилия');
    }

    // Проверка на подозрительные паттерны
    if (detectSuspiciousPatterns(userData.email) || 
        detectSuspiciousPatterns(userData.firstName) || 
        detectSuspiciousPatterns(userData.lastName) ||
        (userData.patronymic && detectSuspiciousPatterns(userData.patronymic))) {
      logSuspiciousActivity('Попытка регистрации с подозрительными данными', { email: userData.email });
      throw new Error('Обнаружены недопустимые символы в данных');
    }

    // Санитизация данных
    const sanitizedUserData = {
      email: sanitizeInput(userData.email.toLowerCase().trim(), 254),
      password: userData.password,
      firstName: sanitizeInput(userData.firstName.trim(), 50),
      lastName: sanitizeInput(userData.lastName.trim(), 50),
      patronymic: userData.patronymic ? sanitizeInput(userData.patronymic.trim(), 50) : undefined,
      role: userData.role
    };
    
    try {
      const response = await fetch(`${API_BASE_URL}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(sanitizedUserData)
      });
      
      console.log('📝 Ответ сервера на регистрацию:', response.status, response.statusText);
      
      const data = await this.handleResponse<AuthResponse>(response);
      
      // Валидация токена
      if (!isValidToken(data.token)) {
        logSuspiciousActivity('Получен некорректный токен при регистрации');
        throw new Error('Ошибка аутентификации');
      }
      
      return data;
    } catch (error) {
      console.error('❌ Ошибка при регистрации:', error);
      throw error;
    }
  }

  async login(email: string, password: string): Promise<AuthResponse> {
    console.log('🔐 Попытка входа:', { email, apiUrl: `${API_BASE_URL}/auth/login` });
    
    // Валидация входных данных
    if (!validateEmail(email)) {
      throw new Error('Некорректный email адрес');
    }

    if (!password || password.length < 1) {
      throw new Error('Пароль обязателен');
    }

    // Проверка на подозрительные паттерны
    if (detectSuspiciousPatterns(email)) {
      logSuspiciousActivity('Попытка входа с подозрительным email', { email });
      throw new Error('Обнаружены недопустимые символы в email');
    }

    // Санитизация email
    const sanitizedEmail = sanitizeInput(email.toLowerCase().trim(), 254);
    
    try {
      const response = await fetch(`${API_BASE_URL}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          email: sanitizedEmail, 
          password 
        })
      });
      
      console.log('🔐 Ответ сервера на вход:', response.status, response.statusText);
      
      const data = await this.handleResponse<AuthResponse>(response);
      
      // Валидация токена
      if (!isValidToken(data.token)) {
        logSuspiciousActivity('Получен некорректный токен при входе');
        throw new Error('Ошибка аутентификации');
      }
      
      return data;
    } catch (error) {
      console.error('❌ Ошибка при входе:', error);
      throw error;
    }
  }

  async getCurrentUser(): Promise<User> {
    const response = await fetch(`${API_BASE_URL}/auth/me`, {
      headers: this.getAuthHeaders()
    });
    
    return this.handleResponse<User>(response);
  }

  async updateUser(userId: string, userData: Partial<User>): Promise<User> {
    console.log('👤 Обновление пользователя:', { userId, userData });
    
    // Валидация ID пользователя
    if (!userId || typeof userId !== 'string' || userId.trim().length === 0) {
      throw new Error('ID пользователя обязателен');
    }
    
    // Валидация обновляемых данных
    if (userData.email !== undefined) {
      if (!validateEmail(userData.email)) {
        throw new Error('Некорректный email адрес');
      }
      
      if (detectSuspiciousPatterns(userData.email)) {
        logSuspiciousActivity('Попытка обновления пользователя с подозрительным email', { userId, email: userData.email });
        throw new Error('Обнаружены недопустимые символы в email');
      }
    }
    
    if (userData.firstName !== undefined) {
      const firstNameValidation = validateName(userData.firstName);
      if (!firstNameValidation.isValid) {
        throw new Error(firstNameValidation.error || 'Некорректное имя');
      }
      
      if (detectSuspiciousPatterns(userData.firstName)) {
        logSuspiciousActivity('Попытка обновления пользователя с подозрительным именем', { userId });
        throw new Error('Обнаружены недопустимые символы в имени');
      }
    }
    
    if (userData.lastName !== undefined) {
      const lastNameValidation = validateName(userData.lastName);
      if (!lastNameValidation.isValid) {
        throw new Error(lastNameValidation.error || 'Некорректная фамилия');
      }
      
      if (detectSuspiciousPatterns(userData.lastName)) {
        logSuspiciousActivity('Попытка обновления пользователя с подозрительной фамилией', { userId });
        throw new Error('Обнаружены недопустимые символы в фамилии');
      }
    }
    
    if (userData.patronymic !== undefined && userData.patronymic !== null) {
      const patronymicValidation = validateName(userData.patronymic);
      if (!patronymicValidation.isValid) {
        throw new Error(patronymicValidation.error || 'Некорректное отчество');
      }
      
      if (detectSuspiciousPatterns(userData.patronymic)) {
        logSuspiciousActivity('Попытка обновления пользователя с подозрительным отчеством', { userId });
        throw new Error('Обнаружены недопустимые символы в отчестве');
      }
    }
    
    // Санитизация данных
    const sanitizedUserData = { ...userData };
    if (userData.email !== undefined) {
      sanitizedUserData.email = sanitizeInput(userData.email.toLowerCase().trim(), 254);
    }
    if (userData.firstName !== undefined) {
      sanitizedUserData.firstName = sanitizeInput(userData.firstName.trim(), 50);
    }
    if (userData.lastName !== undefined) {
      sanitizedUserData.lastName = sanitizeInput(userData.lastName.trim(), 50);
    }
    if (userData.patronymic !== undefined && userData.patronymic !== null) {
      sanitizedUserData.patronymic = sanitizeInput(userData.patronymic.trim(), 50);
    }
    
    try {
      const response = await fetch(`${API_BASE_URL}/users/${encodeURIComponent(userId)}`, {
        method: 'PUT',
        headers: this.getAuthHeaders(),
        body: JSON.stringify(sanitizedUserData)
      });
      
      console.log('👤 Ответ сервера на обновление пользователя:', response.status, response.statusText);
      
      return this.handleResponse<User>(response);
    } catch (error) {
      console.error('❌ Ошибка при обновлении пользователя:', error);
      throw error;
    }
  }

  // === USER METHODS ===

  async getUsers(role?: string): Promise<User[]> {
    const url = new URL(`${API_BASE_URL}/users`);
    if (role) {
      url.searchParams.append('role', role);
    }
    
    const response = await fetch(url.toString(), {
      headers: this.getAuthHeaders()
    });
    
    const data = await this.handleResponse<{ users: User[]; pagination?: any }>(response);
    return data.users || [];
  }

  // === TASK METHODS ===

  async getTasks(includeArchived: boolean = false): Promise<Task[]> {
    const url = new URL(`${API_BASE_URL}/tasks`);
    if (includeArchived) {
      url.searchParams.append('includeArchived', 'true');
    }
    
    const response = await fetch(url.toString(), {
      headers: this.getAuthHeaders()
    });
    
    const data = await this.handleResponse<{ tasks: Task[]; pagination?: any }>(response);
    return data.tasks || [];
  }

  async createTask(taskData: {
    title: string;
    description?: string;
    priority?: string;
    deadline?: string;
    assigneeId?: string;
    assigneeName?: string;
  }): Promise<Task> {
    console.log('📝 Создание задачи:', taskData);
    
    // Валидация данных задачи
    if (!taskData.title || taskData.title.trim().length === 0) {
      throw new Error('Название задачи обязательно');
    }
    
    if (taskData.title.length > 200) {
      throw new Error('Название задачи слишком длинное (максимум 200 символов)');
    }
    
    if (taskData.description && taskData.description.length > 2000) {
      throw new Error('Описание задачи слишком длинное (максимум 2000 символов)');
    }
    
    // Проверка на подозрительные паттерны
    if (detectSuspiciousPatterns(taskData.title) || 
        (taskData.description && detectSuspiciousPatterns(taskData.description))) {
      logSuspiciousActivity('Попытка создания задачи с подозрительными данными', { title: taskData.title });
      throw new Error('Обнаружены недопустимые символы в данных задачи');
    }
    
    // Санитизация данных
    const sanitizedTaskData = {
      ...taskData,
      title: sanitizeInput(taskData.title.trim(), 200),
      description: taskData.description ? sanitizeInput(taskData.description.trim(), 2000) : taskData.description
    };
    
    try {
      const response = await fetch(`${API_BASE_URL}/tasks`, {
        method: 'POST',
        headers: this.getAuthHeaders(),
        body: JSON.stringify(sanitizedTaskData)
      });
      
      console.log('📝 Ответ сервера на создание задачи:', response.status, response.statusText);
      
      return this.handleResponse<Task>(response);
    } catch (error) {
      console.error('❌ Ошибка при создании задачи:', error);
      throw error;
    }
  }

  async updateTask(taskId: string, updates: Partial<Task>): Promise<Task> {
    console.log('📝 Обновление задачи:', { taskId, updates });
    
    // Валидация ID задачи
    if (!taskId || typeof taskId !== 'string' || taskId.trim().length === 0) {
      throw new Error('ID задачи обязателен');
    }
    
    // Валидация обновляемых данных
    if (updates.title !== undefined) {
      if (!updates.title || updates.title.trim().length === 0) {
        throw new Error('Название задачи не может быть пустым');
      }
      
      if (updates.title.length > 200) {
        throw new Error('Название задачи слишком длинное (максимум 200 символов)');
      }
      
      if (detectSuspiciousPatterns(updates.title)) {
        logSuspiciousActivity('Попытка обновления задачи с подозрительным названием', { taskId, title: updates.title });
        throw new Error('Обнаружены недопустимые символы в названии задачи');
      }
    }
    
    if (updates.description !== undefined && updates.description !== null) {
      if (updates.description.length > 2000) {
        throw new Error('Описание задачи слишком длинное (максимум 2000 символов)');
      }
      
      if (detectSuspiciousPatterns(updates.description)) {
        logSuspiciousActivity('Попытка обновления задачи с подозрительным описанием', { taskId });
        throw new Error('Обнаружены недопустимые символы в описании задачи');
      }
    }
    
    // Валидация deadline
    if (updates.deadline !== undefined) {
      if (updates.deadline !== null && updates.deadline !== '') {
        const deadlineDate = new Date(updates.deadline);
        if (isNaN(deadlineDate.getTime())) {
          throw new Error('Неверный формат даты дедлайна');
        }
      }
    }
    
    // Санитизация данных
    const sanitizedUpdates = { ...updates };
    if (updates.title !== undefined) {
      sanitizedUpdates.title = sanitizeInput(updates.title.trim(), 200);
    }
    if (updates.description !== undefined && updates.description !== null) {
      sanitizedUpdates.description = sanitizeInput(updates.description.trim(), 2000);
    }
    if (updates.deadline !== undefined) {
      // Оставляем deadline как есть, если он валидный
      sanitizedUpdates.deadline = updates.deadline;
    }
    
    try {
      const response = await fetch(`${API_BASE_URL}/tasks/${encodeURIComponent(taskId)}`, {
        method: 'PUT',
        headers: this.getAuthHeaders(),
        body: JSON.stringify(sanitizedUpdates)
      });
      
      console.log('📝 Ответ сервера на обновление задачи:', response.status, response.statusText);
      
      return this.handleResponse<Task>(response);
    } catch (error) {
      console.error('❌ Ошибка при обновлении задачи:', error);
      throw error;
    }
  }

  async deleteTask(taskId: string): Promise<{ message: string }> {
    const response = await fetch(`${API_BASE_URL}/tasks/${taskId}`, {
      method: 'DELETE',
      headers: this.getAuthHeaders()
    });
    
    return this.handleResponse<{ message: string }>(response);
  }

  async archiveTask(taskId: string): Promise<Task> {
    const response = await fetch(`${API_BASE_URL}/tasks/${taskId}/archive`, {
      method: 'PUT',
      headers: this.getAuthHeaders()
    });
    
    return this.handleResponse<Task>(response);
  }

  async uploadTaskFile(taskId: string, file?: File, comment?: string, textContent?: string): Promise<{ task: Task; fileUrl: string }> {
    const formData = new FormData();
    
    if (textContent) {
      // Текстовый отчет
      formData.append('reportType', 'text');
      formData.append('textContent', textContent);
    } else if (file) {
      // Файловый отчет
      formData.append('reportType', 'file');
      formData.append('file', file);
    } else {
      throw new Error('Необходимо предоставить либо файл, либо текстовый контент');
    }
    
    if (comment) {
      formData.append('comment', comment);
    }
    
    const response = await fetch(`${API_BASE_URL}/tasks/${taskId}/upload`, {
      method: 'POST',
      headers: this.getFormDataHeaders(),
      body: formData
    });
    
    return this.handleResponse<{ task: Task; fileUrl: string }>(response);
  }

  // === UTILITY METHODS ===

  setAuthToken(token: string): void {
    localStorage.setItem('authToken', token);
  }

  removeAuthToken(): void {
    localStorage.removeItem('authToken');
  }

  getAuthToken(): string | null {
    return localStorage.getItem('authToken');
  }

  isAuthenticated(): boolean {
    return !!this.getAuthToken();
  }
}

export const apiClient = new ApiClient();

// Утилиты для преобразования данных с улучшенной типизацией
export const mapStatusToRussian = (status: TaskStatusEn): TaskStatusRu => {
  const statusMap: Record<TaskStatusEn, TaskStatusRu> = {
    'ASSIGNED': 'назначено',
    'IN_PROGRESS': 'в работе',
    'UNDER_REVIEW': 'на проверке',
    'COMPLETED': 'выполнено',
    'REVISION': 'доработка'
  };
  return statusMap[status];
};

export const mapStatusFromRussian = (status: TaskStatus): TaskStatusEn => {
  if (isRussianStatus(status)) {
    const statusMap: Record<TaskStatusRu, TaskStatusEn> = {
      'назначено': 'ASSIGNED',
      'в работе': 'IN_PROGRESS',
      'на проверке': 'UNDER_REVIEW',
      'выполнено': 'COMPLETED',
      'доработка': 'REVISION'
    };
    return statusMap[status];
  }
  return status as TaskStatusEn;
};

export const mapPriorityToRussian = (priority: TaskPriorityEn): TaskPriorityRu => {
  const priorityMap: Record<TaskPriorityEn, TaskPriorityRu> = {
    'LOW': 'низкий',
    'MEDIUM': 'средний',
    'HIGH': 'высокий'
  };
  return priorityMap[priority];
};

export const mapPriorityFromRussian = (priority: TaskPriority): TaskPriorityEn => {
  if (isRussianPriority(priority)) {
    const priorityMap: Record<TaskPriorityRu, TaskPriorityEn> = {
      'низкий': 'LOW',
      'средний': 'MEDIUM',
      'высокий': 'HIGH'
    };
    return priorityMap[priority];
  }
  return priority as TaskPriorityEn;
};

export const mapRoleToRussian = (role: UserRoleEn): UserRoleRu => {
  const roleMap: Record<UserRoleEn, UserRoleRu> = {
    'USER': 'пользователь',
    'ADMIN': 'администратор',
    'BOSS': 'руководитель'
  };
  return roleMap[role];
};

export const mapRoleFromRussian = (role: UserRole): UserRoleEn => {
  const roleMap: Record<string, UserRoleEn> = {
    'пользователь': 'USER',
    'администратор': 'ADMIN',
    'руководитель': 'BOSS'
  };
  return roleMap[role as string] || role as UserRoleEn;
};