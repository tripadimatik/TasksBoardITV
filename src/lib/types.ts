// Английские типы (для API)
export type TaskStatusEn = 'ASSIGNED' | 'IN_PROGRESS' | 'UNDER_REVIEW' | 'COMPLETED' | 'REVISION';
export type TaskPriorityEn = 'LOW' | 'MEDIUM' | 'HIGH';
export type UserRoleEn = 'USER' | 'ADMIN' | 'BOSS';

// Русские типы (для UI)
export type TaskStatusRu = 'назначено' | 'в работе' | 'на проверке' | 'выполнено' | 'доработка';
export type TaskPriorityRu = 'низкий' | 'средний' | 'высокий';
export type UserRoleRu = 'пользователь' | 'администратор' | 'руководитель';

// Объединенные типы для гибкости
export type TaskStatus = TaskStatusEn | TaskStatusRu;
export type TaskPriority = TaskPriorityEn | TaskPriorityRu;
export type UserRole = UserRoleEn | UserRoleRu;

// Расширенный интерфейс Task с поддержкой русских значений
export interface TaskWithRussian {
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
  assignee?: {
    id: string;
    email: string;
    firstName: string;
    lastName: string;
    patronymic?: string;
    role: UserRole;
    createdAt: string;
    updatedAt: string;
  } | null;
  creator?: {
    id: string;
    email: string;
    firstName: string;
    lastName: string;
    patronymic?: string;
    role: UserRole;
    createdAt: string;
    updatedAt: string;
  } | null;
}

// Утилиты для проверки типов
export const isRussianStatus = (status: string): status is TaskStatusRu => {
  return ['назначено', 'в работе', 'на проверке', 'выполнено', 'доработка'].includes(status);
};

export const isEnglishStatus = (status: string): status is TaskStatusEn => {
  return ['ASSIGNED', 'IN_PROGRESS', 'UNDER_REVIEW', 'COMPLETED', 'REVISION'].includes(status);
};

export const isRussianPriority = (priority: string): priority is TaskPriorityRu => {
  return ['низкий', 'средний', 'высокий'].includes(priority);
};

export const isEnglishPriority = (priority: string): priority is TaskPriorityEn => {
  return ['LOW', 'MEDIUM', 'HIGH'].includes(priority);
};

export const isRussianRole = (role: string): role is UserRoleRu => {
  return ['пользователь', 'администратор', 'руководитель'].includes(role);
};

export const isEnglishRole = (role: string): role is UserRoleEn => {
  return ['USER', 'ADMIN', 'BOSS'].includes(role);
};

// Экспорт Task как алиас для TaskWithRussian для обратной совместимости
export type Task = TaskWithRussian;