import { useState, useEffect, useRef, useCallback } from 'react';
import { apiClient, Task, mapStatusFromRussian, mapPriorityFromRussian } from '../lib/api';
import { TaskStatus, TaskPriority, isRussianStatus, isRussianPriority } from '../lib/types';
import { useAuth } from '@/contexts/AuthContext';
import { notificationSound } from '../utils/notifications';

// Используем интерфейс Task из api.ts
export type { Task } from '../lib/api';

export const useTasks = () => {
  const [tasks, setTasks] = useState<Task[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const { user } = useAuth();
  const isUserInteracting = useRef(false);
  const refreshTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const previousTaskIds = useRef<Set<string>>(new Set());
  const lastFetchTime = useRef<number>(0);
  const pollIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const currentTasksRef = useRef<Task[]>([]);

  // Функция для проверки изменений в задачах и отправки уведомлений
  const checkForTaskChanges = useCallback((newTasks: Task[]) => {
    if (!user) return;

    const currentTaskIds = new Set(currentTasksRef.current.map(t => t.id));
    const newTaskIds = new Set(newTasks.map(t => t.id));

    // Проверяем новые задачи - используем previousTaskIds для более точного отслеживания
    newTasks.forEach(task => {
      // Проверяем, что задача действительно новая (не была в предыдущем состоянии)
      if (!previousTaskIds.current.has(task.id) && !currentTaskIds.has(task.id)) {
        console.log('🔄 Real-time: Новая задача обнаружена:', task.title);
        
        // Добавляем задачу в previousTaskIds, чтобы не воспроизводить звук повторно
        previousTaskIds.current.add(task.id);
        
        // Воспроизводим звук для новых задач (только для назначенного исполнителя)
        if (user.role === 'USER' && task.assigneeId === user.id) {
          notificationSound.playNewTaskSound();
          notificationSound.showNotification(
            'Новая задача',
            `Вам назначена задача: ${task.title}`
          );
        }
        
        // Для админов и боссов также показываем уведомления о новых задачах
        if ((user.role === 'ADMIN' || user.role === 'BOSS') && task.assigneeId !== user.id) {
          notificationSound.showNotification(
            'Новая задача создана',
            `Создана задача: ${task.title} для ${task.assigneeName}`
          );
        }
      }
    });

    // Обновляем previousTaskIds для следующей проверки
    previousTaskIds.current = new Set(newTasks.map(t => t.id));

    // Проверяем обновленные задачи
    newTasks.forEach(newTask => {
      const oldTask = currentTasksRef.current.find(t => t.id === newTask.id);
      if (oldTask && oldTask.status !== newTask.status) {
        console.log('🔄 Real-time: Задача обновлена:', newTask.title, 'Статус:', newTask.status);
        
        // Уведомления для разных статусов и ролей
        if (user) {
          // Для исполнителя - уведомления о его задачах
          if (newTask.assigneeId === user.id) {
            if (newTask.status === 'выполнено') {
              notificationSound.playSuccessSound();
              notificationSound.showNotification(
                'Задача завершена',
                `Задача "${newTask.title}" успешно завершена!`
              );
            } else if (newTask.status === 'доработка') {
              notificationSound.showNotification(
                'Задача возвращена на доработку',
                `Задача "${newTask.title}" требует доработки`
              );
            }
          }
          
          // Для админов и боссов - уведомления о всех изменениях
          if ((user.role === 'ADMIN' || user.role === 'BOSS') && newTask.assigneeId !== user.id) {
            if (newTask.status === 'в работе') {
              notificationSound.showNotification(
                'Задача взята в работу',
                `${newTask.assigneeName} взял в работу: ${newTask.title}`
              );
            } else if (newTask.status === 'на проверке') {
              notificationSound.showNotification(
                'Отчет загружен',
                `${newTask.assigneeName} загрузил отчет по задаче: ${newTask.title}`
              );
            }
          }
        }
      }
    });

    // Проверяем удаленные задачи
    currentTasksRef.current.forEach(task => {
      if (!newTaskIds.has(task.id)) {
        console.log('🔄 Real-time: Задача удалена:', task.id);
      }
    });
  }, [user]);

  const fetchTasks = useCallback(async (showLoading = true) => {
    if (!user) {
      setTasks([]);
      setLoading(false);
      return;
    }

    // Предотвращаем частые запросы (не чаще раза в секунду)
    const now = Date.now();
    if (now - lastFetchTime.current < 1000 && !showLoading) {
      return;
    }
    lastFetchTime.current = now;

    if (showLoading) {
      setLoading(true);
    }
    setError(null);

    try {
      const tasksData = await apiClient.getTasks();
      
      // Проверяем, что tasksData является массивом
      if (!Array.isArray(tasksData)) {
        console.error('❌ API вернул не массив:', tasksData);
        throw new Error('Некорректный формат данных от сервера');
      }
      
      // Фильтруем задачи в зависимости от роли пользователя
      let filteredTasks = tasksData;
      if (user.role === 'USER') {
        // Для обычных пользователей показываем только их задачи
        filteredTasks = tasksData.filter(task => task.assigneeId === user.id);
      }
      // Для админов и боссов показываем все задачи
      
      // Проверяем изменения для уведомлений только если это не первая загрузка
      if (!showLoading && currentTasksRef.current.length > 0) {
        checkForTaskChanges(filteredTasks);
      } else if (showLoading || currentTasksRef.current.length === 0) {
        // При первой загрузке просто инициализируем previousTaskIds без уведомлений
        previousTaskIds.current = new Set(filteredTasks.map(t => t.id));
      }
      
      currentTasksRef.current = filteredTasks;
      setTasks(filteredTasks);
    } catch (error) {
      console.error('Error fetching tasks:', error);
      setError('Ошибка при загрузке задач');
      // Устанавливаем пустой массив в случае ошибки
      currentTasksRef.current = [];
      setTasks([]);
    } finally {
      if (showLoading) {
        setLoading(false);
      }
    }
  }, [user, checkForTaskChanges]);

  // Функция для запуска real-time polling
  const startPolling = useCallback(() => {
    if (pollIntervalRef.current) {
      clearInterval(pollIntervalRef.current);
    }
    
    // Обновляем каждую секунду для максимально быстрых real-time обновлений
    pollIntervalRef.current = setInterval(() => {
    if (!isUserInteracting.current) {
        fetchTasks(false);
    }
}, 5000);
  }, []);

  // Функция для остановки polling
  const stopPolling = useCallback(() => {
    if (pollIntervalRef.current) {
      clearInterval(pollIntervalRef.current);
      pollIntervalRef.current = null;
    }
  }, []);

  const clearRefreshTimeout = useCallback(() => {
    if (refreshTimeoutRef.current) {
      clearTimeout(refreshTimeoutRef.current);
      refreshTimeoutRef.current = null;
    }
  }, []);

  // Функции для управления взаимодействием пользователя
  const pausePolling = useCallback(() => {
    isUserInteracting.current = true;
    clearRefreshTimeout();
  }, [clearRefreshTimeout]);

  const resumePolling = useCallback(() => {
    isUserInteracting.current = false;
  }, []);

  useEffect(() => {
    if (user) {
      // Сбрасываем previousTaskIds при смене пользователя
      previousTaskIds.current = new Set();
      fetchTasks(true); // Загрузка при входе
      startPolling(); // Запускаем real-time обновления
    } else {
      // Если пользователя нет, очищаем задачи, таймеры и previousTaskIds
      currentTasksRef.current = [];
      setTasks([]);
      previousTaskIds.current = new Set();
      clearRefreshTimeout();
      stopPolling();
    }

    // Очистка при размонтировании
    return () => {
      clearRefreshTimeout();
      stopPolling();
      currentTasksRef.current = [];
      previousTaskIds.current = new Set();
    };
  }, [user, fetchTasks, clearRefreshTimeout, startPolling, stopPolling]);

  const updateTask = useCallback(async (id: string, updates: Partial<Task>) => {
    try {
      console.log('🔄 Обновление задачи:', id, updates);
      
      // Оптимистичное обновление
      const updatedTasks = currentTasksRef.current.map(task => 
        task.id === id ? { ...task, ...updates } : task
      );
      currentTasksRef.current = updatedTasks;
      setTasks(updatedTasks);

      // Преобразуем русские значения в английские для API
      const apiUpdates = {
        ...updates,
        status: updates.status ? mapStatusFromRussian(updates.status as TaskStatus) : undefined,
        priority: updates.priority && typeof updates.priority === 'string' ? mapPriorityFromRussian(updates.priority as TaskPriority) : undefined
      };

      const updatedTask = await apiClient.updateTask(id, apiUpdates);
      
      console.log('✅ Задача успешно обновлена на сервере:', updatedTask.id);
      
      // Обновляем состояние с ответом от сервера
      const finalUpdatedTasks = currentTasksRef.current.map(task => 
        task.id === id ? updatedTask : task
      );
      currentTasksRef.current = finalUpdatedTasks;
      setTasks(finalUpdatedTasks);
      
      // Немедленно обновляем список задач для real-time эффекта
      setTimeout(() => fetchTasks(false), 100);
      
      return updatedTask;
    } catch (error) {
      console.error('❌ Ошибка при обновлении задачи:', error);
      // Откатываем оптимистичное обновление
      await fetchTasks(false);
      throw error;
    }
  }, [fetchTasks]);

  const createTask = useCallback(async (taskData: {
    title: string;
    description?: string;
    priority?: string;
    deadline?: string;
    assigneeId?: string;
    assigneeName?: string;
  }) => {
    try {
      console.log('🔄 Создание новой задачи:', taskData.title);
      
      // Преобразуем русские значения в английские для API
      const apiTaskData: typeof taskData & { priority?: string } = { ...taskData };
      
      if (taskData.priority && typeof taskData.priority === 'string') {
        apiTaskData.priority = mapPriorityFromRussian(taskData.priority as TaskPriority);
      }
      
      await apiClient.createTask(apiTaskData);
      
      console.log('✅ Задача успешно создана на сервере');
      // Немедленно обновляем список задач для real-time эффекта
      setTimeout(() => fetchTasks(false), 100);
      
      return true;
    } catch (error) {
      console.error('❌ Ошибка создания задачи:', error);
      return false;
    }
  }, [fetchTasks]);

  const deleteTask = useCallback(async (taskId: string) => {
    try {
      console.log('🔄 Удаление задачи:', taskId);
      
      await apiClient.deleteTask(taskId);
      
      console.log('✅ Задача успешно удалена с сервера');
      // Немедленно обновляем список задач для real-time эффекта
      setTimeout(() => fetchTasks(false), 100);
      
    } catch (error) {
      console.error('❌ Ошибка удаления задачи:', error);
      throw new Error('Ошибка при удалении задачи');
    }
  }, [fetchTasks]);

  const uploadTaskFile = useCallback(async (taskId: string, file?: File, comment?: string, textContent?: string) => {
    try {
      console.log('🔄 Загрузка отчета для задачи:', taskId);
      
      const result = await apiClient.uploadTaskFile(taskId, file, comment, textContent);
      
      console.log('✅ Отчет успешно загружен на сервер');
      // Немедленно обновляем список задач для real-time эффекта
      setTimeout(() => fetchTasks(false), 100);
      
      return result;
    } catch (error) {
      console.error('❌ Ошибка загрузки файла:', error);
      throw new Error('Ошибка при загрузке файла');
    }
  }, [fetchTasks]);

  return {
    tasks,
    loading,
    error,
    updateTask,
    createTask,
    deleteTask,
    uploadTaskFile,
    refreshTasks: () => fetchTasks(true),
    pausePolling,
    resumePolling,
    isWebSocketConnected: () => true, // Всегда возвращаем true для совместимости
    getWebSocketStatus: () => 'connected', // Всегда возвращаем connected
    reconnectWebSocket: () => {} // Пустая функция для совместимости
  };
};