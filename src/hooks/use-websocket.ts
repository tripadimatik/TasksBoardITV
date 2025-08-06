import { useEffect, useRef, useCallback } from 'react';
import { io, Socket } from 'socket.io-client';
import { useAuth } from '@/contexts/AuthContext';
import { Task } from '@/lib/api';
import { notificationSound } from '@/utils/notifications';

interface UserStatus {
  id: string;
  firstName: string;
  lastName: string;
  patronymic?: string;
  role: string;
  isOnline: boolean;
}

interface WebSocketEvents {
  task_created: (task: Task) => void;
  task_updated: (task: Task) => void;
  task_deleted: (data: { taskId: string }) => void;
  users_status_updated: (users: UserStatus[]) => void;
}

interface UseWebSocketProps {
  onTaskCreated?: (task: Task) => void;
  onTaskUpdated?: (task: Task) => void;
  onTaskDeleted?: (taskId: string) => void;
  onUsersStatusUpdated?: (users: UserStatus[]) => void;
}

export const useWebSocket = ({ onTaskCreated, onTaskUpdated, onTaskDeleted, onUsersStatusUpdated }: UseWebSocketProps = {}) => {
  const socketRef = useRef<Socket | null>(null);
  const { user } = useAuth();
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const heartbeatIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const isConnectedRef = useRef(false);
  const reconnectAttemptsRef = useRef(0);
  const maxReconnectAttempts = 10;
  const baseReconnectDelay = 1000; // 1 секунда
  const heartbeatInterval = 30000; // 30 секунд

  // Функция для запуска heartbeat
  const startHeartbeat = useCallback(() => {
    if (heartbeatIntervalRef.current) {
      clearInterval(heartbeatIntervalRef.current);
    }
    
    heartbeatIntervalRef.current = setInterval(() => {
      if (socketRef.current?.connected) {
        console.log('💓 Отправка heartbeat ping');
        socketRef.current.emit('ping');
      } else {
        console.log('⚠️ Соединение потеряно, попытка переподключения');
        // connect() будет вызван позже
      }
    }, heartbeatInterval);
  }, []);

  const stopHeartbeat = useCallback(() => {
    if (heartbeatIntervalRef.current) {
      clearInterval(heartbeatIntervalRef.current);
      heartbeatIntervalRef.current = null;
    }
  }, []);

  const connect = useCallback(() => {
    if (!user || socketRef.current?.connected) {
      return;
    }

    const token = localStorage.getItem('authToken');
    if (!token) {
      console.warn('⚠️ Нет токена для WebSocket соединения');
      return;
    }

    // Определяем URL сервера для WebSocket
    const serverUrl = import.meta.env.VITE_WS_URL || 'https://localhost:3002';
    
    console.log('🔌 Подключение к WebSocket:', serverUrl);
    
    socketRef.current = io(serverUrl, {
      transports: ['websocket', 'polling'],
      timeout: 20000,
      forceNew: true,
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000
    });

    const socket = socketRef.current;

    socket.on('connect', () => {
      console.log('✅ WebSocket подключен:', socket.id);
      isConnectedRef.current = true;
      reconnectAttemptsRef.current = 0; // Сбрасываем счетчик попыток при успешном подключении
      
      // Запускаем heartbeat
      startHeartbeat();
      
      // Аутентификация
      socket.emit('authenticate', token);
    });

    socket.on('authenticated', (data) => {
      console.log('✅ WebSocket аутентификация успешна:', data);
    });

    socket.on('authentication_error', (error) => {
      console.error('❌ Ошибка аутентификации WebSocket:', error);
    });

    socket.on('disconnect', (reason) => {
      console.log('🔌 WebSocket отключен:', reason);
      isConnectedRef.current = false;
      
      // Останавливаем heartbeat
      stopHeartbeat();
      
      // Автоматическое переподключение с экспоненциальной задержкой
      if (reason !== 'io client disconnect' && reconnectAttemptsRef.current < maxReconnectAttempts) {
        const delay = Math.min(baseReconnectDelay * Math.pow(2, reconnectAttemptsRef.current), 30000);
        console.log(`🔄 Переподключение через ${delay}ms (попытка ${reconnectAttemptsRef.current + 1}/${maxReconnectAttempts})`);
        
        reconnectTimeoutRef.current = setTimeout(() => {
          reconnectAttemptsRef.current++;
          connect();
        }, delay);
      } else if (reconnectAttemptsRef.current >= maxReconnectAttempts) {
        console.error('❌ Превышено максимальное количество попыток переподключения');
      }
    });

    // Обработчик pong ответа от сервера
    socket.on('pong', () => {
      console.log('💓 Получен pong от сервера');
    });

    socket.on('connect_error', (error) => {
      console.error('❌ Ошибка подключения WebSocket:', error);
      isConnectedRef.current = false;
      
      // Переподключение с экспоненциальной задержкой при ошибке
      if (reconnectAttemptsRef.current < maxReconnectAttempts) {
        const delay = Math.min(baseReconnectDelay * Math.pow(2, reconnectAttemptsRef.current), 30000);
        console.log(`🔄 Переподключение после ошибки через ${delay}ms (попытка ${reconnectAttemptsRef.current + 1}/${maxReconnectAttempts})`);
        
        reconnectTimeoutRef.current = setTimeout(() => {
          reconnectAttemptsRef.current++;
          connect();
        }, delay);
      } else {
        console.error('❌ Превышено максимальное количество попыток переподключения после ошибок');
      }
    });

    // Обработчики событий задач
    socket.on('task_created', (task: Task) => {
      console.log('📝 Получена новая задача:', task.title);
      
      // Уведомления и звуки обрабатываются в use-tasks.ts
      onTaskCreated?.(task);
    });

    socket.on('task_updated', (task: Task) => {
      console.log('📝 Обновлена задача:', task.title);
      onTaskUpdated?.(task);
    });

    socket.on('task_deleted', (data: { taskId: string }) => {
      console.log('🗑️ Удалена задача:', data.taskId);
      onTaskDeleted?.(data.taskId);
    });


    
    socket.on('users_status_updated', (users: UserStatus[]) => {
      console.log('👥 Обновлен статус пользователей:', users);
      onUsersStatusUpdated?.(users);
    });

  }, [user, onTaskCreated, onTaskUpdated, onTaskDeleted, onUsersStatusUpdated, startHeartbeat, stopHeartbeat]);

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    
    // Останавливаем heartbeat
    stopHeartbeat();
    
    if (socketRef.current) {
      console.log('🔌 Отключение WebSocket');
      socketRef.current.disconnect();
      socketRef.current = null;
      isConnectedRef.current = false;
    }
  }, [stopHeartbeat]);

  useEffect(() => {
    if (user) {
      connect();
    } else {
      disconnect();
    }

    return () => {
      disconnect();
    };
  }, [user, connect, disconnect]);

  const isConnected = () => {
    return isConnectedRef.current && socketRef.current?.connected;
  };

  const getConnectionStatus = () => {
    return {
      isConnected: isConnected(),
      reconnectAttempts: reconnectAttemptsRef.current,
      maxReconnectAttempts,
      socketId: socketRef.current?.id || null
    };
  };

  const forceReconnect = useCallback(() => {
    console.log('🔄 Принудительное переподключение WebSocket');
    reconnectAttemptsRef.current = 0;
    disconnect();
    setTimeout(() => connect(), 1000);
  }, [connect, disconnect]);

  return {
    isConnected,
    getConnectionStatus,
    connect,
    disconnect,
    forceReconnect
  };
};