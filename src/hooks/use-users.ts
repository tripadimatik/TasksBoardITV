import { useState, useEffect, useCallback } from 'react';
import { apiClient, User, mapRoleFromRussian } from '../lib/api';
import { useAuth } from '@/contexts/AuthContext';

// Используем интерфейс User из api.ts
export type UserData = User;

export const useUsers = (role?: 'USER' | 'ADMIN' | 'BOSS') => {
  const [users, setUsers] = useState<UserData[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const { user: currentUser } = useAuth();

  const fetchUsers = useCallback(async () => {
    if (!currentUser) {
      setUsers([]);
      setLoading(false);
      return;
    }

    try {
      setLoading(true);
      setError(null);
      
      let apiRole: string | undefined;
      if (role) {
        apiRole = role;
      }
      
      const usersData = await apiClient.getUsers(apiRole);
      // Убеждаемся, что usersData является массивом
      if (Array.isArray(usersData)) {
        setUsers(usersData);
      } else {
        console.warn('API returned non-array users data:', usersData);
        setUsers([]);
      }
    } catch (err) {
      console.error('Error fetching users:', err);
      setError('Не удалось загрузить пользователей. Попробуйте позже.');
      setUsers([]); // Устанавливаем пустой массив при ошибке
    } finally {
      setLoading(false);
    }
  }, [currentUser, role]);

  useEffect(() => {
    fetchUsers();
  }, [fetchUsers]);

  return { users, loading, error, refreshUsers: fetchUsers };
};