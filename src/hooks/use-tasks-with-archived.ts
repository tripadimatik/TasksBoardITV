import { useState, useEffect, useCallback } from 'react';
import { apiClient, Task } from '../lib/api';
import { useAuth } from '@/contexts/AuthContext';

export const useTasksWithArchived = () => {
  const [tasks, setTasks] = useState<Task[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const { user } = useAuth();

  const fetchTasksWithArchived = useCallback(async () => {
    if (!user) {
      setTasks([]);
      setLoading(false);
      return;
    }

    setLoading(true);
    setError(null);

    try {
      // Fetch tasks including archived ones for reports
      const tasksData = await apiClient.getTasks(true); // includeArchived = true
      
      // For reports, we want to show all tasks (including archived) for admins and bosses
      let filteredTasks = tasksData;
      if (user.role === 'USER') {
        // For regular users, show only their tasks (including archived)
        filteredTasks = tasksData.filter(task => task.assigneeId === user.id);
      }
      // For admins and bosses, show all tasks including archived
      
      setTasks(filteredTasks);
    } catch (error) {
      console.error('Error fetching tasks with archived:', error);
      setError('Ошибка при загрузке задач');
    } finally {
      setLoading(false);
    }
  }, [user]);

  useEffect(() => {
    if (user) {
      fetchTasksWithArchived();
    } else {
      setTasks([]);
      setLoading(false);
    }
  }, [user, fetchTasksWithArchived]);

  return {
    tasks,
    loading,
    error,
    refreshTasks: fetchTasksWithArchived
  };
};