import React, { useState, useCallback, useMemo } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Dialog } from "@/components/ui/dialog";
import { UserProfile } from '@/components/profile/UserProfile';
import { StatisticsDashboard } from '@/components/dashboard/StatisticsDashboard';
import { CreateTaskModal } from '@/components/tasks/CreateTaskModal';
import { KanbanBoard } from '@/components/tasks/KanbanBoard';
import { NotificationSettings } from '@/components/settings/NotificationSettings';
import CompletedTasksReport from '@/components/reports/CompletedTasksReport';
import { UserCircle, LogOut, Plus, BarChart3, CheckSquare, Clock, User, Bell, FileText } from 'lucide-react';
import { KazakhstanFlag } from '@/components/ui/kazakhstan-flag';
import { KazakhstanFooter } from '@/components/ui/kazakhstan-footer';
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/contexts/AuthContext";
import { useNavigate } from "react-router-dom";
import { useTasks } from '@/hooks/use-tasks';
import { useTasksWithArchived } from '@/hooks/use-tasks-with-archived';
import { useIsMobile } from '@/hooks/use-mobile';
import { useUsers } from '@/hooks/use-users';
import { Task } from '@/lib/api';

interface TaskData {
  title: string;
  description: string;
  priority: string;
  deadline: string;
  assigneeId: string;
  assigneeName: string;
}

type TaskUpdate = Partial<Task>;

const Index = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [currentView, setCurrentView] = useState('tasks');
  const [showCreateTask, setShowCreateTask] = useState(false);
  const [showProfile, setShowProfile] = useState(false);
  const { tasks, loading: tasksLoading, error: tasksError, updateTask, createTask, refreshTasks, uploadTaskFile, resumePolling } = useTasks();
  const { tasks: tasksWithArchived, loading: archivedLoading, error: archivedError, refreshTasks: refreshArchivedTasks } = useTasksWithArchived();
  const { refreshUsers } = useUsers();
  const { toast } = useToast();
  const isMobile = useIsMobile();
  
  // Вычисляем производные значения
  const fullName = user ? `${user.lastName} ${user.firstName}${user.patronymic ? ' ' + user.patronymic : ''}` : '';
  const isBoss = user?.role === 'BOSS';
  

  
  // Инициализируем статус пользователей для отображения онлайн/оффлайн
  

  const handleLogout = useCallback(async () => {
    try {
      console.log('Logging out user...');
      
      // Сначала показываем уведомление, чтобы пользователь видел, что процесс начался
      toast({
        title: "Выход из системы",
        description: "Пожалуйста, подождите..."
      });
      
      // Устанавливаем состояние загрузки, чтобы предотвратить дальнейшие запросы
      setCurrentView('loading');
      
      try {
        // Выходим из системы
        await logout();
        
        console.log('Redirecting to auth page...');
        
        toast({
          title: "До свидания!",
          description: "Вы вышли из системы"
        });
      } catch (innerError) {
        console.error('Error during logout:', innerError);
        toast({
          title: "Ошибка",
          description: "Не удалось выйти из системы",
          variant: "destructive"
        });
      }
    } catch (error) {
      console.error('Error during logout:', error);
      toast({
        title: "Ошибка",
        description: "Не удалось выйти из системы",
        variant: "destructive"
      });
    }
  }, [logout, toast]);

  const handleCreateTask = useCallback(async (taskData: TaskData) => {
    try {
      console.log('Creating task with data:', taskData);
      if (!taskData.title || !taskData.description || !taskData.priority || !taskData.deadline || !taskData.assigneeId) {
        console.error('Missing required fields in task data');
        toast({
          title: "Ошибка",
          description: "Пожалуйста, заполните все обязательные поля",
          variant: "destructive"
        });
        return false;
      }
      
      const success = await createTask(taskData);
      console.log('Task creation result:', success);
      
      if (success) {
        toast({
          title: "Задача создана",
          description: `Задача "${taskData.title}" назначена исполнителю`
        });
        setShowCreateTask(false);
        return true;
      } else {
        toast({
          title: "Ошибка",
          description: "Не удалось создать задачу",
          variant: "destructive"
        });
        return false;
      }
    } catch (error) {
      console.error('Error in handleCreateTask:', error);
      toast({
        title: "Ошибка",
        description: "Произошла ошибка при создании задачи",
        variant: "destructive"
      });
      return false;
    }
  }, [createTask, toast]);

  const handleUpdateTask = useCallback(async (taskId: string, updates: TaskUpdate) => {
    const success = await updateTask(taskId, updates);
    if (success) {
      toast({
        title: "Задача обновлена",
        description: "Статус задачи успешно изменен"
      });
    } else {
      toast({
        title: "Ошибка",
        description: "Не удалось обновить задачу",
        variant: "destructive"
      });
    }
  }, [updateTask, toast]);

  const handleUploadTaskFile = useCallback(async (taskId: string, file?: File, comment?: string, textContent?: string): Promise<void> => {
    await uploadTaskFile(taskId, file, comment, textContent);
  }, [uploadTaskFile]);

  // Если пользователь не аутентифицирован, ProtectedRoute перенаправит на страницу авторизации
  // Но добавим дополнительную проверку для уверенности
  if (!user) {
    // Перенаправляем на страницу авторизации
    navigate('/auth');
    return (
      <div className="min-h-screen flex flex-col items-center justify-center gap-4">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
        <p className="text-gray-600">Перенаправление на страницу входа...</p>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-blue-50 overflow-x-hidden flex flex-col animate-fade-in">
      <div className="relative w-full flex-1 flex flex-col">
      {/* Header */}
      <header className="bg-white shadow-sm border-b sticky top-0 z-10 animate-slide-in">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16 sm:h-18 lg:h-20">
            <div className="flex items-center space-x-3 sm:space-x-4 lg:space-x-6">
              {/* Флаг Казахстана */}
               <div className="flex items-center space-x-3">
                 <KazakhstanFlag className="h-5 w-8 sm:h-6 sm:w-10" showOrnament={!isMobile} />
               </div>
              <div>
                <h1 className={`${isMobile ? 'text-base' : 'text-lg sm:text-xl lg:text-2xl'} font-semibold text-gray-900`}>
                  {isMobile ? 'Управление' : 'Управление задачами'}
                </h1>
                <p className="text-xs text-sky-600 font-medium hidden sm:block">Республика Казахстан</p>
              </div>
            </div>
            <div className="flex items-center space-x-2 sm:space-x-3 lg:space-x-4">

              

              
              <Button
                variant="ghost"
                className="flex items-center space-x-2 px-3 sm:px-4 py-2 min-h-[48px] touch-manipulation"
                onClick={() => setShowProfile(true)}
              >
                <UserCircle className="h-6 w-6 sm:h-7 sm:w-7 text-gray-600" />
                {!isMobile && <span className="text-sm sm:text-base font-medium text-gray-700 whitespace-nowrap">{fullName}</span>}
                <Badge variant={isBoss ? "default" : "secondary"} className="text-xs sm:text-sm py-1 px-2 sm:px-3">
                  {isMobile ? (user?.role === 'BOSS' ? 'Рук.' : user?.role === 'ADMIN' ? 'Адм.' : 'Сотр.') : 
                   (user?.role === 'BOSS' ? 'Руководитель' : user?.role === 'ADMIN' ? 'Админ' : 'Сотрудник')}
                </Badge>
              </Button>
              <Button variant="ghost" size="sm" onClick={handleLogout} className="h-12 w-12 sm:h-14 sm:w-14 p-2 sm:p-3 min-h-[48px] touch-manipulation transition-all duration-200 transform hover:scale-105">
                <LogOut className="h-5 w-5 sm:h-6 sm:w-6" />
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 sm:py-6 lg:py-8 flex-1">
        {/* Navigation */}
        <div className="flex flex-col sm:flex-row justify-between items-stretch sm:items-center mb-6 sm:mb-8 lg:mb-10 gap-4 sm:gap-6">
          <div className="flex flex-wrap gap-2 sm:gap-3 animate-slide-in">
            <Button
              variant={currentView === 'tasks' ? 'default' : 'outline'}
              onClick={() => setCurrentView('tasks')}
              className="flex items-center justify-center space-x-2 h-12 sm:h-13 text-sm sm:text-base px-4 sm:px-6 min-w-[100px] sm:min-w-[120px] flex-1 sm:flex-none touch-manipulation transition-all duration-200 nav-item"
            >
              <CheckSquare className="h-5 w-5" />
              <span>Задачи</span>
            </Button>
            {isBoss && (
              <Button
                variant={currentView === 'statistics' ? 'default' : 'outline'}
                onClick={() => setCurrentView('statistics')}
                className="flex items-center justify-center space-x-2 h-12 sm:h-13 text-sm sm:text-base px-4 sm:px-6 min-w-[100px] sm:min-w-[120px] flex-1 sm:flex-none touch-manipulation transition-all duration-200 nav-item"
              >
                <BarChart3 className="h-5 w-5" />
                <span>Статистика</span>
              </Button>
            )}
            {isBoss && (
              <Button
                variant={currentView === 'reports' ? 'default' : 'outline'}
                onClick={() => setCurrentView('reports')}
                className="flex items-center justify-center space-x-2 h-12 sm:h-13 text-sm sm:text-base px-4 sm:px-6 min-w-[100px] sm:min-w-[120px] flex-1 sm:flex-none touch-manipulation"
              >
                <FileText className="h-5 w-5" />
                <span>Отчеты</span>
              </Button>
            )}
            <Button
              variant={currentView === 'notifications' ? 'default' : 'outline'}
              onClick={() => setCurrentView('notifications')}
              className="flex items-center justify-center space-x-2 h-12 sm:h-13 text-sm sm:text-base px-4 sm:px-6 min-w-[100px] sm:min-w-[120px] flex-1 sm:flex-none touch-manipulation"
            >
              <Bell className="h-5 w-5" />
              <span>Уведомления</span>
            </Button>

          </div>
          {isBoss && currentView === 'tasks' && (
            <Button 
              onClick={() => {
              console.log('Create task button clicked, setting showCreateTask to true');
              setShowCreateTask(true);
            }} 
            className="flex items-center justify-center space-x-2 h-12 sm:h-13 text-sm sm:text-base px-6 sm:px-8 w-full sm:w-auto min-h-[48px] touch-manipulation bg-sky-600 hover:bg-sky-700 text-white transition-all duration-200 hover:shadow-lg transform hover:-translate-y-0.5"
            >
              <Plus className="h-5 w-5" />
              <span>Создать задачу</span>
            </Button>
          )}
        </div>

        {/* Dashboard Content */}
        {currentView === 'tasks' && (
          <div className="space-y-8">
            {tasksLoading ? (
              <div className="flex justify-center py-12">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
              </div>
            ) : tasksError ? (
              <Card>
                <CardContent className="flex flex-col items-center justify-center py-12">
                  <h3 className="text-lg font-medium text-red-600 mb-2">Ошибка загрузки задач</h3>
                  <p className="text-gray-500 text-center">{tasksError}</p>
                </CardContent>
              </Card>
            ) : (
              <KanbanBoard 
                tasks={tasks} 
                userRole={user.role} 
                onUpdateTask={handleUpdateTask}
                uploadTaskFile={handleUploadTaskFile}
                onRefreshArchivedTasks={refreshArchivedTasks}
              />
            )}
          </div>
        )}

        {currentView === 'statistics' && isBoss && (
          <StatisticsDashboard tasks={tasksWithArchived} />
        )}

        {currentView === 'reports' && isBoss && (
          archivedLoading ? (
            <div className="flex justify-center py-12">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
            </div>
          ) : archivedError ? (
            <Card>
              <CardContent className="flex flex-col items-center justify-center py-12">
                <h3 className="text-lg font-medium text-red-600 mb-2">Ошибка загрузки отчетов</h3>
                <p className="text-gray-500 text-center">{archivedError}</p>
              </CardContent>
            </Card>
          ) : (
            <CompletedTasksReport tasks={tasksWithArchived} />
          )
        )}

        {currentView === 'notifications' && (
          <div className="flex justify-center w-full">
            <div className="w-full max-w-2xl">
              <NotificationSettings />
            </div>
          </div>
        )}



        {/* Modals */}
        {showCreateTask && (
        <Dialog open={showCreateTask} onOpenChange={(open) => {
          console.log('Dialog onOpenChange called with:', open);
          setShowCreateTask(open);
        }}>
          <CreateTaskModal 
            onClose={() => {
              console.log('CreateTaskModal onClose called');
              setShowCreateTask(false);
            }}
            onSubmit={handleCreateTask}
            onOpen={refreshUsers}
          />
        </Dialog>
      )}

        {showProfile && (
          <UserProfile
            user={user}
            onClose={() => setShowProfile(false)}
          />
        )}
        </main>
      </div>
      
      {/* Футер с национальным орнаментом */}
      <KazakhstanFooter />
    </div>
  );
};

export default Index;
