
import React, { useState, useCallback, useMemo } from 'react';
import { useIsMobile } from '@/hooks/use-mobile';
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Calendar, Clock, User, AlertCircle, CheckCircle, Play, Upload, Download, Check, X, FileText, Eye, Trash2 } from 'lucide-react';
import { TaskFileUpload } from './TaskFileUpload';
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/contexts/AuthContext";
import { useTasks } from '@/hooks/use-tasks';
import { useNotifications } from '@/utils/notifications';
import { Task } from '@/lib/types';

import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";

interface TaskListProps {
  tasks: Task[];
  userRole: string;
  onUpdateTask: (taskId: string, updates: Partial<Task>) => void;
  uploadTaskFile?: (taskId: string, file?: File, comment?: string, textContent?: string) => Promise<void>;
}

export const TaskList: React.FC<TaskListProps> = ({ 
  tasks, 
  userRole, 
  onUpdateTask, 
  uploadTaskFile
}) => {
  const [uploadModalData, setUploadModalData] = useState<{taskId: string; isOpen: boolean} | null>(null);
  const [showTextReport, setShowTextReport] = useState<Task | null>(null);
  const { toast } = useToast();
  const { user } = useAuth();
  
  // Используем переданные функции или заглушки
  const safeUploadTaskFile = uploadTaskFile || (() => Promise.resolve());
  const { playSuccessSound, playNewTaskSound, showNotification } = useNotifications();

  // Функция для получения текстового содержимого отчета
  const getTextReportContent = (reportFile: { content?: string; url?: string; isTextReport?: boolean }): string => {
    try {
      // Если это текстовый отчет с полем content
      if (reportFile.content) {
        return reportFile.content;
      }
      
      // Если это старый формат с Base64 в url
      if (reportFile.url && typeof reportFile.url === 'string') {
        // Проверяем, является ли это data URL
        if (reportFile.url.startsWith('data:')) {
          const base64Part = reportFile.url.split(',')[1];
          if (!base64Part) {
            throw new Error('Неверный формат data URL');
          }
          
          // Декодируем base64 в бинарные данные
          const binaryString = atob(base64Part);
          
          // Преобразуем бинарную строку в Uint8Array
          const bytes = new Uint8Array(binaryString.length);
          for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
          }
          
          // Декодируем UTF-8
          const decoder = new TextDecoder('utf-8');
          return decoder.decode(bytes);
        }
      }
      
      throw new Error('Не найдено содержимое текстового отчета');
    } catch (error) {
      console.error('Ошибка получения текста отчета:', error);
      return 'Ошибка при получении содержимого отчета';
    }
  };

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'высокий': return 'destructive';
      case 'средний': return 'default';
      case 'низкий': return 'secondary';
      default: return 'secondary';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'назначено': return 'secondary';
      case 'в работе': return 'default';
      case 'на проверке': return 'outline';
      case 'выполнено': return 'outline';
      case 'доработка': return 'destructive';
      default: return 'secondary';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'назначено': return <Clock className="h-4 w-4" />;
      case 'в работе': return <Play className="h-4 w-4" />;
      case 'на проверке': return <Upload className="h-4 w-4" />;
      case 'выполнено': return <CheckCircle className="h-4 w-4" />;
      case 'доработка': return <AlertCircle className="h-4 w-4" />;
      default: return <Clock className="h-4 w-4" />;
    }
  };

  const handleTakeTask = (taskId: string) => {
    if (!user) return;
    
    // Обновляем статус и назначаем текущего пользователя исполнителем
    onUpdateTask(taskId, { 
      status: 'в работе',
      assigneeId: user.id,
      assigneeName: `${user.lastName} ${user.firstName}${user.patronymic ? ' ' + user.patronymic : ''}` 
    });
    
    toast({
      title: "Задача взята в работу",
      description: "Вы можете приступить к выполнению задачи"
    });
  };

  const handleUploadReport = async (taskId: string, fileOrText: File | string, comment?: string) => {
    try {
      // Показываем индикатор загрузки
      toast({
        title: "Загрузка отчета",
        description: "Отчет загружается на сервер..."
      });
      
      if (typeof fileOrText === 'string') {
        // Обрабатываем текстовый отчет через API
        await safeUploadTaskFile(taskId, undefined, comment, fileOrText);
      } else {
        // Обрабатываем файл через API
        await safeUploadTaskFile(taskId, fileOrText, comment);
      }
      
      // Статус задачи обновляется автоматически на сервере
      
      setUploadModalData(null);
      toast({
        title: "Отчёт загружен",
        description: "Задача отправлена на проверку начальнику"
      });
    } catch (error) {
      console.error('Error uploading report:', error);
      toast({
        title: "Ошибка загрузки",
        description: "Не удалось загрузить отчет",
        variant: "destructive"
      });
    }
  };

  const handleDownloadReport = async (task: Task) => {
    if (task.reportFile) {
      try {
        const isTextReport = task.reportFile.isTextReport;
        
        if (isTextReport) {
          // Для текстовых отчетов открываем модальное окно
          setShowTextReport(task);
          
          toast({
            title: "Отчет открыт",
            description: "Текстовый отчет открыт"
          });
        } else {
          // Для файлов используем правильный URL с сервера
          toast({
            title: "Подготовка к скачиванию",
            description: `Подготовка файла ${task.reportFile.name}`
          });
          
          // Формируем правильный URL для скачивания, используя ту же логику что и в api.ts
          const currentHost = window.location.hostname;
          const currentProtocol = window.location.protocol;
          
          let API_BASE_URL;
          if (currentProtocol === 'https:') {
            API_BASE_URL = `https://${currentHost}:3001/api`;
          } else if (currentHost !== 'localhost' && currentHost !== '127.0.0.1') {
            API_BASE_URL = `https://${currentHost}:3001/api`;
          } else if (import.meta.env.VITE_API_URL) {
            API_BASE_URL = import.meta.env.VITE_API_URL;
          } else {
            API_BASE_URL = 'https://localhost:3001/api';
          }
          
          const downloadUrl = `${API_BASE_URL}/tasks/${task.id}/download`;
          
          // Используем fetch для получения файла с правильными заголовками
          const response = await fetch(downloadUrl, {
            method: 'GET',
            headers: {
              'Authorization': `Bearer ${localStorage.getItem('authToken')}`
            }
          });
          
          if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
          }
          
          // Получаем blob из ответа
          const blob = await response.blob();
          
          // Создаем URL для blob и скачиваем
          const blobUrl = window.URL.createObjectURL(blob);
          const link = document.createElement('a');
          link.href = blobUrl;
          link.download = task.reportFile.name;
          document.body.appendChild(link);
          link.click();
          document.body.removeChild(link);
          
          // Освобождаем память
          window.URL.revokeObjectURL(blobUrl);
          
          toast({
            title: "Файл скачан",
            description: `Файл ${task.reportFile.name} успешно скачан`
          });
        }
      } catch (error) {
        console.error('Ошибка при скачивании отчета:', error);
        toast({
          title: "Ошибка скачивания",
          description: "Не удалось скачать отчет: " + (error instanceof Error ? error.message : 'Неизвестная ошибка'),
          variant: "destructive"
        });
      }
    }
  };

  const handleApproveTask = (taskId: string) => {
    onUpdateTask(taskId, { status: 'выполнено' });
    
    toast({
      title: "Задача принята",
      description: "Отчёт одобрен, задача завершена"
    });
  };

  const handleRejectTask = (taskId: string) => {
    onUpdateTask(taskId, { status: 'доработка' });
    
    toast({
      title: "Задача отклонена",
      description: "Задача возвращена исполнителю на доработку"
    });
  };

  const handleDeleteTask = useCallback(async (taskId: string) => {
    try {
      const { apiClient } = await import('@/lib/api');
      await apiClient.deleteTask(taskId);
      
      toast({
        title: "Задача удалена",
        description: "Задача была успешно удалена"
      });
      
      // Обновляем список задач, удаляя задачу из локального состояния
      window.location.reload();
    } catch (error) {
      console.error('Error deleting task:', error);
      toast({
        title: "Ошибка удаления",
        description: "Не удалось удалить задачу",
        variant: "destructive"
      });
    }
  }, [toast]);

  const isOverdue = (deadline: string) => {
    return new Date(deadline) < new Date();
  };

  // Используем хук для определения мобильного устройства
  const isMobile = useIsMobile();
  
  // Мемоизируем размеры иконок для предотвращения мерцания
  const iconSize = useMemo(() => isMobile ? 'h-3.5 w-3.5' : 'h-4 w-4', [isMobile]);

  // Фильтрация задач в зависимости от роли
  const { user: currentUser } = useAuth();
  
  // Изменяем фильтрацию задач
  const filteredTasks = userRole === 'USER' 
    ? tasks.filter(task => task.assigneeId === currentUser.id)
    : tasks;

  return (
    <div className="space-y-3 sm:space-y-4">
      {filteredTasks.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-8 sm:py-12">
            <CheckCircle className={`h-${isMobile ? '10' : '12'} w-${isMobile ? '10' : '12'} text-gray-400 mb-${isMobile ? '3' : '4'}`} />
            <h3 className={`text-${isMobile ? 'base' : 'lg'} font-medium text-gray-900 mb-2`}>Нет задач</h3>
            <p className="text-gray-500 text-center">
              {userRole === 'BOSS' || userRole === 'ADMIN' 
                ? 'Создайте первую задачу, нажав кнопку "Создать задачу"' 
                : 'Вам пока не назначены задачи'
              }
            </p>
          </CardContent>
        </Card>
      ) : (
        filteredTasks.map((task) => (
          <Card key={task.id} className={`overflow-hidden border-l-4 ${isMobile ? 'p-0' : ''} card-hover animate-fade-in`} style={{
            borderLeftColor: task.status === 'выполнено' ? '#10b981' : 
                           task.status === 'в работе' ? '#f59e0b' : 
                           task.status === 'на проверке' ? '#3b82f6' : 
                           task.status === 'доработка' ? '#ef4444' : '#6b7280'
          }}>
            <div className="absolute right-0 top-0 h-32 w-32 opacity-5 transform translate-x-8 -translate-y-8">
              {getStatusIcon(task.status)}
            </div>
            <CardHeader className={`pb-2 ${isMobile ? 'px-3 py-3' : ''}`}>
              <div className="flex flex-col gap-4">
                <div className="flex-1">
                  <div className="flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-3 mb-3">
                    <h3 className="font-semibold text-lg sm:text-xl text-gray-900 leading-tight select-none">
                      {task.title}
                      {isOverdue(task.deadline) && task.status !== 'выполнено' && (
                        <AlertCircle className="h-5 w-5 text-red-500 animate-pulse ml-2" />
                      )}
                    </h3>
                    <div className="flex flex-wrap gap-2">
                      <Badge variant={getPriorityColor(task.priority)} className="shadow-sm">
                        {task.priority}
                      </Badge>
                      <Badge variant={getStatusColor(task.status)} className="flex items-center gap-1 shadow-sm">
                        {getStatusIcon(task.status)}
                        {task.status}
                      </Badge>
                    </div>
                  </div>
                  <p className={`text-gray-600 text-${isMobile ? 'xs' : 'sm'} leading-relaxed select-none ${isMobile ? 'line-clamp-2' : ''}`}>{task.description}</p>
                  {task.reportFile && (
                    <div className="mt-3 p-3 bg-gradient-to-r from-blue-50 to-blue-100 rounded-lg border border-blue-200 shadow-sm">
                      <p className="text-xs text-blue-700 flex items-center gap-2">
                        <Upload className="h-4 w-4" />
                        Прикреплён файл: <span className="font-medium">{task.reportFile.name}</span>
                      </p>
                    </div>
                  )}
                </div>
              </div>
            </CardHeader>
            <CardContent className={isMobile ? 'px-3 py-3 pt-0' : ''}>
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div className="flex flex-col gap-3 text-sm text-gray-500 mb-4 select-none">
                  <div className="flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-4">
                    <span className="flex items-center gap-2">
                      <Calendar className="h-4 w-4 flex-shrink-0" />
                      <span>Срок: {new Date(task.deadline).toLocaleDateString('ru-RU')}</span>
                      {isOverdue(task.deadline) && task.status !== 'выполнено' && (
                        <span className="text-red-500 font-medium">(Просрочено)</span>
                      )}
                    </span>
                    <span className="flex items-center gap-2">
                      <User className="h-4 w-4 flex-shrink-0" />
                      <span>{task.assigneeName || 'Не назначено'}</span>
                    </span>
                  </div>
                  <div className="text-xs text-gray-400">
                    Создано: {new Date(task.createdAt).toLocaleDateString('ru-RU')}
                  </div>
                </div>
                
                {/* Action buttons for employee */}
                {userRole === 'USER' && (
                  <div className="flex flex-col sm:flex-row gap-2 sm:gap-3">
                    {task.status === 'назначено' && (
                      <Button 
                        size="sm" 
                        onClick={() => handleTakeTask(task.id)}
                        className="bg-blue-600 hover:bg-blue-700 text-white border-0 transition-all duration-200 hover:shadow-lg transform hover:-translate-y-0.5"
                      >
                        <Play className={`${iconSize} mr-1`} />
                        {isMobile ? "Взять" : "Взять в работу"}
                      </Button>
                    )}
                    {task.status === 'в работе' && (
                      <Button 
                        size="sm" 
                        variant="outline"
                        onClick={() => setUploadModalData({taskId: task.id, isOpen: true})}
                        className="flex items-center gap-1 border-blue-200 hover:border-blue-400 hover:bg-blue-50 transition-all duration-200 hover:shadow-lg transform hover:-translate-y-0.5"
                      >
                        <Upload className={`${iconSize} text-blue-500`} />
                        {isMobile ? "Загрузить" : "Загрузить отчет"}
                      </Button>
                    )}
                    {task.status === 'доработка' && (
                      <Button 
                        size="sm" 
                        variant="outline"
                        onClick={() => setUploadModalData({taskId: task.id, isOpen: true})}
                        className="flex items-center gap-1 border-amber-200 hover:border-amber-400 hover:bg-amber-50 transition-all duration-200 hover:shadow-lg transform hover:-translate-y-0.5"
                      >
                        <Upload className={`${iconSize} text-amber-500`} />
                        {isMobile ? "Исправить" : "Исправить отчет"}
                      </Button>
                    )}
                    {(task.status === 'на проверке' || task.status === 'выполнено') && task.reportFile && (
                      <Button 
                        size="sm" 
                        variant="outline"
                        onClick={() => handleDownloadReport(task)}
                        className="flex items-center gap-1 border-blue-200 hover:border-blue-400 hover:bg-blue-50"
                      >
                        {task.reportFile.isTextReport ? (
                          <>
                            <Eye className={`${iconSize} text-blue-500`} />
                            {isMobile ? "Просмотреть" : "Просмотреть отчет"}
                          </>
                        ) : (
                          <>
                            <Download className={`${iconSize} text-blue-500`} />
                            {isMobile ? "Скачать" : "Скачать отчет"}
                          </>
                        )}
                      </Button>
                    )}
                  </div>
                )}
                
                {/* Action buttons for boss */}
                {(userRole === 'BOSS' || userRole === 'ADMIN') && (
                  <div className={`flex flex-wrap gap-${isMobile ? '1' : '2'} ${isMobile ? 'mt-2' : ''}`}>
                    {task.status === 'на проверке' && task.reportFile && (
                      <>
                        <Button 
                          size="sm" 
                          variant="outline"
                          onClick={() => handleDownloadReport(task)}
                          className="flex items-center gap-1 border-blue-200 hover:border-blue-400 hover:bg-blue-50"
                        >
                          <Download className={`${iconSize} text-blue-500`} />
                          Скачать
                        </Button>
                        <Button 
                          size="sm" 
                          onClick={() => handleApproveTask(task.id)}
                          className="flex items-center gap-1 bg-green-600 hover:bg-green-700 text-white border-0 transition-all duration-200 hover:shadow-lg transform hover:-translate-y-0.5"
                        >
                          <Check className={iconSize} />
                          Принять
                        </Button>
                        <Button 
                          size="sm" 
                          onClick={() => handleRejectTask(task.id)}
                          className="flex items-center gap-1 bg-red-600 hover:bg-red-700 text-white border-0 transition-all duration-200 hover:shadow-lg transform hover:-translate-y-0.5"
                        >
                          <X className={iconSize} />
                          Отклонить
                        </Button>
                      </>
                    )}
                    {task.status === 'выполнено' && task.reportFile && (
                      <Button 
                        size="sm" 
                        variant="outline"
                        onClick={() => handleDownloadReport(task)}
                        className="flex items-center gap-1 border-green-200 hover:border-green-400 hover:bg-green-50"
                      >
                        <Download className={`${iconSize} text-green-500`} />
                         {isMobile ? "Скачать" : "Скачать отчет"}
                      </Button>
                    )}
                    {/* Кнопка удаления - только для админов и создателей задачи */}
                    {(userRole === 'ADMIN' || (user && task.createdBy === user.id)) && (
                      <Button 
                        size="sm" 
                        variant="outline"
                        onClick={() => handleDeleteTask(task.id)}
                        className="flex items-center gap-1 border-red-200 hover:border-red-300 hover:bg-red-50"
                      >
                        <Trash2 className={`${iconSize} text-red-500`} />
                        {isMobile ? "Удалить" : "Удалить задачу"}
                      </Button>
                    )}
                  </div>
                )}
              </div>
              

            </CardContent>
          </Card>
        ))
      )}

      {/* Global File Upload Modal */}
      {uploadModalData?.isOpen && (
        <Dialog open={uploadModalData.isOpen} onOpenChange={() => setUploadModalData(null)}>
          <DialogContent className="max-w-2xl">
            <DialogHeader>
              <DialogTitle>Загрузить отчет</DialogTitle>
              <DialogDescription>
                Загрузите файл или введите текстовый отчет для задачи
              </DialogDescription>
            </DialogHeader>
            <TaskFileUpload
               key={`stable-upload-${uploadModalData.taskId}`}
               onUpload={async (fileOrText) => {
                 try {
                   await handleUploadReport(uploadModalData.taskId, fileOrText);
                 } catch (error) {
                   console.error('Upload error:', error);
                   // Модал останется открытым при ошибке
                 }
               }}
               onCancel={() => setUploadModalData(null)}
             />
          </DialogContent>
        </Dialog>
      )}

      {/* Модальное окно для текстовых отчетов */}
       {showTextReport && showTextReport.reportFile && (
         <Dialog open={!!showTextReport} onOpenChange={() => setShowTextReport(null)}>
           <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
             <DialogHeader>
               <DialogTitle className="flex items-center gap-2">
                 <FileText className="h-5 w-5" />
                 Текстовый отчет по задаче "{showTextReport.title}"
               </DialogTitle>
               <DialogDescription>
                 Содержимое текстового отчета для задачи
               </DialogDescription>
             </DialogHeader>
             <div className="mt-4">
               <div className="bg-gray-50 p-4 rounded-lg border">
                  <pre className="whitespace-pre-wrap text-sm font-mono">
                    {showTextReport.reportFile?.isTextReport ? 
                      getTextReportContent(showTextReport.reportFile) : 
                      'Отчет недоступен'
                    }
                  </pre>
                </div>
             </div>
             <DialogFooter>
               <Button onClick={() => setShowTextReport(null)}>
                 Закрыть
               </Button>
             </DialogFooter>
           </DialogContent>
         </Dialog>
       )}
    </div>
  );
};
