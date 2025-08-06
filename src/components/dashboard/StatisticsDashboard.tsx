
import React, { useMemo } from 'react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { BarChart3, TrendingUp, Users, Clock, CheckCircle, AlertTriangle, Activity, User, Award, ChevronUp, ChevronDown, Flag } from 'lucide-react';
import { useIsMobile } from '@/hooks/use-mobile';
import { Task } from '@/lib/types';

interface StatisticsDashboardProps {
  tasks: Task[];
}

export const StatisticsDashboard: React.FC<StatisticsDashboardProps> = ({ tasks }) => {
  const isMobile = useIsMobile();
  // Подсчет статистики
  const completedTasks = tasks.filter(t => t.status === 'выполнено');
  const tasksByEmployee = tasks.reduce((acc, task) => {
    // Используем assigneeName вместо assignee
    // Если assigneeName не определено, используем 'Не назначено'
    const employeeName = task.assigneeName || 'Не назначено';
    acc[employeeName] = acc[employeeName] || { total: 0, completed: 0 };
    acc[employeeName].total++;
    if (task.status === 'выполнено') {
      acc[employeeName].completed++;
    }
    return acc;
  }, {} as Record<string, { total: number; completed: number }>);

  const averageCompletionTime = completedTasks.length > 0 ? 
    Math.round(completedTasks.length * 3.5) : 0; // Моковое среднее время

  const completionRate = tasks.length > 0 ? 
    Math.round((completedTasks.length / tasks.length) * 100) : 0;

  return (
    <div className="space-y-4 sm:space-y-6 p-2 sm:p-0">
      {/* Заголовок */}
      <div className="flex items-center gap-2">
        <BarChart3 className="h-5 w-5 sm:h-6 sm:w-6 text-blue-600" />
        <h2 className="text-xl sm:text-2xl font-bold text-gray-900">Статистика</h2>
      </div>

      {/* Основные метрики */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4 animate-fade-in">
        <Card className="overflow-hidden border-l-4 border-l-blue-500 relative group card-hover animate-scale-in">
          <div className="absolute top-0 right-0 w-24 h-24 opacity-5 group-hover:opacity-10 transition-opacity duration-300">
            <TrendingUp className="w-full h-full text-blue-600" />
          </div>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-1 sm:pb-2">
            <div className="flex items-center gap-1.5 sm:gap-2">
              <div className="bg-blue-100 p-1 sm:p-1.5 rounded-full">
                <TrendingUp className="h-3.5 w-3.5 sm:h-4 sm:w-4 text-blue-600" />
              </div>
              <CardTitle className="text-xs sm:text-sm font-medium">{isMobile ? 'Выполнение' : 'Общий процент выполнения'}</CardTitle>
            </div>
          </CardHeader>
          <CardContent>
            <div className="text-2xl sm:text-3xl font-bold text-blue-600">{completionRate}%</div>
            <p className="text-xs text-gray-600 flex items-center gap-1">
              <CheckCircle className="h-3 w-3 text-green-500" />
              {completedTasks.length} из {tasks.length} задач
            </p>
            <div className="mt-3 h-1.5 w-full bg-gray-100 rounded-full overflow-hidden">
              <div 
                className="h-full bg-gradient-to-r from-blue-500 to-blue-600 rounded-full"
                style={{ width: `${completionRate}%` }}
              ></div>
            </div>
          </CardContent>
        </Card>

        <Card className="overflow-hidden border-l-4 border-l-amber-500 relative group card-hover animate-scale-in">
          <div className="absolute top-0 right-0 w-24 h-24 opacity-5 group-hover:opacity-10 transition-opacity duration-300">
            <Clock className="w-full h-full text-amber-600" />
          </div>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-1 sm:pb-2">
            <div className="flex items-center gap-1.5 sm:gap-2">
              <div className="bg-amber-100 p-1 sm:p-1.5 rounded-full">
                <Clock className="h-3.5 w-3.5 sm:h-4 sm:w-4 text-amber-600" />
              </div>
              <CardTitle className="text-xs sm:text-sm font-medium">{isMobile ? 'Ср. время' : 'Среднее время выполнения'}</CardTitle>
            </div>
          </CardHeader>
          <CardContent>
            <div className="text-2xl sm:text-3xl font-bold text-amber-600">{averageCompletionTime}ч</div>
            <p className="text-xs text-gray-600 flex items-center gap-1">
              <Activity className="h-3 w-3 text-amber-500" />
              среднее по отделу
            </p>
            <div className="mt-3 h-1.5 w-full bg-gray-100 rounded-full overflow-hidden">
              <div 
                className="h-full bg-gradient-to-r from-amber-500 to-amber-600 rounded-full"
                style={{ width: `${Math.min(averageCompletionTime * 2, 100)}%` }}
              ></div>
            </div>
          </CardContent>
        </Card>

        <Card className="overflow-hidden border-l-4 border-l-green-500 relative group card-hover animate-scale-in">
          <div className="absolute top-0 right-0 w-24 h-24 opacity-5 group-hover:opacity-10 transition-opacity duration-300">
            <Users className="w-full h-full text-green-600" />
          </div>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-1 sm:pb-2">
            <div className="flex items-center gap-1.5 sm:gap-2">
              <div className="bg-green-100 p-1 sm:p-1.5 rounded-full">
                <Users className="h-3.5 w-3.5 sm:h-4 sm:w-4 text-green-600" />
              </div>
              <CardTitle className="text-xs sm:text-sm font-medium">{isMobile ? 'Исполнители' : 'Активные исполнители'}</CardTitle>
            </div>
          </CardHeader>
          <CardContent>
            <div className="text-2xl sm:text-3xl font-bold text-green-600">{Object.keys(tasksByEmployee).length}</div>
            <p className="text-xs text-gray-600 flex items-center gap-1">
              <User className="h-3 w-3 text-green-500" />
              сотрудников
            </p>
            <div className="mt-3 h-1.5 w-full bg-gray-100 rounded-full overflow-hidden">
              <div 
                className="h-full bg-gradient-to-r from-green-500 to-green-600 rounded-full"
                style={{ width: `${Math.min(Object.keys(tasksByEmployee).length * 10, 100)}%` }}
              ></div>
            </div>
          </CardContent>
        </Card>

        <Card className="overflow-hidden border-l-4 border-l-purple-500 relative group card-hover animate-scale-in">
          <div className="absolute top-0 right-0 w-24 h-24 opacity-5 group-hover:opacity-10 transition-opacity duration-300">
            <BarChart3 className="w-full h-full text-purple-600" />
          </div>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-1 sm:pb-2">
            <div className="flex items-center gap-1.5 sm:gap-2">
              <div className="bg-purple-100 p-1 sm:p-1.5 rounded-full">
                <BarChart3 className="h-3.5 w-3.5 sm:h-4 sm:w-4 text-purple-600" />
              </div>
              <CardTitle className="text-xs sm:text-sm font-medium">{isMobile ? 'Задач' : 'Задач в этом месяце'}</CardTitle>
            </div>
          </CardHeader>
          <CardContent>
            <div className="text-2xl sm:text-3xl font-bold text-purple-600">{tasks.length}</div>
            <p className="text-xs text-gray-600 flex items-center gap-1">
              <CheckCircle className="h-3 w-3 text-purple-500" />
              создано
            </p>
            <div className="mt-3 h-1.5 w-full bg-gray-100 rounded-full overflow-hidden">
              <div 
                className="h-full bg-gradient-to-r from-purple-500 to-purple-600 rounded-full"
                style={{ width: `${Math.min(tasks.length * 2, 100)}%` }}
              ></div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Employee Performance */}
      <Card className="overflow-hidden border-t-4 border-t-blue-500 card-hover animate-scale-in">
        <CardHeader className="pb-1 sm:pb-2">
          <div className="flex items-center gap-2 sm:gap-3">
            <div className="bg-blue-100 p-1.5 sm:p-2 rounded-full">
              <Award className="h-4 w-4 sm:h-5 sm:w-5 text-blue-600" />
            </div>
            <div>
              <CardTitle className="text-base sm:text-xl">{isMobile ? 'Производительность' : 'Производительность сотрудников'}</CardTitle>
              <CardDescription className="text-xs sm:text-sm">
                Статистика выполнения задач по каждому исполнителю
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {Object.entries(tasksByEmployee).map(([employee, stats]) => {
              const completionRate = Math.round((stats.completed / stats.total) * 100);
              return (
                <div 
                  key={employee} 
                  className="flex flex-col sm:flex-row sm:items-center justify-between p-3 sm:p-4 border rounded-lg group"
                >
                  <div className="flex items-center gap-2 sm:gap-3 mb-2 sm:mb-0">
                    <div className="bg-blue-100 p-1.5 sm:p-2 rounded-full">
                      <User className="h-4 w-4 sm:h-5 sm:w-5 text-blue-600" />
                    </div>
                    <div>
                      <h4 className="font-medium text-gray-900 text-sm sm:text-base">{employee}</h4>
                      <p className="text-xs sm:text-sm text-gray-600">
                        Выполнено: {stats.completed} из {stats.total} задач
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3 sm:gap-4 ml-8 sm:ml-0">
                    <div className="text-right">
                      <p className="text-base sm:text-lg font-bold">{completionRate}%</p>
                      <p className="text-xs text-gray-500">эффективность</p>
                    </div>
                    <Badge 
                      variant={completionRate >= 80 ? 'default' : completionRate >= 60 ? 'secondary' : 'destructive'}
                      className="shadow-sm text-xs py-0.5 px-1.5 sm:py-1 sm:px-2"
                    >
                      {completionRate >= 80 ? (
                        <>
                          <ChevronUp className="h-2.5 w-2.5 sm:h-3 sm:w-3 mr-0.5 sm:mr-1" />
                          Отлично
                        </>
                      ) : completionRate >= 60 ? (
                        <>Хорошо</>
                      ) : (
                        <>
                          <ChevronDown className="h-2.5 w-2.5 sm:h-3 sm:w-3 mr-0.5 sm:mr-1" />
                          Требует внимания
                        </>
                      )}
                    </Badge>
                  </div>
                  <div className="w-full mt-3 sm:hidden">
                    <div className="h-1.5 w-full bg-gray-100 rounded-full overflow-hidden">
                      <div 
                        className={`h-full rounded-full ${completionRate >= 80 ? 'bg-green-500' : completionRate >= 60 ? 'bg-amber-500' : 'bg-red-500'}`}
                        style={{ width: `${completionRate}%` }}
                      ></div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {/* Priority Distribution */}
      <Card className="overflow-hidden border-t-4 border-t-blue-500 card-hover animate-scale-in">
        <CardHeader className="pb-1 sm:pb-2">
          <div className="flex items-center gap-2 sm:gap-3">
            <div className="bg-blue-100 p-1.5 sm:p-2 rounded-full">
              <Flag className="h-4 w-4 sm:h-5 sm:w-5 text-blue-600" />
            </div>
            <div>
              <CardTitle className="text-base sm:text-xl">{isMobile ? 'Приоритеты' : 'Распределение по приоритетам'}</CardTitle>
              <CardDescription className="text-xs sm:text-sm">
                Анализ задач по уровню важности
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 sm:gap-6 animate-fade-in">
            {[{name: 'высокий', color: 'red'}, {name: 'средний', color: 'amber'}, {name: 'низкий', color: 'green'}].map((priority) => {
              const priorityTasks = tasks.filter(t => t.priority === priority.name);
              const percentage = tasks.length > 0 ? Math.round((priorityTasks.length / tasks.length) * 100) : 0;
              
              return (
                <div 
                  key={priority.name} 
                  className={`text-center p-4 sm:p-6 border-l-4 border-${priority.color}-500 rounded-lg bg-gradient-to-r from-white to-${priority.color}-50 group`}
                >
                  <div className="flex justify-center mb-2 sm:mb-3">
                    <div className={`bg-${priority.color}-100 p-1.5 sm:p-2 rounded-full`}>
                      {priority.name === 'высокий' ? (
                        <AlertTriangle className={`h-4 w-4 sm:h-5 sm:w-5 text-${priority.color}-600`} />
                      ) : priority.name === 'средний' ? (
                        <Flag className={`h-4 w-4 sm:h-5 sm:w-5 text-${priority.color}-600`} />
                      ) : (
                        <CheckCircle className={`h-4 w-4 sm:h-5 sm:w-5 text-${priority.color}-600`} />
                      )}
                    </div>
                  </div>
                  <Badge 
                    variant={priority.name === 'высокий' ? 'destructive' : priority.name === 'средний' ? 'default' : 'secondary'}
                    className="mb-1 sm:mb-2 shadow-sm text-xs py-0.5 px-1.5 sm:py-1 sm:px-2"
                  >
                    {priority.name}
                  </Badge>
                  <p className={`text-2xl sm:text-3xl font-bold text-${priority.color}-600 mt-1 sm:mt-2`}>{priorityTasks.length}</p>
                  <p className="text-xs sm:text-sm text-gray-600 mt-0.5 sm:mt-1">{percentage}% от общего</p>
                  
                  <div className="mt-3 h-1.5 w-full bg-gray-100 rounded-full overflow-hidden">
                    <div 
                      className={`h-full bg-${priority.color}-500 rounded-full`}
                      style={{ width: `${percentage}%` }}
                    ></div>
                  </div>
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};
