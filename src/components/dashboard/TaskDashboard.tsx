
import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { CheckSquare, Clock, AlertTriangle, Eye } from 'lucide-react';

interface Task {
  id: number;
  title: string;
  description: string;
  priority: string;
  deadline: string;
  status: string;
  assignee: string;
  createdAt: string;
}

interface TaskDashboardProps {
  tasks: Task[];
  userRole: string;
}

export const TaskDashboard: React.FC<TaskDashboardProps> = ({ tasks, userRole }) => {
  const userTasks = userRole === 'employee' ? 
    tasks.filter(task => task.assignee === 'Текущий пользователь') : 
    tasks;

  const statusCounts = {
    назначено: userTasks.filter(t => t.status === 'назначено').length,
    'в работе': userTasks.filter(t => t.status === 'в работе').length,
    'на проверке': userTasks.filter(t => t.status === 'на проверке').length,
    выполнено: userTasks.filter(t => t.status === 'выполнено').length
  };

  const urgentTasks = userTasks.filter(task => {
    const deadline = new Date(task.deadline);
    const today = new Date();
    const diffTime = deadline.getTime() - today.getTime();
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    return diffDays <= 3 && task.status !== 'выполнено';
  });

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8 animate-fade-in">
      <Card className="overflow-hidden border-l-4 border-l-blue-400 hover:border-l-blue-500 transition-colors duration-200 card-hover animate-scale-in">
        <div className="absolute right-0 top-0 h-16 w-16 opacity-10 transform translate-x-4 -translate-y-4">
          <Clock className="h-full w-full text-blue-500" />
        </div>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Clock className="h-5 w-5 text-blue-500" />
            Новые
          </CardTitle>
          <Badge variant="outline" className="bg-blue-50">{statusCounts.назначено}</Badge>
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold text-blue-600">{statusCounts.назначено}</div>
          <p className="text-xs text-muted-foreground">назначенных задач</p>
          <div className="h-1 w-full bg-blue-100 mt-4 rounded-full overflow-hidden">
            <div 
              className="h-full bg-blue-500 rounded-full" 
              style={{ width: `${(statusCounts.назначено / Math.max(userTasks.length, 1)) * 100}%` }}
            ></div>
          </div>
        </CardContent>
      </Card>

      <Card className="overflow-hidden border-l-4 border-l-amber-400 hover:border-l-amber-500 transition-colors duration-200 card-hover animate-scale-in">
        <div className="absolute right-0 top-0 h-16 w-16 opacity-10 transform translate-x-4 -translate-y-4">
          <CheckSquare className="h-full w-full text-amber-500" />
        </div>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <CheckSquare className="h-5 w-5 text-amber-500" />
            В работе
          </CardTitle>
          <Badge variant="outline" className="bg-amber-50">{statusCounts['в работе']}</Badge>
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold text-amber-600">{statusCounts['в работе']}</div>
          <p className="text-xs text-muted-foreground">активных задач</p>
          <div className="h-1 w-full bg-amber-100 mt-4 rounded-full overflow-hidden">
            <div 
              className="h-full bg-amber-500 rounded-full" 
              style={{ width: `${(statusCounts['в работе'] / Math.max(userTasks.length, 1)) * 100}%` }}
            ></div>
          </div>
        </CardContent>
      </Card>

      <Card className="overflow-hidden border-l-4 border-l-purple-400 hover:border-l-purple-500 transition-colors duration-200 card-hover animate-scale-in">
        <div className="absolute right-0 top-0 h-16 w-16 opacity-10 transform translate-x-4 -translate-y-4">
          <Eye className="h-full w-full text-purple-500" />
        </div>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Eye className="h-5 w-5 text-purple-500" />
            На проверке
          </CardTitle>
          <Badge variant="outline" className="bg-purple-50">{statusCounts['на проверке']}</Badge>
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold text-purple-600">{statusCounts['на проверке']}</div>
          <p className="text-xs text-muted-foreground">на рассмотрении</p>
          <div className="h-1 w-full bg-purple-100 mt-4 rounded-full overflow-hidden">
            <div 
              className="h-full bg-purple-500 rounded-full" 
              style={{ width: `${(statusCounts['на проверке'] / Math.max(userTasks.length, 1)) * 100}%` }}
            ></div>
          </div>
        </CardContent>
      </Card>

      <Card className="overflow-hidden border-l-4 border-l-green-400 hover:border-l-green-500 transition-colors duration-200 card-hover animate-scale-in">
        <div className="absolute right-0 top-0 h-16 w-16 opacity-10 transform translate-x-4 -translate-y-4">
          <CheckSquare className="h-full w-full text-green-500" />
        </div>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <CheckSquare className="h-5 w-5 text-green-500" />
            Завершено
          </CardTitle>
          <Badge variant="outline" className="bg-green-50">{statusCounts.выполнено}</Badge>
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold text-green-600">{statusCounts.выполнено}</div>
          <p className="text-xs text-muted-foreground">выполненных задач</p>
          <div className="h-1 w-full bg-green-100 mt-4 rounded-full overflow-hidden">
            <div 
              className="h-full bg-green-500 rounded-full" 
              style={{ width: `${(statusCounts.выполнено / Math.max(userTasks.length, 1)) * 100}%` }}
            ></div>
          </div>
        </CardContent>
      </Card>

      <Card className="overflow-hidden border-l-4 border-l-red-400 hover:border-l-red-500 transition-colors duration-200 card-hover animate-scale-in">
        <div className="absolute right-0 top-0 h-16 w-16 opacity-10 transform translate-x-4 -translate-y-4">
          <AlertTriangle className="h-full w-full text-red-500" />
        </div>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-red-500" />
            Срочные
          </CardTitle>
          <Badge variant="outline" className="bg-red-50">{urgentTasks.length}</Badge>
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold text-red-600">{urgentTasks.length}</div>
          <p className="text-xs text-muted-foreground">требуют внимания</p>
          <div className="h-1 w-full bg-red-100 mt-4 rounded-full overflow-hidden">
            <div 
              className="h-full bg-red-500 rounded-full" 
              style={{ width: `${(urgentTasks.length / Math.max(userTasks.length, 1)) * 100}%` }}
            ></div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};
