import React, { useState, useEffect, useMemo } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Calendar } from "@/components/ui/calendar";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { useToast } from "@/hooks/use-toast";
import { Task } from "@/lib/types";
import { ChevronDown, ChevronUp, Download, FileText, Calendar as CalendarIcon, Filter, X, Archive } from 'lucide-react';
import { format, parseISO } from 'date-fns';
import { ru } from 'date-fns/locale';
import jsPDF from 'jspdf';
import html2canvas from 'html2canvas';
import { sanitizeInput, detectSuspiciousPatterns, logSuspiciousActivity } from '@/lib/security';

interface CompletedTasksReportProps {
  tasks: Task[];
}

interface FilterState {
  employeeName: string;
  taskTitle: string;
  dateFrom: Date | null;
  dateTo: Date | null;
  showArchived: boolean;
}

const CompletedTasksReport: React.FC<CompletedTasksReportProps> = ({ tasks }) => {
  const [expandedTasks, setExpandedTasks] = useState<Set<string>>(new Set());
  const [expandedReports, setExpandedReports] = useState<Set<string>>(new Set());
  const [filters, setFilters] = useState<FilterState>({
    employeeName: '',
    taskTitle: '',
    dateFrom: null,
    dateTo: null,
    showArchived: true
  });
  const [showDateFromPicker, setShowDateFromPicker] = useState(false);
  const [showDateToPicker, setShowDateToPicker] = useState(false);
  const { toast } = useToast();

  // Валидация и санитизация входных данных
  const validateAndSanitizeInput = (value: string, fieldName: string): string => {
    if (!value) return '';
    
    // Проверка на подозрительные паттерны
    if (detectSuspiciousPatterns(value)) {
      logSuspiciousActivity(`Suspicious input detected in ${fieldName}`, { value, fieldName });
      toast({
        title: 'Недопустимый ввод',
        description: 'Обнаружены недопустимые символы в поле ввода',
        variant: 'destructive'
      });
      return '';
    }
    
    // Санитизация входных данных
    return sanitizeInput(value);
  };

  // Фильтруем завершенные и архивированные задачи
  const completedTasks = useMemo(() => {
    return tasks.filter(task => 
      (task.status === 'выполнено' || task.status === 'COMPLETED') || task.archived
    );
  }, [tasks]);

  // Применяем фильтры
  const filteredTasks = useMemo(() => {
    return completedTasks.filter(task => {
      // Фильтр по архивированным задачам
      if (!filters.showArchived && task.archived) {
        return false;
      }
      // Фильтр по имени сотрудника
      if (filters.employeeName && 
          !task.assigneeName?.toLowerCase().includes(filters.employeeName.toLowerCase())) {
        return false;
      }

      // Фильтр по названию задачи
      if (filters.taskTitle && 
          !task.title.toLowerCase().includes(filters.taskTitle.toLowerCase())) {
        return false;
      }

      // Фильтр по дате
      if (filters.dateFrom || filters.dateTo) {
        const taskDate = parseISO(task.updatedAt);
        
        if (filters.dateFrom && taskDate < filters.dateFrom) {
          return false;
        }
        
        if (filters.dateTo) {
          const endOfDay = new Date(filters.dateTo);
          endOfDay.setHours(23, 59, 59, 999);
          if (taskDate > endOfDay) {
            return false;
          }
        }
      }

      return true;
    });
  }, [completedTasks, filters]);

  // Получаем уникальных сотрудников для фильтра
  const uniqueEmployees = useMemo(() => {
    const employees = completedTasks
      .map(task => task.assigneeName)
      .filter(Boolean)
      .filter((name, index, arr) => arr.indexOf(name) === index)
      .sort();
    return employees;
  }, [completedTasks]);

  const toggleTaskExpansion = (taskId: string) => {
    const newExpanded = new Set(expandedTasks);
    if (newExpanded.has(taskId)) {
      newExpanded.delete(taskId);
    } else {
      newExpanded.add(taskId);
    }
    setExpandedTasks(newExpanded);
  };

  const toggleReportExpansion = (taskId: string) => {
    const newExpanded = new Set(expandedReports);
    if (newExpanded.has(taskId)) {
      newExpanded.delete(taskId);
    } else {
      newExpanded.add(taskId);
    }
    setExpandedReports(newExpanded);
  };

  const clearFilters = () => {
    setFilters({
      employeeName: '',
      taskTitle: '',
      dateFrom: null,
      dateTo: null,
      showArchived: true
    });
  };

  const generatePDF = async () => {
    try {
      // Создаем временный HTML элемент с таблицей
      const reportElement = document.createElement('div');
      reportElement.style.position = 'absolute';
      reportElement.style.left = '-9999px';
      reportElement.style.top = '-9999px';
      reportElement.style.width = '1400px'; // Оптимальная ширина для альбомной ориентации
      reportElement.style.backgroundColor = 'white';
      reportElement.style.padding = '40px';
      reportElement.style.fontFamily = '"Segoe UI", "Roboto", "Helvetica Neue", Arial, sans-serif';
      reportElement.style.fontSize = '14px'; // Оптимальный размер шрифта
      reportElement.style.lineHeight = '1.5';
      reportElement.style.color = '#1a1a1a'; // Делаем текст темнее
      reportElement.style.webkitFontSmoothing = 'antialiased';
      reportElement.style.mozOsxFontSmoothing = 'grayscale';
      reportElement.style.textRendering = 'optimizeLegibility';
      reportElement.style.fontWeight = '400';
      
      // Заголовок отчета
      const title = 'Отчет: Завершенные задачи';
      const dateRange = filters.dateFrom || filters.dateTo 
        ? ` с ${filters.dateFrom ? format(filters.dateFrom, 'dd.MM.yyyy', { locale: ru }) : 'начала'} по ${filters.dateTo ? format(filters.dateTo, 'dd.MM.yyyy', { locale: ru }) : 'сегодня'}`
        : '';
      
      let htmlContent = `
        <div style="margin-bottom: 40px;">
          <h1 style="font-size: 24px; margin-bottom: 20px; color: #1a1a1a; font-weight: 700; letter-spacing: -0.5px;">${title}${dateRange}</h1>
           <div style="font-size: 14px; color: #555; margin-bottom: 10px; line-height: 1.6;">
            ${filters.employeeName ? `<div style="margin-bottom: 6px;">Сотрудник: <strong>${filters.employeeName}</strong></div>` : ''}
            ${filters.taskTitle ? `<div style="margin-bottom: 6px;">Поиск по названию: <strong>${filters.taskTitle}</strong></div>` : ''}
            <div style="margin-bottom: 6px;">Дата создания отчета: <strong>${format(new Date(), 'dd.MM.yyyy HH:mm', { locale: ru })}</strong></div>
            <div>Всего задач: <strong>${filteredTasks.length}</strong></div>
          </div>
        </div>
        <table style="width: 100%; border-collapse: collapse; font-size: 12px; border: 2px solid #1a1a1a; table-layout: fixed;">
          <thead>
            <tr style="background-color: #2563eb; color: white;">
              <th style="border: 1px solid #1e40af; padding: 12px 10px; text-align: left; font-weight: 700; font-size: 13px; width: 25%;">Название задачи</th>
               <th style="border: 1px solid #1e40af; padding: 12px 10px; text-align: left; font-weight: 700; font-size: 13px; width: 15%;">Сотрудник</th>
               <th style="border: 1px solid #1e40af; padding: 12px 10px; text-align: left; font-weight: 700; font-size: 13px; width: 12%;">Дата завершения</th>
               <th style="border: 1px solid #1e40af; padding: 12px 10px; text-align: left; font-weight: 700; font-size: 13px; width: 10%;">Приоритет</th>
               <th style="border: 1px solid #1e40af; padding: 12px 10px; text-align: left; font-weight: 700; font-size: 13px; width: 23%;">Описание</th>
               <th style="border: 1px solid #1e40af; padding: 12px 10px; text-align: left; font-weight: 700; font-size: 13px; width: 15%;">Отчет</th>
            </tr>
          </thead>
          <tbody>
      `;
      
      // Добавляем строки таблицы
      filteredTasks.forEach((task, index) => {
        const priority = task.priority === 'HIGH' || task.priority === 'высокий' ? 'Высокий' :
                        task.priority === 'MEDIUM' || task.priority === 'средний' ? 'Средний' : 'Низкий';
        
        const reportInfo = task.reportFile ? 
          (task.reportFile.isTextReport ? 
            `Текстовый отчет: ${(task.reportFile.content || 'Содержимое недоступно').substring(0, 50)}...` : 
            `Файл: ${task.reportFile.name}`) : 
          'Нет отчета';
        
        htmlContent += `
          <tr style="${index % 2 === 0 ? 'background-color: #f8fafc;' : 'background-color: white;'}">
            <td style="border: 1px solid #d1d5db; padding: 12px 10px; vertical-align: top; font-weight: 600; color: #1f2937; word-wrap: break-word; font-size: 12px; line-height: 1.4;">${task.title}</td>
             <td style="border: 1px solid #d1d5db; padding: 12px 10px; vertical-align: top; color: #374151; font-size: 12px; font-weight: 500;">${task.assigneeName || 'Не назначен'}</td>
             <td style="border: 1px solid #d1d5db; padding: 12px 10px; vertical-align: top; color: #374151; font-size: 12px; font-weight: 500;">${format(parseISO(task.updatedAt), 'dd.MM.yyyy', { locale: ru })}</td>
             <td style="border: 1px solid #d1d5db; padding: 12px 10px; vertical-align: top; color: #374151; font-size: 12px; font-weight: 500;">${priority}</td>
             <td style="border: 1px solid #d1d5db; padding: 12px 10px; vertical-align: top; word-wrap: break-word; line-height: 1.5; color: #4b5563; font-size: 11px;">${(task.description || 'Нет описания').substring(0, 100)}${task.description && task.description.length > 100 ? '...' : ''}</td>
             <td style="border: 1px solid #d1d5db; padding: 12px 10px; vertical-align: top; word-wrap: break-word; line-height: 1.5; color: #4b5563; font-size: 11px;">${reportInfo}</td>
          </tr>
        `;
      });
      
      htmlContent += `
          </tbody>
        </table>
      `;
      
      reportElement.innerHTML = htmlContent;
      document.body.appendChild(reportElement);
      
      // Конвертируем в canvas с оптимальным качеством
      const canvas = await html2canvas(reportElement, {
        scale: 2, // Оптимальный масштаб для хорошего качества без избыточного размера
        useCORS: true,
        allowTaint: true,
        backgroundColor: '#ffffff',
        logging: false,
        width: reportElement.scrollWidth,
        height: reportElement.scrollHeight,
        scrollX: 0,
        scrollY: 0,
        windowWidth: reportElement.scrollWidth,
        windowHeight: reportElement.scrollHeight
      });
      
      // Удаляем временный элемент
      document.body.removeChild(reportElement);
      
      // Создаем PDF с альбомной ориентацией для широких таблиц
      const pdf = new jsPDF({
        orientation: 'landscape', // Меняем на альбомную ориентацию
        unit: 'mm',
        format: 'a4',
        compress: true, // Включаем сжатие для оптимального размера файла
        precision: 2,
        userUnit: 1.0
      });
      
      // Используем оптимальное качество для изображения
      const imgData = canvas.toDataURL('image/jpeg', 0.85); // JPEG с хорошим качеством и меньшим размером
      const imgWidth = 297; // A4 landscape width in mm
      const pageHeight = 210; // A4 landscape height in mm
      const imgHeight = (canvas.height * imgWidth) / canvas.width;
      let heightLeft = imgHeight;
      
      let position = 0;
      
      // Добавляем изображение на первую страницу
      pdf.addImage(imgData, 'JPEG', 0, position, imgWidth, imgHeight, undefined, 'FAST');
      heightLeft -= pageHeight;
      
      // Добавляем дополнительные страницы если необходимо
      while (heightLeft >= 0) {
        position = heightLeft - imgHeight;
        pdf.addPage();
        pdf.addImage(imgData, 'JPEG', 0, position, imgWidth, imgHeight, undefined, 'FAST');
        heightLeft -= pageHeight;
      }
      
      // Сохраняем PDF
      const fileName = `Отчет_Завершенные_задачи_${format(new Date(), 'yyyy-MM-dd_HH-mm')}.pdf`;
      pdf.save(fileName);
      
      toast({
        title: "PDF отчет создан",
        description: `Отчет сохранен как ${fileName}`
      });
      
    } catch (error) {
      console.error('Error generating PDF:', error);
      toast({
        title: "Ошибка",
        description: "Не удалось создать PDF отчет",
        variant: "destructive"
      });
    }
  };

  const truncateText = (text: string, maxLength: number) => {
    return text.length > maxLength ? text.substring(0, maxLength) + '...' : text;
  };

  return (
    <div className="space-y-6">
      {/* Заголовок */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <span>Отчет по завершенным задачам</span>
            <Badge variant="outline" className="text-sm">
              Найдено: {filteredTasks.length} из {completedTasks.length}
            </Badge>
          </CardTitle>
        </CardHeader>
      </Card>

      {/* Фильтры */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Filter className="h-5 w-5" />
            <span>Фильтры</span>
            {(filters.employeeName || filters.taskTitle || filters.dateFrom || filters.dateTo) && (
              <Button variant="ghost" size="sm" onClick={clearFilters}>
                <X className="h-4 w-4 mr-1" />
                Очистить
              </Button>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
            {/* Фильтр по сотруднику */}
            <div className="space-y-2">
              <Label htmlFor="employee-filter">Сотрудник</Label>
              <Select value={filters.employeeName || "__all__"} onValueChange={(value) => 
                setFilters(prev => ({ ...prev, employeeName: value === "__all__" ? "" : value }))
              }>
                <SelectTrigger>
                  <SelectValue placeholder="Выберите сотрудника" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="__all__">Все сотрудники</SelectItem>
                  {uniqueEmployees.map(employee => {
                    const sanitizedEmployee = sanitizeInput(employee!);
                    return (
                      <SelectItem key={employee} value={employee!}>
                        {sanitizedEmployee}
                      </SelectItem>
                    );
                  })}
                </SelectContent>
              </Select>
            </div>

            {/* Фильтр по названию задачи */}
            <div className="space-y-2">
              <Label htmlFor="title-filter">Название задачи</Label>
              <Input
                id="title-filter"
                placeholder="Поиск по названию..."
                value={filters.taskTitle}
                onChange={(e) => {
                  const sanitizedValue = validateAndSanitizeInput(e.target.value, 'taskTitle');
                  setFilters(prev => ({ ...prev, taskTitle: sanitizedValue }));
                }}
                maxLength={100}
              />
            </div>

            {/* Фильтр по дате "с" */}
            <div className="space-y-2">
              <Label>Дата с</Label>
              <Popover open={showDateFromPicker} onOpenChange={setShowDateFromPicker}>
                <PopoverTrigger asChild>
                  <Button variant="outline" className="w-full justify-start text-left font-normal">
                    <CalendarIcon className="mr-2 h-4 w-4" />
                    {filters.dateFrom ? format(filters.dateFrom, 'dd.MM.yyyy', { locale: ru }) : 'Выберите дату'}
                  </Button>
                </PopoverTrigger>
                <PopoverContent className="w-auto p-0" align="start">
                  <Calendar
                    mode="single"
                    selected={filters.dateFrom || undefined}
                    onSelect={(date) => {
                      setFilters(prev => ({ ...prev, dateFrom: date || null }));
                      setShowDateFromPicker(false);
                    }}
                    locale={ru}
                    initialFocus
                  />
                </PopoverContent>
              </Popover>
            </div>

            {/* Фильтр по дате "до" */}
            <div className="space-y-2">
              <Label>Дата до</Label>
              <Popover open={showDateToPicker} onOpenChange={setShowDateToPicker}>
                <PopoverTrigger asChild>
                  <Button variant="outline" className="w-full justify-start text-left font-normal">
                    <CalendarIcon className="mr-2 h-4 w-4" />
                    {filters.dateTo ? format(filters.dateTo, 'dd.MM.yyyy', { locale: ru }) : 'Выберите дату'}
                  </Button>
                </PopoverTrigger>
                <PopoverContent className="w-auto p-0" align="start">
                  <Calendar
                    mode="single"
                    selected={filters.dateTo || undefined}
                    onSelect={(date) => {
                      setFilters(prev => ({ ...prev, dateTo: date || null }));
                      setShowDateToPicker(false);
                    }}
                    locale={ru}
                    initialFocus
                  />
                </PopoverContent>
              </Popover>
            </div>

            {/* Фильтр по архивированным задачам */}
            <div className="space-y-2">
              <Label>Показать архивированные</Label>
              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="show-archived"
                  checked={filters.showArchived}
                  onChange={(e) => setFilters(prev => ({ ...prev, showArchived: e.target.checked }))}
                  className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                />
                <Label htmlFor="show-archived" className="text-sm font-normal cursor-pointer">
                  Включить архивированные задачи
                </Label>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Кнопка экспорта */}
      <div className="flex justify-end">
        <Button onClick={generatePDF} className="flex items-center space-x-2">
          <Download className="h-4 w-4" />
          <span>Скачать PDF отчет</span>
        </Button>
      </div>

      {/* Таблица задач */}
      <Card>
        <CardContent className="p-0">
          {filteredTasks.length === 0 ? (
            <div className="text-center py-12">
              <FileText className="h-12 w-12 text-gray-400 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-gray-900 mb-2">Нет завершенных задач</h3>
              <p className="text-gray-500">
                {completedTasks.length === 0 
                  ? 'Пока нет завершенных задач для отображения'
                  : 'Попробуйте изменить фильтры поиска'
                }
              </p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[35%]">Задача</TableHead>
                  <TableHead className="w-[20%]">Сотрудник</TableHead>
                  <TableHead className="w-[15%]">Дата завершения</TableHead>
                  <TableHead className="w-[10%]">Приоритет</TableHead>
                  <TableHead className="w-[10%]">Статус</TableHead>
                  <TableHead className="w-[10%]">Детали</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredTasks.map((task) => (
                  <React.Fragment key={task.id}>
                    <TableRow>
                      <TableCell>
                        <div>
                          <div className="font-medium select-none">{task.title}</div>
                          <div className="text-sm text-gray-500 select-none">
                            {truncateText(task.description, 100)}
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="font-medium select-none">{task.assigneeName || 'Не назначен'}</div>
                      </TableCell>
                      <TableCell>
                        <div className="text-sm">
                          {format(parseISO(task.updatedAt), 'dd.MM.yyyy', { locale: ru })}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant={
                          (task.priority === 'HIGH' || task.priority === 'высокий') ? 'destructive' :
                          (task.priority === 'MEDIUM' || task.priority === 'средний') ? 'default' : 'secondary'
                        }>
                          {task.priority === 'HIGH' || task.priority === 'высокий' ? 'Высокий' :
                           task.priority === 'MEDIUM' || task.priority === 'средний' ? 'Средний' : 'Низкий'}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center space-x-1">
                          {task.archived && (
                            <Archive className="h-4 w-4 text-gray-500" />
                          )}
                          <Badge variant={task.archived ? 'outline' : 'default'}>
                            {task.archived ? 'Архивирована' : 'Завершена'}
                          </Badge>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Collapsible>
                          <CollapsibleTrigger asChild>
                            <Button 
                              variant="outline" 
                              size="sm"
                              onClick={() => toggleTaskExpansion(task.id)}
                              className="border-gray-200 hover:border-gray-300 hover:bg-gray-50"
                            >
                              {expandedTasks.has(task.id) ? (
                                <ChevronUp className="h-4 w-4" />
                              ) : (
                                <ChevronDown className="h-4 w-4" />
                              )}
                            </Button>
                          </CollapsibleTrigger>
                        </Collapsible>
                      </TableCell>
                    </TableRow>
                    {expandedTasks.has(task.id) && (
                      <TableRow>
                        <TableCell colSpan={6} className="bg-gray-50">
                          <div className="p-4 space-y-4">
                            <div>
                              <h4 className="font-medium mb-2 select-none">Полное описание:</h4>
                              <p className="text-sm text-gray-700 select-none">{task.description}</p>
                            </div>
                            
                            {task.reportFile && (
                              <div>
                                <h4 className="font-medium mb-2 select-none">Прикрепленный отчет:</h4>
                                <div className="space-y-2">
                                  <div className="flex items-center space-x-2">
                                    <FileText className="h-4 w-4 text-blue-500" />
                                    {task.reportFile.isTextReport ? (
                                      <div className="flex items-center space-x-2">
                                        <span className="text-sm text-blue-600 select-none">Текстовый отчет</span>
                                        <Button 
                                          variant="outline" 
                                          size="sm"
                                          onClick={() => toggleReportExpansion(task.id)}
                                          className="text-xs border-gray-200 hover:border-gray-300 hover:bg-gray-50"
                                        >
                                          {expandedReports.has(task.id) ? 'Свернуть' : 'Развернуть'}
                                        </Button>
                                      </div>
                                    ) : (
                                      <a 
                                        href={task.reportFile.url} 
                                        target="_blank" 
                                        rel="noopener noreferrer"
                                        className="text-sm text-blue-600 hover:underline select-none"
                                      >
                                        {task.reportFile.name}
                                      </a>
                                    )}
                                    {task.reportFile.comment && (
                                      <span className="text-sm text-gray-500 select-none">- {task.reportFile.comment}</span>
                                    )}
                                  </div>
                                  
                                  {task.reportFile.isTextReport && expandedReports.has(task.id) && task.reportFile.content && (
                                    <div className="mt-2 p-3 bg-white border rounded-md">
                                      <h5 className="text-sm font-medium mb-2 select-none">Содержимое отчета:</h5>
                                      <div className="text-sm text-gray-700 whitespace-pre-wrap max-h-60 overflow-y-auto select-none">
                                        {task.reportFile.content}
                                      </div>
                                    </div>
                                  )}
                                </div>
                              </div>
                            )}
                            
                            <div className="text-xs text-gray-500 select-none">
                              Создано: {format(parseISO(task.createdAt), 'dd.MM.yyyy HH:mm', { locale: ru })} | 
                              Завершено: {format(parseISO(task.updatedAt), 'dd.MM.yyyy HH:mm', { locale: ru })}
                            </div>
                          </div>
                        </TableCell>
                      </TableRow>
                    )}
                  </React.Fragment>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default CompletedTasksReport;