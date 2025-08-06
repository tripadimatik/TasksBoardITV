import React, { useState, useRef, useEffect, useCallback } from 'react';
import { useIsMobile } from '@/hooks/use-mobile';
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import { 
  sanitizeInput, 
  detectSuspiciousPatterns,
  detectSuspiciousFilePatterns, 
  logSuspiciousActivity 
} from "@/lib/security";

import { Upload, X, FileText, File } from 'lucide-react';
// Firebase импорты удалены, так как проект использует собственный API сервер

interface TaskFileUploadProps {
  onUpload: (file: File | string) => Promise<void>;
  onCancel: () => void;
}

export const TaskFileUpload: React.FC<TaskFileUploadProps> = React.memo(({ onUpload, onCancel }) => {
  // Используем обычное состояние React для стабильного управления данными
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [textReport, setTextReport] = useState<string>('');
  const [reportType, setReportType] = useState<string>('text');
  const [uploading, setUploading] = useState<boolean>(false);
  
  // Используем хук для определения мобильного устройства
  const isMobile = useIsMobile();
  const { toast } = useToast();

  // Разрешенные типы файлов - расширенный список
  const allowedFileTypes = [
    'image/jpeg',
    'image/jpg', // Добавлен для совместимости
    'image/png',
    'image/gif',
    'image/webp',
    'image/bmp',
    'image/tiff',
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.ms-powerpoint',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'text/plain',
    'text/csv',
    'application/zip',
    'application/x-zip-compressed',
    'application/rar',
    'application/x-rar-compressed',
    'application/rtf',
    'application/json',
    'text/xml',
    'application/xml'
  ];

  // Разрешенные расширения файлов - расширенный список
  const allowedExtensions = [
    '.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.tiff',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.txt', '.csv', '.rtf', '.json', '.xml',
    '.zip', '.rar'
  ];

  const handleFileChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      const fileExtension = '.' + file.name.split('.').pop()?.toLowerCase();
      
      // Валидация типа файла - более гибкая проверка
      let isValidFile = false;
      
      // Если MIME тип не определен или пустой, проверяем только по расширению
      if (!file.type || file.type === '') {
        isValidFile = allowedExtensions.includes(fileExtension);
      } else {
        // Если MIME тип определен, проверяем его
        isValidFile = allowedFileTypes.includes(file.type);
        // Дополнительная проверка по расширению для совместимости
        if (!isValidFile) {
          isValidFile = allowedExtensions.includes(fileExtension);
        }
      }
      
      if (!isValidFile) {
        toast({
          title: "Ошибка",
          description: "Недопустимый тип файла. Разрешены: изображения, документы, архивы и текстовые файлы",
          variant: "destructive"
        });
        e.target.value = ''; // Очищаем input
        return;
      }

      // Валидация размера файла (максимум 10MB)
      if (file.size > 10 * 1024 * 1024) {
        toast({
          title: "Ошибка",
          description: "Размер файла не должен превышать 10MB",
          variant: "destructive"
        });
        e.target.value = ''; // Очищаем input
        return;
      }

      // Проверка на подозрительные имена файлов
      if (detectSuspiciousFilePatterns(file.name)) {
        logSuspiciousActivity('Suspicious file name detected', { fileName: file.name });
        toast({
          title: "Ошибка",
          description: "Имя файла содержит недопустимые символы или расширение",
          variant: "destructive"
        });
        e.target.value = ''; // Очищаем input
        return;
      }

      setSelectedFile(file);
    }
  }, [toast, allowedFileTypes, allowedExtensions]);

  const handleTabChange = useCallback((value: string) => {
    setReportType(value);
    // Данные сохраняются при переключении табов
  }, []);

  const handleTextChange = useCallback((e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const value = e.target.value;
    
    // Валидация длины текста
    if (value.length > 5000) {
      toast({
        title: "Ошибка",
        description: "Текстовый отчет не должен превышать 5000 символов",
        variant: "destructive"
      });
      return;
    }

    // Проверка на подозрительные паттерны
    if (detectSuspiciousPatterns(value)) {
      logSuspiciousActivity('Suspicious text patterns detected in report', { textLength: value.length });
      toast({
        title: "Ошибка",
        description: "Текст содержит недопустимые символы или паттерны",
        variant: "destructive"
      });
      return;
    }

    setTextReport(value);
  }, [toast]);

  const handleUpload = useCallback(async () => {
    if (uploading) return; // Предотвращаем множественные отправки
    
    setUploading(true);
    try {
      if (reportType === 'file' && selectedFile) {
        // Дополнительная валидация файла перед загрузкой
        if (selectedFile.size > 10 * 1024 * 1024) {
          throw new Error("Размер файла не должен превышать 10MB");
        }
        
        // Более гибкая проверка типа файла
        const fileExtension = '.' + selectedFile.name.split('.').pop()?.toLowerCase();
        let isValidFile = false;
        
        if (!selectedFile.type || selectedFile.type === '') {
          isValidFile = allowedExtensions.includes(fileExtension);
        } else {
          isValidFile = allowedFileTypes.includes(selectedFile.type);
          if (!isValidFile) {
            isValidFile = allowedExtensions.includes(fileExtension);
          }
        }
        
        if (!isValidFile) {
          throw new Error("Недопустимый тип файла");
        }
        
        // Передаем файл родительскому компоненту для обработки
        await onUpload(selectedFile);
      } else if (reportType === 'text' && textReport.trim()) {
        const trimmedText = textReport.trim();
        
        // Валидация длины текста

        
        if (trimmedText.length > 5000) {
          throw new Error("Текстовый отчет не должен превышать 5000 символов");
        }
        
        // Финальная проверка на подозрительные паттерны
        if (detectSuspiciousPatterns(trimmedText)) {
          logSuspiciousActivity('Suspicious text patterns detected during upload', { textLength: trimmedText.length });
          throw new Error("Текст содержит недопустимые символы или паттерны");
        }
        
        // Санитизация текста перед отправкой
        const sanitizedText = sanitizeInput(trimmedText);
        await onUpload(sanitizedText);
      } else {
        throw new Error("Пожалуйста, выберите файл или введите текстовый отчет");
      }
      
      // Успешная загрузка - сбрасываем только использованные данные
      setUploading(false);
      if (reportType === 'file') {
        setSelectedFile(null);
        // Сбрасываем значение input файла
        const fileInput = document.getElementById('fileUpload') as HTMLInputElement;
        if (fileInput) {
          fileInput.value = '';
        }
      } else if (reportType === 'text') {
        setTextReport('');
      }
      
      // Автоматически закрываем компонент после успешной загрузки
      // Пользователь получит уведомление от родительского компонента
      onCancel();
    } catch (error) {
      console.error('Ошибка загрузки отчета:', error);
      setUploading(false);
      
      // Показываем уведомление об ошибке
      toast({
        title: "Ошибка загрузки",
        description: error instanceof Error ? error.message : "Произошла ошибка при загрузке отчета",
        variant: "destructive"
      });
      
      // Не очищаем поля при ошибке - пользователь может попробовать снова
    }
  }, [uploading, reportType, selectedFile, textReport, onUpload, onCancel, toast, allowedFileTypes, allowedExtensions]);

  // Focus management for mobile keyboards
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  
  useEffect(() => {
    // Auto-focus textarea when text tab is selected
    if (reportType === 'text' && textareaRef.current) {
      // Добавляем небольшую задержку для мобильных устройств
      const timer = setTimeout(() => {
        textareaRef.current?.focus();
      }, 100);
      return () => clearTimeout(timer);
    }
  }, [reportType]);

  return (
    <div className="w-full space-y-3 sm:space-y-4 relative">
      <button 
        onClick={onCancel}
        className="absolute right-0 top-0 p-1 rounded-full hover:bg-gray-100 transition-colors"
        aria-label="Close upload dialog"
        // Prevent default to avoid keyboard closing on mobile
        onMouseDown={(e) => e.preventDefault()}
        onTouchStart={(e) => {
          e.preventDefault();
          e.stopPropagation();
        }}
        type="button"
      >
        <X className="h-5 w-5 text-gray-500" />
      </button>
      
      <div className="space-y-1 sm:space-y-2">
        <h3 className="text-base sm:text-lg font-medium">Загрузить отчет</h3>
        <p className="text-xs sm:text-sm text-gray-600">
          Выберите файл отчета или введите текстовый отчет
        </p>
      </div>
        
        <Tabs value={reportType} onValueChange={handleTabChange} className="w-full">
          <TabsList className="grid w-full grid-cols-2 h-11 sm:h-10">
            <TabsTrigger value="text" className="text-sm sm:text-base py-2">Текстовый отчет</TabsTrigger>
            <TabsTrigger value="file" className="text-sm sm:text-base py-2">Файл</TabsTrigger>
          </TabsList>
          
          <TabsContent value="text" className="space-y-3 sm:space-y-4 mt-3 sm:mt-4">
            <div className="space-y-1.5 sm:space-y-2">
              <Label htmlFor="textReport" className="text-sm font-medium">Текст отчета</Label>
              <Textarea
                id="textReport"
                ref={textareaRef}
                value={textReport}
                onChange={handleTextChange}
                placeholder="Введите ваш отчет здесь..."
                className="w-full min-h-[120px] sm:min-h-[140px] resize-none"
                required
                // Mobile-specific attributes to prevent keyboard auto-closing
                onFocus={() => {
                  if (isMobile) {
                    // Add slight delay to ensure keyboard stays open
                    setTimeout(() => textareaRef.current?.focus(), 100);
                  }
                }}
                // Prevent input from losing focus on mobile
                onBlur={(e) => {
                  // Only refocus if the blur wasn't caused by clicking another element
                  if (isMobile && !e.relatedTarget) {
                    // Small delay to prevent keyboard flicker
                    setTimeout(() => {
                      if (textareaRef.current && document.activeElement !== textareaRef.current) {
                        textareaRef.current.focus();
                      }
                    }, 100);
                  }
                }}
                // Prevent keyboard from closing when scrolling on mobile
                onTouchStart={(e) => {
                  if (isMobile) {
                    e.stopPropagation();
                  }
                }}
              />
            </div>
          </TabsContent>
          
          <TabsContent value="file" className="space-y-3 sm:space-y-4 mt-3 sm:mt-4">
            <div className="space-y-1.5 sm:space-y-2">
              <Label htmlFor="fileUpload" className="text-sm font-medium">Выберите файл</Label>
              <Input
                id="fileUpload"
                type="file"
                onChange={handleFileChange}
                accept=".jpg,.jpeg,.png,.gif,.webp,.bmp,.tiff,.pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.txt,.csv,.rtf,.json,.xml,.zip,.rar"
                className="h-11 sm:h-10 text-base sm:text-sm file:mr-3 file:py-2 file:px-3 file:rounded-md file:border-0 file:text-sm file:font-medium file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100"
                required
              />
              {selectedFile && (
                <p className="text-xs sm:text-sm text-gray-600 break-all">
                  Выбран файл: {selectedFile.name}
                </p>
              )}
            </div>
          </TabsContent>
        </Tabs>

      <div className="flex flex-col-reverse sm:flex-row gap-2 sm:gap-3 pt-3 sm:pt-4">
        <Button 
          variant="outline" 
          onClick={onCancel} 
          disabled={uploading}
          className="w-full sm:w-auto h-10 sm:h-9 text-sm font-medium"
        >
          Отмена
        </Button>
        <Button 
          onClick={handleUpload} 
          disabled={uploading || (!selectedFile && reportType === 'file') || (!textReport.trim() && reportType === 'text')}
          className="w-full sm:w-auto h-10 sm:h-9 text-sm font-medium transition-all duration-200 ease-in-out hover:scale-[1.02] active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100"
        >
          <span className={`transition-opacity duration-200 ${uploading ? 'opacity-70' : 'opacity-100'}`}>
            {uploading ? 'Загрузка...' : 'Загрузить'}
          </span>
        </Button>
      </div>
    </div>
  );
});

TaskFileUpload.displayName = 'TaskFileUpload';

export default TaskFileUpload;
