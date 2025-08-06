import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Switch } from '@/components/ui/switch';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Volume2, VolumeX, Bell, BellOff } from 'lucide-react';
import { useNotifications } from '@/utils/notifications';
import { useToast } from '@/hooks/use-toast';

export const NotificationSettings: React.FC = () => {
  const [soundEnabled, setSoundEnabled] = useState(true);
  const [browserNotificationsEnabled, setBrowserNotificationsEnabled] = useState(false);
  const { setEnabled, isEnabled, playNewTaskSound, showNotification, requestPermission } = useNotifications();
  const { toast } = useToast();

  useEffect(() => {
    // Загружаем текущие настройки
    setSoundEnabled(isEnabled());
    
    // Проверяем разрешение на браузерные уведомления
    if ('Notification' in window) {
      setBrowserNotificationsEnabled(Notification.permission === 'granted');
    }
  }, [isEnabled]);

  const handleSoundToggle = (enabled: boolean) => {
    setSoundEnabled(enabled);
    setEnabled(enabled);
    
    toast({
      title: enabled ? "Звуковые уведомления включены" : "Звуковые уведомления выключены",
      description: enabled 
        ? "Вы будете слышать звук при получении новых задач"
        : "Звуковые уведомления отключены"
    });
  };

  const handleTestSound = () => {
    playNewTaskSound();
    toast({
      title: "Тестовый звук",
      description: "Так будет звучать уведомление о новой задаче"
    });
  };

  const handleRequestNotificationPermission = async () => {
    if (!('Notification' in window)) {
      toast({
        title: "Уведомления не поддерживаются",
        description: "Ваш браузер не поддерживает браузерные уведомления",
        variant: "destructive"
      });
      return;
    }

    try {
      const hasPermission = await requestPermission();
      setBrowserNotificationsEnabled(hasPermission);
      
      if (hasPermission) {
        toast({
          title: "Уведомления разрешены",
          description: "Теперь вы будете получать браузерные уведомления о новых задачах"
        });
        
        // Показываем тестовое уведомление
        showNotification(
          "Тестовое уведомление",
          "Уведомления настроены и работают!"
        );
      } else {
        toast({
          title: "Разрешение отклонено",
          description: "Для включения уведомлений: нажмите на иконку замка в адресной строке браузера → Уведомления → Разрешить",
          variant: "destructive"
        });
      }
    } catch (error) {
      console.error('Ошибка при запросе разрешения на уведомления:', error);
      toast({
        title: "Ошибка",
        description: "Не удалось запросить разрешение на уведомления",
        variant: "destructive"
      });
    }
  };

  return (
    <Card className="w-full max-w-2xl">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Bell className="h-5 w-5" />
          Настройки уведомлений
        </CardTitle>
        <CardDescription>
          Настройте способы получения уведомлений о новых задачах
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Звуковые уведомления */}
        <div className="flex items-center justify-between space-x-2">
          <div className="space-y-1">
            <Label className="text-base font-medium flex items-center gap-2">
              {soundEnabled ? <Volume2 className="h-4 w-4" /> : <VolumeX className="h-4 w-4" />}
              Звуковые уведомления
            </Label>
            <p className="text-sm text-muted-foreground">
              Воспроизводить приятный звук при получении новых задач
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Switch
              checked={soundEnabled}
              onCheckedChange={handleSoundToggle}
              aria-label="Включить звуковые уведомления"
            />
            {soundEnabled && (
              <Button
                variant="outline"
                size="sm"
                onClick={handleTestSound}
                className="ml-2"
              >
                Тест
              </Button>
            )}
          </div>
        </div>

        {/* Браузерные уведомления */}
        <div className="flex items-center justify-between space-x-2">
          <div className="space-y-1">
            <Label className="text-base font-medium flex items-center gap-2">
              {browserNotificationsEnabled ? <Bell className="h-4 w-4" /> : <BellOff className="h-4 w-4" />}
              Браузерные уведомления
            </Label>
            <p className="text-sm text-muted-foreground">
              Показывать уведомления в браузере даже когда вкладка неактивна
            </p>
          </div>
          <div className="flex items-center gap-2">
            {browserNotificationsEnabled ? (
              <div className="text-sm text-green-600 font-medium">Включены</div>
            ) : (
              <Button
                variant="outline"
                size="sm"
                onClick={handleRequestNotificationPermission}
              >
                Разрешить
              </Button>
            )}
          </div>
        </div>

        {/* Статус разрешений */}
        {'Notification' in window && (
          <div className={`p-4 rounded-lg ${
            Notification.permission === 'granted' 
              ? 'bg-green-50 dark:bg-green-950' 
              : Notification.permission === 'denied'
              ? 'bg-red-50 dark:bg-red-950'
              : 'bg-yellow-50 dark:bg-yellow-950'
          }`}>
            <h4 className={`text-sm font-medium mb-2 ${
              Notification.permission === 'granted'
                ? 'text-green-900 dark:text-green-100'
                : Notification.permission === 'denied'
                ? 'text-red-900 dark:text-red-100'
                : 'text-yellow-900 dark:text-yellow-100'
            }`}>
              {Notification.permission === 'granted' && '✅ Браузерные уведомления разрешены'}
              {Notification.permission === 'denied' && '❌ Браузерные уведомления заблокированы'}
              {Notification.permission === 'default' && '⚠️ Разрешение на уведомления не запрошено'}
            </h4>
            {Notification.permission === 'denied' && (
              <div className="text-sm text-red-800 dark:text-red-200">
                <p className="mb-2">Чтобы включить уведомления:</p>
                <ol className="list-decimal list-inside space-y-1 ml-2">
                  <li>Нажмите на иконку замка (🔒) или информации (ℹ️) в адресной строке</li>
                  <li>Найдите пункт "Уведомления" и выберите "Разрешить"</li>
                  <li>Обновите страницу</li>
                </ol>
              </div>
            )}
          </div>
        )}

        {/* Информация */}
        <div className="bg-blue-50 dark:bg-blue-950 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-blue-900 dark:text-blue-100 mb-2">
            💡 Полезная информация
          </h4>
          <ul className="text-sm text-blue-800 dark:text-blue-200 space-y-1">
            <li>• Звуковые уведомления работают только когда вкладка активна</li>
            <li>• Браузерные уведомления показываются даже в фоновом режиме</li>
            <li>• Уведомления приходят только исполнителям задач</li>
            <li>• Настройки сохраняются в браузере автоматически</li>
          </ul>
        </div>
      </CardContent>
    </Card>
  );
};