// Утилита для звуковых уведомлений
import { GENERATED_SOUNDS } from './sounds';

// Используем сгенерированные звуки
const SOUNDS = GENERATED_SOUNDS;

class NotificationSound {
  private audioContext: AudioContext | null = null;
  private isEnabled: boolean = true;
  private audioCache: Map<string, HTMLAudioElement> = new Map();

  constructor() {
    // Проверяем поддержку Web Audio API
    if (typeof window !== 'undefined' && (window.AudioContext || (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext)) {
      this.audioContext = new (window.AudioContext || (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext)();
    }
    
    // Предзагружаем звуки
    this.preloadSounds();
  }

  // Предзагрузка звуков для быстрого воспроизведения
  private preloadSounds() {
    Object.entries(SOUNDS).forEach(([key, dataUrl]) => {
      // Пропускаем пустые звуки
      if (!dataUrl || dataUrl === '') {
        return;
      }
      
      try {
        const audio = new Audio(dataUrl);
        audio.preload = 'auto';
        audio.volume = 0.4;
        // Добавляем обработчик ошибок
        audio.addEventListener('error', (e) => {
          console.warn(`Ошибка загрузки звука ${key}:`, e);
        });
        this.audioCache.set(key, audio);
      } catch (error) {
        console.warn(`Не удалось создать аудио для ${key}:`, error);
      }
    });
  }

  // Воспроизвести звук через HTML5 Audio (более надёжно)
  private async playAudioFile(soundKey: string) {
    if (!this.isNotificationEnabled()) return;

    // Проверяем, есть ли звук для воспроизведения
    const soundData = SOUNDS[soundKey as keyof typeof SOUNDS];
    if (!soundData || soundData === '') {
      // Если звук пустой или отсутствует, не воспроизводим
      return;
    }

    try {
      const audio = this.audioCache.get(soundKey);
      if (audio) {
        // Клонируем аудио для возможности одновременного воспроизведения
        const audioClone = audio.cloneNode() as HTMLAudioElement;
        audioClone.volume = 0.4;
        audioClone.currentTime = 0;
        
        // Пытаемся воспроизвести звук
        const playPromise = audioClone.play();
        if (playPromise !== undefined) {
          await playPromise.catch(error => {
            console.warn('Не удалось воспроизвести звук:', error);
            // Fallback на Web Audio API
            this.fallbackToWebAudio(soundKey);
          });
        }
      } else {
        // Если звук не загружен, используем fallback
        this.fallbackToWebAudio(soundKey);
      }
    } catch (error) {
      console.warn('Ошибка воспроизведения звука:', error);
      this.fallbackToWebAudio(soundKey);
    }
  }

  // Fallback на Web Audio API
  private fallbackToWebAudio(soundKey: string) {
    // Не воспроизводим fallback для пустого звука успеха
    if (soundKey === 'success') {
      return; // Не воспроизводим звук
    } else if (soundKey === 'newTask') {
      // Приятная мелодия для новой задачи
      setTimeout(() => this.createBeep(523, 150, 0.06), 0);
      setTimeout(() => this.createBeep(659, 150, 0.06), 300);
      setTimeout(() => this.createBeep(784, 150, 0.06), 600);
      setTimeout(() => this.createBeep(1047, 200, 0.06), 900);
    } else if (soundKey === 'error') {
      this.createBeep(400, 600, 0.06);
    }
  }

  // Включить/выключить звуковые уведомления
  setEnabled(enabled: boolean) {
    this.isEnabled = enabled;
    localStorage.setItem('notifications-sound-enabled', enabled.toString());
  }

  // Проверить, включены ли звуковые уведомления
  isNotificationEnabled(): boolean {
    const stored = localStorage.getItem('notifications-sound-enabled');
    return stored !== null ? stored === 'true' : this.isEnabled;
  }

  // Создать простой звуковой сигнал
  private createBeep(frequency: number = 800, duration: number = 200, volume: number = 0.1) {
    if (!this.audioContext || !this.isNotificationEnabled()) return;

    try {
      // Возобновляем контекст если он приостановлен
      if (this.audioContext.state === 'suspended') {
        this.audioContext.resume();
      }

      const oscillator = this.audioContext.createOscillator();
      const gainNode = this.audioContext.createGain();

      oscillator.connect(gainNode);
      gainNode.connect(this.audioContext.destination);

      oscillator.frequency.setValueAtTime(frequency, this.audioContext.currentTime);
      oscillator.type = 'sine';

      gainNode.gain.setValueAtTime(0, this.audioContext.currentTime);
      gainNode.gain.linearRampToValueAtTime(volume, this.audioContext.currentTime + 0.01);
      gainNode.gain.exponentialRampToValueAtTime(0.001, this.audioContext.currentTime + duration / 1000);

      oscillator.start(this.audioContext.currentTime);
      oscillator.stop(this.audioContext.currentTime + duration / 1000);
    } catch (error) {
      console.warn('Не удалось воспроизвести звуковое уведомление:', error);
    }
  }

  // Воспроизвести звук новой задачи
  playNewTaskSound() {
    this.playAudioFile('newTask');
  }

  // Воспроизвести звук успешного действия
  playSuccessSound() {
    this.playAudioFile('success');
  }

  // Воспроизвести звук ошибки
  playErrorSound() {
    this.playAudioFile('error');
  }

  // Запросить разрешение на уведомления (для мобильных устройств)
  async requestPermission(): Promise<boolean> {
    if (!('Notification' in window)) {
      return false;
    }

    if (Notification.permission === 'granted') {
      return true;
    }

    if (Notification.permission === 'denied') {
      return false;
    }

    const permission = await Notification.requestPermission();
    return permission === 'granted';
  }

  // Показать браузерное уведомление
  async showNotification(title: string, body: string, icon?: string) {
    const hasPermission = await this.requestPermission();
    
    if (hasPermission) {
      new Notification(title, {
        body,
        icon: icon || '/notification.svg',
        badge: '/notification.svg',
        tag: 'task-notification',
        requireInteraction: false,
        silent: false
      });
    }
  }
}

// Экспортируем единственный экземпляр
export const notificationSound = new NotificationSound();

// Хук для использования в компонентах
export const useNotifications = () => {
  return {
    playNewTaskSound: () => notificationSound.playNewTaskSound(),
    playSuccessSound: () => notificationSound.playSuccessSound(),
    playErrorSound: () => notificationSound.playErrorSound(),
    showNotification: (title: string, body: string, icon?: string) => 
      notificationSound.showNotification(title, body, icon),
    requestPermission: () => notificationSound.requestPermission(),
    setEnabled: (enabled: boolean) => notificationSound.setEnabled(enabled),
    isEnabled: () => notificationSound.isNotificationEnabled()
  };
};