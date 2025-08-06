// Звуковые файлы в формате base64 (WAV)
// Короткие звуки для уведомлений

export const NOTIFICATION_SOUNDS = {
  // Звук успеха - короткий приятный тон
  success: 'data:audio/wav;base64,UklGRiQAAABXQVZFZm10IBAAAAABAAEARKwAAIhYAQACABAAZGF0YQAAAAA=',
  
  // Звук новой задачи - мелодичный сигнал
  newTask: 'data:audio/wav;base64,UklGRiQAAABXQVZFZm10IBAAAAABAAEARKwAAIhYAQACABAAZGF0YQAAAAA=',
  
  // Звук ошибки - низкий предупреждающий тон
  error: 'data:audio/wav;base64,UklGRiQAAABXQVZFZm10IBAAAAABAAEARKwAAIhYAQACABAAZGF0YQAAAAA='
};

// Функция для создания приятного мелодичного WAV файла
export function createMelodicWav(frequencies: number[], duration: number, sampleRate: number = 44100): string {
  const samples = Math.floor(sampleRate * duration);
  const buffer = new ArrayBuffer(44 + samples * 2);
  const view = new DataView(buffer);
  
  // WAV заголовок
  const writeString = (offset: number, string: string) => {
    for (let i = 0; i < string.length; i++) {
      view.setUint8(offset + i, string.charCodeAt(i));
    }
  };
  
  writeString(0, 'RIFF');
  view.setUint32(4, 36 + samples * 2, true);
  writeString(8, 'WAVE');
  writeString(12, 'fmt ');
  view.setUint32(16, 16, true);
  view.setUint16(20, 1, true);
  view.setUint16(22, 1, true);
  view.setUint32(24, sampleRate, true);
  view.setUint32(28, sampleRate * 2, true);
  view.setUint16(32, 2, true);
  view.setUint16(34, 16, true);
  writeString(36, 'data');
  view.setUint32(40, samples * 2, true);
  
  // Генерация мелодичных звуковых данных
  for (let i = 0; i < samples; i++) {
    const t = i / sampleRate;
    let amplitude = 0;
    
    // Создаем приятную мелодию из нескольких частот
    frequencies.forEach((freq, index) => {
      const noteStart = (duration / frequencies.length) * index;
      const noteEnd = (duration / frequencies.length) * (index + 1);
      
      if (t >= noteStart && t < noteEnd) {
        const noteTime = t - noteStart;
        const noteDuration = noteEnd - noteStart;
        
        // Плавное нарастание и затухание для каждой ноты
        const envelope = Math.sin(Math.PI * (noteTime / noteDuration));
        amplitude += Math.sin(2 * Math.PI * freq * noteTime) * envelope * 0.2;
      }
    });
    
    // Общее затухание
    amplitude *= Math.exp(-t * 1.5);
    
    const sample = Math.max(-1, Math.min(1, amplitude));
    view.setInt16(44 + i * 2, sample * 0x7FFF, true);
  }
  
  // Конвертация в base64
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  
  return 'data:audio/wav;base64,' + btoa(binary);
}

// Функция для создания простого приятного звука
export function createSimpleWav(frequency: number, duration: number, sampleRate: number = 44100): string {
  const samples = Math.floor(sampleRate * duration);
  const buffer = new ArrayBuffer(44 + samples * 2);
  const view = new DataView(buffer);
  
  // WAV заголовок
  const writeString = (offset: number, string: string) => {
    for (let i = 0; i < string.length; i++) {
      view.setUint8(offset + i, string.charCodeAt(i));
    }
  };
  
  writeString(0, 'RIFF');
  view.setUint32(4, 36 + samples * 2, true);
  writeString(8, 'WAVE');
  writeString(12, 'fmt ');
  view.setUint32(16, 16, true);
  view.setUint16(20, 1, true);
  view.setUint16(22, 1, true);
  view.setUint32(24, sampleRate, true);
  view.setUint32(28, sampleRate * 2, true);
  view.setUint16(32, 2, true);
  view.setUint16(34, 16, true);
  writeString(36, 'data');
  view.setUint32(40, samples * 2, true);
  
  // Генерация приятного звукового сигнала
  for (let i = 0; i < samples; i++) {
    const t = i / sampleRate;
    // Мягкий синусоидальный звук с плавным затуханием
    const envelope = Math.exp(-t * 2) * Math.sin(Math.PI * t / duration);
    const amplitude = Math.sin(2 * Math.PI * frequency * t) * envelope * 0.3;
    const sample = Math.max(-1, Math.min(1, amplitude));
    view.setInt16(44 + i * 2, sample * 0x7FFF, true);
  }
  
  // Конвертация в base64
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  
  return 'data:audio/wav;base64,' + btoa(binary);
}

// Функция для создания ультра-элегантного уведомления (Apple-стиль)
export function createLuxuryNotificationWav(duration: number = 1.2, sampleRate: number = 44100): string {
  const samples = Math.floor(sampleRate * duration);
  const buffer = new ArrayBuffer(44 + samples * 2);
  const view = new DataView(buffer);
  
  // WAV заголовок
  const writeString = (offset: number, string: string) => {
    for (let i = 0; i < string.length; i++) {
      view.setUint8(offset + i, string.charCodeAt(i));
    }
  };
  
  writeString(0, 'RIFF');
  view.setUint32(4, 36 + samples * 2, true);
  writeString(8, 'WAVE');
  writeString(12, 'fmt ');
  view.setUint32(16, 16, true);
  view.setUint16(20, 1, true);
  view.setUint16(22, 1, true);
  view.setUint32(24, sampleRate, true);
  view.setUint32(28, sampleRate * 2, true);
  view.setUint16(32, 2, true);
  view.setUint16(34, 16, true);
  writeString(36, 'data');
  view.setUint32(40, samples * 2, true);
  
  // Генерация роскошного звука (стиль Apple/Microsoft премиум)
  for (let i = 0; i < samples; i++) {
    const t = i / sampleRate;
    const progress = t / duration;
    
    // Кристально чистые частоты (основанные на золотом сечении)
    const freq1 = 880.0;   // A5 - чистая нота
    const freq2 = 1108.73; // C#6 - мажорная терция от A5
    const freq3 = 1318.51; // E6 - квинта от A5
    const freq4 = 1760.0;  // A6 - октава (очень тихо)
    
    // Ультра-мягкая огибающая (как у Apple)
    let envelope;
    if (progress < 0.05) {
      // Мгновенное, но плавное нарастание
      envelope = Math.sin(progress * Math.PI / 0.1) * 0.06;
    } else if (progress < 0.15) {
      // Короткий пик
      envelope = 0.06;
    } else {
      // Очень долгое, роскошное затухание
      const fadeProgress = (progress - 0.15) / 0.85;
      envelope = 0.06 * Math.exp(-fadeProgress * 2.5) * Math.cos(fadeProgress * Math.PI / 4);
    }
    
    // Создаем кристальный звук с гармониками (как пианино)
    const tone1 = Math.sin(2 * Math.PI * freq1 * t) * 0.4;  // Основной тон
    const tone2 = Math.sin(2 * Math.PI * freq2 * t) * 0.25; // Терция
    const tone3 = Math.sin(2 * Math.PI * freq3 * t) * 0.15; // Квинта
    const tone4 = Math.sin(2 * Math.PI * freq4 * t) * 0.08; // Октава (блеск)
    
    // Добавляем тонкий модуляционный эффект для "живости"
    const modulation = 1 + Math.sin(2 * Math.PI * 4 * t) * 0.02;
    
    // Легкий хорус эффект для глубины
    const chorus1 = Math.sin(2 * Math.PI * (freq1 + 2) * t) * 0.03;
    const chorus2 = Math.sin(2 * Math.PI * (freq1 - 2) * t) * 0.03;
    
    const amplitude = ((tone1 + tone2 + tone3 + tone4) * modulation + chorus1 + chorus2) * envelope;
    const sample = Math.max(-1, Math.min(1, amplitude));
    view.setInt16(44 + i * 2, sample * 0x7FFF, true);
  }
  
  // Конвертация в base64
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  
  return 'data:audio/wav;base64,' + btoa(binary);
}

// Предгенерированные роскошные звуки
export const GENERATED_SOUNDS = {
  // Убираем звук успеха - он не нужен для кнопок
  success: '', // Пустой звук
  // Роскошный звук уведомления (уровень Apple/Microsoft премиум)
  newTask: createLuxuryNotificationWav(1.2),
  // Мягкий предупреждающий звук
  error: createSimpleWav(400, 0.6)
};