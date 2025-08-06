const { spawn } = require('child_process');
const path = require('path');

console.log('🚀 Запуск Task Manager в режиме разработки...');
console.log('');

// Запускаем frontend (Vite)
const frontend = spawn('npm', ['run', 'dev'], {
  cwd: process.cwd(),
  stdio: 'pipe',
  shell: true
});

// Запускаем backend (Express)
const backend = spawn('npm', ['run', 'server'], {
  cwd: process.cwd(),
  stdio: 'pipe',
  shell: true
});

let frontendReady = false;
let backendReady = false;
let httpsReady = false;

// Обработка вывода frontend
frontend.stdout.on('data', (data) => {
  const output = data.toString();
  process.stdout.write(output);
  
  if (output.includes('ready in') && !frontendReady) {
    frontendReady = true;
    checkAndShowUrls();
  }
});

frontend.stderr.on('data', (data) => {
  process.stderr.write(data);
});

// Обработка вывода backend
backend.stdout.on('data', (data) => {
  const output = data.toString();
  process.stdout.write(output);
  
  if (output.includes('HTTP сервер запущен') && !backendReady) {
    backendReady = true;
    checkAndShowUrls();
  }
  
  if (output.includes('HTTPS сервер запущен') && !httpsReady) {
    httpsReady = true;
    checkAndShowUrls();
  }
});

backend.stderr.on('data', (data) => {
  process.stderr.write(data);
});

// Функция для отображения всех URL
function checkAndShowUrls() {
  if (frontendReady && backendReady) {
    setTimeout(() => {
      console.log('');
      console.log('🌐 ===== ДОСТУПНЫЕ АДРЕСА =====');
      console.log('');
      console.log('📱 FRONTEND (Клиентская часть):');
      console.log('   🔗 HTTP:  http://localhost:8080/');
      console.log('   🔗 Сеть:  http://192.168.8.69:8080/');
      console.log('');
      console.log('🔧 BACKEND API:');
      console.log('   🔗 HTTP:  http://localhost:3001/api');
      if (httpsReady) {
        console.log('   🔐 HTTPS: https://localhost:3002/api');
        console.log('   🔐 Сеть:  https://192.168.8.69:3002/api');
      }
      console.log('');
      console.log('✅ ДЛЯ РАБОТЫ УВЕДОМЛЕНИЙ:');
      if (httpsReady) {
        console.log('   🔐 Используйте: https://localhost:3002');
        console.log('   🔐 Или в сети:  https://192.168.8.69:3002');
      } else {
        console.log('   ⚠️  HTTPS недоступен - уведомления не будут работать');
        console.log('   💡 Запустите: node generate-ssl.cjs');
      }
      console.log('');
      console.log('===============================');
      console.log('');
    }, 1000);
  }
}

// Обработка завершения
process.on('SIGINT', () => {
  console.log('\n🛑 Завершение работы...');
  frontend.kill('SIGINT');
  backend.kill('SIGINT');
  process.exit(0);
});

process.on('SIGTERM', () => {
  frontend.kill('SIGTERM');
  backend.kill('SIGTERM');
  process.exit(0);
});

frontend.on('exit', (code) => {
  if (code !== 0) {
    console.log(`❌ Frontend завершился с кодом ${code}`);
  }
});

backend.on('exit', (code) => {
  if (code !== 0) {
    console.log(`❌ Backend завершился с кодом ${code}`);
  }
});