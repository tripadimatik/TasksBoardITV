const { spawn } = require('child_process');
const os = require('os');
const fs = require('fs');
const path = require('path');

// Функция для получения локального IP
function getLocalIP() {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        return iface.address;
      }
    }
  }
  return 'localhost';
}

// Проверяем наличие SSL сертификатов
function checkSSLCerts() {
  const certsDir = path.join(__dirname, 'server', 'certs');
  const keyPath = path.join(certsDir, 'key.pem');
  const certPath = path.join(certsDir, 'cert.pem');
  
  return fs.existsSync(keyPath) && fs.existsSync(certPath);
}

console.log('🚀 Запуск Vite сервера разработки...');
console.log('');

// Запускаем Vite напрямую
const viteProcess = spawn('npx', ['vite'], {
  stdio: 'pipe',
  shell: true,
  cwd: __dirname
});

let viteStarted = false;
const localIP = getLocalIP();
const hasSSL = checkSSLCerts();

viteProcess.stdout.on('data', (data) => {
  const output = data.toString();
  process.stdout.write(output);
  
  // Когда Vite запустился, показываем дополнительную информацию
  if (output.includes('ready in') && !viteStarted) {
    viteStarted = true;
    
    console.log('');
    console.log('🌐 Доступные адреса фронтенда:');
    if (hasSSL) {
      console.log(`   ➜  Local:   https://localhost:8080/`);
      console.log(`   ➜  Network: https://${localIP}:8080/`);
    } else {
      console.log(`   ➜  Local:   http://localhost:8080/`);
      console.log(`   ➜  Network: http://${localIP}:8080/`);
    }
    
    console.log('');
    console.log('📊 Доступные адреса для API сервера:');
    console.log(`   🌐 HTTP:  http://localhost:3001/api`);
    console.log(`   🌐 HTTP:  http://${localIP}:3001/api`);
    
    if (hasSSL) {
      console.log(`   🔒 HTTPS: https://localhost:3002/api`);
      console.log(`   🔒 HTTPS: https://${localIP}:3002/api`);
    } else {
      console.log('   ⚠️  HTTPS недоступен (нет SSL сертификатов)');
    }
    
    console.log('');
    if (hasSSL) {
      console.log('✅ HTTPS включен для фронтенда и API!');
      console.log('📱 Используйте HTTPS ссылки для работы уведомлений!');
    } else {
      console.log('⚠️  HTTPS недоступен - уведомления работать не будут!');
    }
    console.log('🔧 Для запуска API сервера выполните: npm run server');
    console.log('');
  }
});

viteProcess.stderr.on('data', (data) => {
  process.stderr.write(data);
});

viteProcess.on('close', (code) => {
  console.log(`\n🛑 Vite сервер завершен с кодом ${code}`);
  process.exit(code);
});

// Обработка сигналов для корректного завершения
process.on('SIGINT', () => {
  console.log('\n🛑 Завершение работы...');
  viteProcess.kill('SIGINT');
});

process.on('SIGTERM', () => {
  viteProcess.kill('SIGTERM');
});