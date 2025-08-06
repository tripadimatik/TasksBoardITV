// Используем встроенный fetch в Node.js 18+
const API_BASE_URL = 'http://localhost:3001/api';

// Тестовые пользователи
const testUsers = [
  { email: 'boss@company.com', password: 'password123' },
  { email: 'admin@company.com', password: 'password123' },
  { email: 'user@company.com', password: 'password123' }
];

async function testLogin(email, password) {
  try {
    console.log(`\n🔐 Тестируем вход для: ${email}`);
    
    const response = await fetch(`${API_BASE_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    
    const data = await response.json();
    
    if (response.ok) {
      console.log('✅ Успешный вход!');
      console.log(`   Пользователь: ${data.user.firstName} ${data.user.lastName}`);
      console.log(`   Роль: ${data.user.role}`);
      console.log(`   Токен: ${data.token.substring(0, 20)}...`);
      return true;
    } else {
      console.log('❌ Ошибка входа:');
      console.log(`   Статус: ${response.status}`);
      console.log(`   Ошибка: ${data.error || data.message}`);
      return false;
    }
  } catch (error) {
    console.log('❌ Ошибка сети:', error.message);
    return false;
  }
}

async function testAllUsers() {
  console.log('🧪 Тестирование аутентификации пользователей\n');
  
  let successCount = 0;
  
  for (const user of testUsers) {
    const success = await testLogin(user.email, user.password);
    if (success) successCount++;
  }
  
  console.log(`\n📊 Результат: ${successCount}/${testUsers.length} пользователей успешно вошли в систему`);
  
  if (successCount === testUsers.length) {
    console.log('🎉 Все тесты прошли успешно!');
  } else {
    console.log('⚠️  Некоторые тесты не прошли. Проверьте базу данных и сервер.');
  }
}

// Запуск тестов
testAllUsers().catch(console.error);