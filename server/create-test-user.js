const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');

const prisma = new PrismaClient();

async function createTestUsers() {
  try {
    console.log('🔄 Создание тестовых пользователей...');
    
    // Проверяем, есть ли уже пользователи
    const existingUsers = await prisma.user.findMany();
    console.log(`📊 Найдено пользователей в базе: ${existingUsers.length}`);
    
    if (existingUsers.length > 0) {
      console.log('👥 Существующие пользователи:');
      existingUsers.forEach(user => {
        console.log(`  - ${user.email} (${user.role}) - ${user.firstName} ${user.lastName}`);
      });
    }
    
    // Создаем тестовых пользователей если их нет
    const testUsers = [
      {
        email: 'boss@company.com',
        password: 'boss123',
        firstName: 'Иван',
        lastName: 'Петров',
        patronymic: 'Сергеевич',
        role: 'BOSS'
      },
      {
        email: 'admin@company.com',
        password: 'admin123',
        firstName: 'Мария',
        lastName: 'Иванова',
        patronymic: 'Александровна',
        role: 'ADMIN'
      },
      {
        email: 'user@company.com',
        password: 'user123',
        firstName: 'Алексей',
        lastName: 'Сидоров',
        patronymic: 'Михайлович',
        role: 'USER'
      }
    ];
    
    for (const userData of testUsers) {
      const existingUser = await prisma.user.findUnique({
        where: { email: userData.email }
      });
      
      if (!existingUser) {
        const passwordHash = await bcrypt.hash(userData.password, 10);
        
        const user = await prisma.user.create({
          data: {
            email: userData.email,
            passwordHash,
            firstName: userData.firstName,
            lastName: userData.lastName,
            patronymic: userData.patronymic,
            role: userData.role
          }
        });
        
        console.log(`✅ Создан пользователь: ${user.email} (${user.role})`);
        console.log(`   Пароль: ${userData.password}`);
      } else {
        console.log(`⚠️  Пользователь ${userData.email} уже существует`);
      }
    }
    
    console.log('\n🎉 Готово! Теперь вы можете войти в систему используя:');
    console.log('👑 Начальник: boss@company.com / boss123');
    console.log('🔧 Админ: admin@company.com / admin123');
    console.log('👤 Пользователь: user@company.com / user123');
    
  } catch (error) {
    console.error('❌ Ошибка при создании пользователей:', error);
  } finally {
    await prisma.$disconnect();
  }
}

createTestUsers();