const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');

const prisma = new PrismaClient();

async function updatePasswords() {
  try {
    console.log('🔄 Обновляем пароли для тестовых пользователей...\n');
    
    const testUsers = [
      { email: 'boss@company.com', password: 'password123' },
      { email: 'admin@company.com', password: 'password123' },
      { email: 'user@company.com', password: 'password123' }
    ];
    
    for (const testUser of testUsers) {
      console.log(`🔐 Обновляем пароль для: ${testUser.email}`);
      
      // Хешируем новый пароль
      const passwordHash = await bcrypt.hash(testUser.password, 10);
      
      // Обновляем пользователя
      const updatedUser = await prisma.user.update({
        where: { email: testUser.email },
        data: { passwordHash },
        select: {
          id: true,
          email: true,
          firstName: true,
          lastName: true,
          role: true
        }
      });
      
      console.log(`✅ Пароль обновлен для: ${updatedUser.firstName} ${updatedUser.lastName} (${updatedUser.role})`);
      
      // Проверяем новый пароль
      const isValid = await bcrypt.compare(testUser.password, passwordHash);
      console.log(`🔍 Проверка пароля: ${isValid ? '✅ УСПЕШНО' : '❌ ОШИБКА'}`);
      console.log('─'.repeat(50));
    }
    
    console.log('\n🎉 Все пароли успешно обновлены!');
    console.log('\n📋 Данные для входа:');
    console.log('• boss@company.com / password123');
    console.log('• admin@company.com / password123');
    console.log('• user@company.com / password123');
    
  } catch (error) {
    console.error('❌ Ошибка при обновлении паролей:', error);
  } finally {
    await prisma.$disconnect();
  }
}

updatePasswords();