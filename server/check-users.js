const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');

const prisma = new PrismaClient();

async function checkUsers() {
  try {
    console.log('🔍 Проверяем пользователей в базе данных...\n');
    
    const users = await prisma.user.findMany({
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        role: true,
        passwordHash: true,
        createdAt: true
      }
    });
    
    if (users.length === 0) {
      console.log('❌ Пользователи не найдены в базе данных!');
      return;
    }
    
    console.log(`✅ Найдено ${users.length} пользователей:\n`);
    
    for (const user of users) {
      console.log(`📧 Email: ${user.email}`);
      console.log(`👤 Имя: ${user.firstName} ${user.lastName}`);
      console.log(`🔑 Роль: ${user.role}`);
      console.log(`🔒 Хеш пароля: ${user.passwordHash.substring(0, 20)}...`);
      console.log(`📅 Создан: ${user.createdAt}`);
      
      // Проверяем пароль 'password123'
      const isValidPassword = await bcrypt.compare('password123', user.passwordHash);
      console.log(`🔐 Пароль 'password123' подходит: ${isValidPassword ? '✅ ДА' : '❌ НЕТ'}`);
      
      console.log('─'.repeat(50));
    }
    
  } catch (error) {
    console.error('❌ Ошибка при проверке пользователей:', error);
  } finally {
    await prisma.$disconnect();
  }
}

checkUsers();