const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

async function checkUserRoles() {
  try {
    console.log('🔍 Проверка ролей пользователей в базе данных...');
    
    const users = await prisma.user.findMany({
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        role: true,
        createdAt: true
      },
      orderBy: {
        email: 'asc'
      }
    });
    
    if (users.length === 0) {
      console.log('❌ Пользователи не найдены в базе данных');
      return;
    }
    
    console.log(`\n📊 Найдено пользователей: ${users.length}\n`);
    
    users.forEach((user, index) => {
      console.log(`${index + 1}. 👤 ${user.firstName} ${user.lastName}`);
      console.log(`   📧 Email: ${user.email}`);
      console.log(`   🎭 Роль: ${user.role}`);
      console.log(`   📅 Создан: ${user.createdAt.toLocaleString('ru-RU')}`);
      console.log(`   🆔 ID: ${user.id}`);
      console.log('');
    });
    
    // Проверим распределение ролей
    const roleStats = users.reduce((acc, user) => {
      acc[user.role] = (acc[user.role] || 0) + 1;
      return acc;
    }, {});
    
    console.log('📈 Статистика ролей:');
    Object.entries(roleStats).forEach(([role, count]) => {
      console.log(`   ${role}: ${count} пользователей`);
    });
    
  } catch (error) {
    console.error('❌ Ошибка при проверке ролей:', error.message);
  } finally {
    await prisma.$disconnect();
  }
}

checkUserRoles();