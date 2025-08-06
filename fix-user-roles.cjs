const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

async function fixUserRoles() {
  try {
    console.log('🔧 Исправление ролей пользователей...');
    
    // Обновим роль для admin@company.com на ADMIN
    const adminUser = await prisma.user.findUnique({
      where: { email: 'admin@company.com' }
    });
    
    if (adminUser) {
      await prisma.user.update({
        where: { email: 'admin@company.com' },
        data: { 
          role: 'ADMIN',
          firstName: 'Мария',
          lastName: 'Иванова'
        }
      });
      console.log('✅ Роль admin@company.com обновлена на ADMIN');
    } else {
      // Создадим пользователя admin@company.com если его нет
      const bcrypt = require('bcryptjs');
      const hashedPassword = await bcrypt.hash('password123', 10);
      
      await prisma.user.create({
        data: {
          email: 'admin@company.com',
          passwordHash: hashedPassword,
          firstName: 'Мария',
          lastName: 'Иванова',
          role: 'ADMIN'
        }
      });
      console.log('✅ Создан пользователь admin@company.com с ролью ADMIN');
    }
    
    // Проверим и обновим boss@company.com
    const bossUser = await prisma.user.findUnique({
      where: { email: 'boss@company.com' }
    });
    
    if (bossUser && bossUser.role !== 'BOSS') {
      await prisma.user.update({
        where: { email: 'boss@company.com' },
        data: { role: 'BOSS' }
      });
      console.log('✅ Роль boss@company.com обновлена на BOSS');
    }
    
    // Проверим финальное состояние
    console.log('\n📊 Финальные роли пользователей:');
    const users = await prisma.user.findMany({
      where: {
        email: {
          in: ['boss@company.com', 'admin@company.com', 'user@company.com']
        }
      },
      select: {
        email: true,
        firstName: true,
        lastName: true,
        role: true
      }
    });
    
    users.forEach(user => {
      console.log(`👤 ${user.firstName} ${user.lastName} (${user.email}) - Роль: ${user.role}`);
    });
    
  } catch (error) {
    console.error('❌ Ошибка при исправлении ролей:', error.message);
  } finally {
    await prisma.$disconnect();
  }
}

fixUserRoles();