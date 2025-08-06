const { initializeApp } = require('firebase/app');
const { getFirestore, collection, getDocs } = require('firebase/firestore');
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');

// Firebase конфигурация (из вашего существующего проекта)
const firebaseConfig = {
  apiKey: "AIzaSyAqqwDawaB7prRaDnHpNx6pwP2_eUYWm0M",
  authDomain: "taskmanager-73f44.firebaseapp.com",
  projectId: "taskmanager-73f44",
  storageBucket: "taskmanager-73f44.firebasestorage.app",
  messagingSenderId: "172331167397",
  appId: "1:172331167397:web:cb16b595840c76bb0a274c",
  measurementId: "G-P8N5Z40QNJ"
};

// Инициализация Firebase
const app = initializeApp(firebaseConfig);
const db = getFirestore(app);

// Инициализация Prisma
const prisma = new PrismaClient();

// Маппинг ролей
const mapRole = (firebaseRole) => {
  const roleMap = {
    'user': 'USER',
    'admin': 'ADMIN',
    'boss': 'BOSS'
  };
  return roleMap[firebaseRole] || 'USER';
};

// Маппинг статусов
const mapStatus = (firebaseStatus) => {
  const statusMap = {
    'назначено': 'ASSIGNED',
    'в работе': 'IN_PROGRESS',
    'выполнено': 'COMPLETED',
    'доработка': 'REVISION'
  };
  return statusMap[firebaseStatus] || 'ASSIGNED';
};

// Маппинг приоритетов
const mapPriority = (firebasePriority) => {
  const priorityMap = {
    'низкий': 'LOW',
    'средний': 'MEDIUM',
    'высокий': 'HIGH'
  };
  return priorityMap[firebasePriority] || 'MEDIUM';
};

// Функция для генерации временного пароля
const generateTempPassword = () => {
  return Math.random().toString(36).slice(-8);
};

// Миграция пользователей
async function migrateUsers() {
  console.log('🔄 Начинаем миграцию пользователей...');
  
  try {
    const usersSnapshot = await getDocs(collection(db, 'users'));
    const users = [];
    
    for (const doc of usersSnapshot.docs) {
      const userData = doc.data();
      const tempPassword = generateTempPassword();
      const hashedPassword = await bcrypt.hash(tempPassword, 10);
      
      const user = {
        id: doc.id,
        email: userData.email || `user_${doc.id}@example.com`,
        password: hashedPassword,
        firstName: userData.firstName || 'Имя',
        lastName: userData.lastName || 'Фамилия',
        patronymic: userData.patronymic || null,
        role: mapRole(userData.role)
      };
      
      users.push(user);
      console.log(`📝 Пользователь: ${user.email}, временный пароль: ${tempPassword}`);
    }
    
    // Создаем пользователей в PostgreSQL
    for (const user of users) {
      try {
        await prisma.user.create({
          data: user
        });
        console.log(`✅ Пользователь ${user.email} успешно создан`);
      } catch (error) {
        if (error.code === 'P2002') {
          console.log(`⚠️  Пользователь ${user.email} уже существует, пропускаем`);
        } else {
          console.error(`❌ Ошибка при создании пользователя ${user.email}:`, error.message);
        }
      }
    }
    
    console.log(`✅ Миграция пользователей завершена. Обработано: ${users.length}`);
    return users;
  } catch (error) {
    console.error('❌ Ошибка при миграции пользователей:', error);
    throw error;
  }
}

// Миграция задач
async function migrateTasks() {
  console.log('🔄 Начинаем миграцию задач...');
  
  try {
    const tasksSnapshot = await getDocs(collection(db, 'tasks'));
    const tasks = [];
    
    for (const doc of tasksSnapshot.docs) {
      const taskData = doc.data();
      
      // Преобразуем Firebase Timestamp в Date
      const createdAt = taskData.createdAt?.toDate ? taskData.createdAt.toDate() : new Date();
      const updatedAt = taskData.updatedAt?.toDate ? taskData.updatedAt.toDate() : new Date();
      const deadline = taskData.deadline ? new Date(taskData.deadline) : null;
      
      const task = {
        id: doc.id,
        title: taskData.title || 'Без названия',
        description: taskData.description || '',
        priority: mapPriority(taskData.priority),
        deadline: deadline,
        status: mapStatus(taskData.status),
        assigneeId: taskData.assigneeId || null,
        assigneeName: taskData.assigneeName || null,
        createdBy: taskData.createdBy || null,
        updatedBy: taskData.updatedBy || null,
        reportFile: taskData.reportFile ? JSON.stringify(taskData.reportFile) : null,
        createdAt: createdAt,
        updatedAt: updatedAt
      };
      
      tasks.push(task);
    }
    
    // Создаем задачи в PostgreSQL
    for (const task of tasks) {
      try {
        await prisma.task.create({
          data: task
        });
        console.log(`✅ Задача "${task.title}" успешно создана`);
      } catch (error) {
        if (error.code === 'P2002') {
          console.log(`⚠️  Задача "${task.title}" уже существует, пропускаем`);
        } else {
          console.error(`❌ Ошибка при создании задачи "${task.title}":`, error.message);
        }
      }
    }
    
    console.log(`✅ Миграция задач завершена. Обработано: ${tasks.length}`);
    return tasks;
  } catch (error) {
    console.error('❌ Ошибка при миграции задач:', error);
    throw error;
  }
}

// Основная функция миграции
async function migrate() {
  console.log('🚀 Начинаем миграцию данных из Firebase в PostgreSQL...');
  console.log('=' .repeat(60));
  
  try {
    // Проверяем подключение к базе данных
    await prisma.$connect();
    console.log('✅ Подключение к PostgreSQL установлено');
    
    // Мигрируем пользователей
    const users = await migrateUsers();
    
    console.log('\n' + '=' .repeat(60));
    
    // Мигрируем задачи
    const tasks = await migrateTasks();
    
    console.log('\n' + '=' .repeat(60));
    console.log('🎉 Миграция успешно завершена!');
    console.log(`📊 Статистика:`);
    console.log(`   - Пользователей: ${users.length}`);
    console.log(`   - Задач: ${tasks.length}`);
    
    console.log('\n📋 Важная информация:');
    console.log('   - Для всех пользователей созданы временные пароли (см. выше)');
    console.log('   - Пользователи должны будут сменить пароли при первом входе');
    console.log('   - Проверьте корректность данных в PostgreSQL');
    
  } catch (error) {
    console.error('💥 Критическая ошибка при миграции:', error);
    process.exit(1);
  } finally {
    await prisma.$disconnect();
    console.log('\n🔌 Отключение от базы данных');
  }
}

// Запускаем миграцию
if (require.main === module) {
  migrate()
    .then(() => {
      console.log('\n✨ Скрипт миграции завершен');
      process.exit(0);
    })
    .catch((error) => {
      console.error('💥 Неожиданная ошибка:', error);
      process.exit(1);
    });
}

module.exports = { migrate };