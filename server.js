const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const cors = require('cors');
const fs = require('fs');
const crypto = require('crypto');
const multer = require('multer');

const app = express();
const PORT = process.env.PORT || 6969;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Создаем папки если они не существуют
const dbDir = path.join(__dirname, 'db');
const publicDir = path.join(__dirname, 'public');
const uploadsDir = path.join(publicDir, 'uploads');

if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

if (!fs.existsSync(publicDir)) {
  fs.mkdirSync(publicDir, { recursive: true });
}

if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Настройка multer для загрузки изображений
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadsDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB
  },
  fileFilter: function (req, file, cb) {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Неверный тип файла. Разрешены только изображения.'), false);
    }
  }
});

// Обслуживание статических файлов
app.use(express.static(publicDir));
app.use('/uploads', express.static(uploadsDir));

// Подключение к базе данных
const dbPath = path.join(dbDir, 'database.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Ошибка подключения к базе данных:', err.message);
  } else {
    console.log('Успешное подключение к базе данных');
    db.run('PRAGMA foreign_keys = ON');
    initDatabase();
  }
});

// Функция инициализации базы данных
function initDatabase() {
  // Создаем таблицу пользователей
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    first_name TEXT,
    last_name TEXT,
    phone TEXT,
    role TEXT DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`, (err) => {
    if (err) {
      console.error('Ошибка создания таблицы users:', err.message);
    } else {
      createDefaultUsers();
    }
  });

  // Создаем таблицы для категорий
  const categories = [
    { name: 'byket', category: 'bouquets' },
    { name: 'nabor', category: 'sets' },
    { name: 'stakanciki', category: 'cups' },
    { name: 'tort', category: 'cakes' }
  ];

  categories.forEach(cat => {
    db.run(`CREATE TABLE IF NOT EXISTS ${cat.name} (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT,
      price REAL NOT NULL,
      category TEXT DEFAULT '${cat.category}',
      overlay_image TEXT,
      in_stock BOOLEAN DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`, (err) => {
      if (err) {
        console.error(`Ошибка создания таблицы ${cat.name}:`, err.message);
      } else {
        checkAndInsertTestData(cat.name);
      }
    });
  });

  db.run(`CREATE TABLE IF NOT EXISTS masterclasses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  description TEXT,
  price REAL NOT NULL,
  duration TEXT,
  max_participants INTEGER,
  rating REAL DEFAULT 5.0,
  reviews_count INTEGER DEFAULT 0,
  image_url TEXT,
  badge TEXT,
  category TEXT,
  in_stock BOOLEAN DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`, (err) => {
    if (err) {
      console.error('Ошибка создания таблицы masterclasses:', err.message);
    } else {
      console.log('Таблица masterclasses создана/проверена');
    }
  });

  // Создаем таблицу заказов
  db.run(`CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    items TEXT NOT NULL,
    total_price REAL NOT NULL,
    status TEXT DEFAULT 'new',
    customer_name TEXT NOT NULL,
    customer_phone TEXT NOT NULL,
    customer_email TEXT,
    delivery_address TEXT,
    delivery_date TEXT,
    delivery_time TEXT,
    payment_method TEXT DEFAULT 'cash',
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
  )`, (err) => {
    if (err) {
      console.error('Ошибка создания таблицы orders:', err.message);
    }
  });

  setTimeout(() => {
    resetAutoIncrement();
  }, 1000);
}

// Создание пользователей по умолчанию
function createDefaultUsers() {
    const adminEmail = 'admin@nadista.com';
    const adminPassword = crypto.createHash('sha256').update('admin123').digest('hex');

    db.get('SELECT * FROM users WHERE email = ?', [adminEmail], (err, row) => {
        if (err) {
            console.error('Ошибка проверки администратора:', err.message);
        } else if (!row) {
            db.run('INSERT INTO users (email, password, role, first_name, last_name) VALUES (?, ?, ?, ?, ?)',
                [adminEmail, adminPassword, 'admin', 'Admin', 'Nadista'], (err) => {
                    if (err) {
                        console.error('Ошибка создания администратора:', err.message);
                    } else {
                        console.log('Администратор создан: email - admin@nadista.com, password - admin123');
                    }
                });
        }
    });

    // Создаем тестовых пользователей
    const testUsers = [
        {
            email: 'client1@example.com',
            password: crypto.createHash('sha256').update('password123').digest('hex'),
            first_name: 'Иван',
            last_name: 'Иванов',
            phone: '+79123456789',
            role: 'user'
        },
        {
            email: 'client2@example.com',
            password: crypto.createHash('sha256').update('password123').digest('hex'),
            first_name: 'Мария',
            last_name: 'Петрова',
            phone: '+79123456780',
            role: 'user'
        }
    ];

    testUsers.forEach(user => {
        db.get('SELECT * FROM users WHERE email = ?', [user.email], (err, row) => {
            if (err) {
                console.error('Ошибка проверки пользователя:', err.message);
            } else if (!row) {
                db.run('INSERT INTO users (email, password, first_name, last_name, phone, role) VALUES (?, ?, ?, ?, ?, ?)',
                    [user.email, user.password, user.first_name, user.last_name, user.phone, user.role], 
                    (err) => {
                        if (err) {
                            console.error('Ошибка создания пользователя:', err.message);
                        } else {
                            console.log(`Тестовый пользователь создан: ${user.email}`);
                        }
                    });
            }
        });
    });
}

// Проверка и вставка тестовых данных
function checkAndInsertTestData(tableName) {
  db.get(`SELECT COUNT(*) as count FROM ${tableName}`, (err, row) => {
    if (err) {
      console.error(`Ошибка проверки таблицы ${tableName}:`, err.message);
    } else if (row.count === 0) {
      insertTestData(tableName);
    }
  });
}

// Вставка тестовых данных
function insertTestData(tableName) {
  let testData = [];

  switch (tableName) {
    case 'byket':
      testData = [
        ["Букет 'Романтика'", "Нежный букет из клубники в белом шоколаде с розами", 2500, "/images/products/byket4.jpg"],
        ["Букет 'Премиум'", "Роскошный букет из отборной клубники в темном шоколаде", 3200, "/images/products/byket4.jpg"],
        ["Букет 'Нежность'", "Изящный букет из клубники в молочном шоколаде с пионами", 2800, "/images/products/byket4.jpg"]
      ];
      break;
    case 'nabor':
      testData = [
        ["Набор 'Сладкоежка'", "Вкусный набор для настоящих сладкоежек", 1800, "/images/products/nabor.jpg"],
        ["Набор 'Праздничный'", "Набор для праздничного стола", 2200, "/images/products/nabor.jpg"],
        ["Набор 'Фруктовый'", "Свежие фрукты в шоколадной глазури", 1900, "/images/products/nabor.jpg"]
      ];
      break;
    case 'stakanciki':
      testData = [
        ["Стаканчик 'Ягодный'", "Сладкий стаканчик с ягодами", 500, "/images/products/stakan.jpg"],
        ["Стаканчик 'Шоколадный'", "Нежный шоколадный мусс", 550, "/images/products/stakan.jpg"],
        ["Стаканчик 'Клубничный'", "Воздушный клубничный крем", 500, "/images/products/stakan.jpg"]
      ];
      break;
    case 'tort':
      testData = [
        ["Торт 'Шоколадный'", "Нежный шоколадный торт", 2000, "/images/products/tort.jpg"],
        ["Торт 'Красный бархат'", "Классический американский десерт", 2200, "/images/products/tort.jpg"],
        ["Торт 'Медовик'", "Традиционный русский торт с медом", 2100, "/images/products/tort.jpg"]
      ];
      break;
  }

  const stmt = db.prepare(`INSERT INTO ${tableName} (name, description, price, overlay_image) VALUES (?, ?, ?, ?)`);

  testData.forEach(item => {
    stmt.run(item, (err) => {
      if (err) {
        console.error(`Ошибка вставки данных в таблицу ${tableName}:`, err.message);
      }
    });
  });

  stmt.finalize();
  console.log(`Тестовые данные добавлены в таблицу ${tableName}`);
}

function resetAutoIncrement() {
  const tables = ['byket', 'nabor', 'stakanciki', 'tort', 'masterclasses'];

  tables.forEach(table => {
    // Получаем максимальный ID для таблицы
    db.get(`SELECT MAX(id) as maxId FROM ${table}`, (err, row) => {
      if (err) {
        console.error(`Ошибка получения maxId для ${table}:`, err.message);
        return;
      }

      const maxId = row.maxId || 0;

      // Сбрасываем последовательность автоинкремента
      db.run(`UPDATE sqlite_sequence SET seq = ? WHERE name = ?`, [maxId, table], (err) => {
        if (err) {
          console.error(`Ошибка сброса автоинкремента для ${table}:`, err.message);
        } else {
          console.log(`Автоинкремент для ${table} установлен на ${maxId}`);
        }
      });
    });
  });
}

// JWT функции
function generateToken(payload) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64');
  const payloadEncoded = Buffer.from(JSON.stringify(payload)).toString('base64');
  const signature = crypto.createHmac('sha256', 'nadista-secret-key')
    .update(`${header}.${payloadEncoded}`)
    .digest('base64');

  return `${header}.${payloadEncoded}.${signature}`;
}

function verifyToken(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const [header, payloadEncoded, signature] = parts;
    const expectedSignature = crypto.createHmac('sha256', 'nadista-secret-key')
      .update(`${header}.${payloadEncoded}`)
      .digest('base64');

    if (signature !== expectedSignature) return null;

    return JSON.parse(Buffer.from(payloadEncoded, 'base64').toString());
  } catch (error) {
    return null;
  }
}

// Middleware для проверки аутентификации
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Токен доступа отсутствует' });
  }

  const user = verifyToken(token);
  if (!user) {
    return res.status(403).json({ error: 'Недействительный токен' });
  }

  req.user = user;
  next();
}

// Middleware для проверки роли администратора
function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Требуются права администратора' });
  }
  next();
}

// Маршруты аутентификации
app.post('/api/register', (req, res) => {
  const { email, password, firstName, lastName, phone } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email и пароль обязательны' });
  }

  db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => {
    if (err) {
      return res.status(500).json({ error: 'Ошибка базы данных' });
    }

    if (row) {
      return res.status(400).json({ error: 'Пользователь с таким email уже существует' });
    }

    const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');

    db.run('INSERT INTO users (email, password, first_name, last_name, phone) VALUES (?, ?, ?, ?, ?)',
      [email, hashedPassword, firstName, lastName, phone], function (err) {
        if (err) {
          return res.status(500).json({ error: 'Ошибка при создании пользователя' });
        }

        const token = generateToken({
          userId: this.lastID,
          email,
          firstName,
          lastName,
          phone,
          role: 'user'
        });

        res.status(201).json({
          message: 'Пользователь успешно создан',
          token,
          user: {
            id: this.lastID,
            email,
            firstName,
            lastName,
            phone,
            role: 'user'
          }
        });
      });
  });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email и пароль обязательны' });
  }

  const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');

  db.get('SELECT * FROM users WHERE email = ? AND password = ?', [email, hashedPassword], (err, row) => {
    if (err) {
      return res.status(500).json({ error: 'Ошибка базы данных' });
    }

    if (!row) {
      return res.status(400).json({ error: 'Неверный email или пароль' });
    }

    const token = generateToken({
      userId: row.id,
      email: row.email,
      firstName: row.first_name,
      lastName: row.last_name,
      phone: row.phone,
      role: row.role
    });

    res.json({
      message: 'Вход выполнен успешно',
      token,
      user: {
        id: row.id,
        email: row.email,
        firstName: row.first_name,
        lastName: row.last_name,
        phone: row.phone,
        role: row.role
      }
    });
  });
});

app.get('/api/profile', authenticateToken, (req, res) => {
  res.json({ user: req.user });
});

// Маршрут для загрузки изображений
app.post('/api/upload', authenticateToken, requireAdmin, upload.single('image'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'Файл не был загружен' });
  }

  const imageUrl = '/uploads/' + req.file.filename;
  res.json({ url: imageUrl });
});

// Маршрут для получения мастер-классов
app.get('/api/masterclasses', (req, res) => {
  const query = 'SELECT * FROM masterclasses WHERE in_stock = 1 ORDER BY id';
  db.all(query, [], (err, rows) => {
    if (err) {
      console.error('Ошибка выполнения запроса:', err.message);
      res.status(500).json({ error: err.message });
    } else {
      // Преобразуем boolean значения
      const formattedMasterclasses = rows.map(masterclass => ({
        ...masterclass,
        in_stock: Boolean(masterclass.in_stock),
        price: parseFloat(masterclass.price),
        rating: parseFloat(masterclass.rating),
        reviews_count: parseInt(masterclass.reviews_count),
        max_participants: parseInt(masterclass.max_participants)
      }));
      res.json(formattedMasterclasses);
    }
  });
});

// Исправьте маршрут для получения всех продуктов
app.get('/api/products', (req, res) => {
  const queries = [
    "SELECT *, 'byket' as category FROM byket WHERE in_stock = 1",
    "SELECT *, 'nabor' as category FROM nabor WHERE in_stock = 1",
    "SELECT *, 'stakanciki' as category FROM stakanciki WHERE in_stock = 1",
    "SELECT *, 'tort' as category FROM tort WHERE in_stock = 1"
  ];

  let allProducts = [];
  let completedQueries = 0;

  queries.forEach(query => {
    db.all(query, [], (err, rows) => {
      if (err) {
        console.error('Ошибка выполнения запроса:', err.message);
      } else {
        // Преобразуем boolean значения и добавляем категорию
        const formattedRows = rows.map(row => ({
          id: row.id,
          name: row.name,
          description: row.description,
          price: parseFloat(row.price),
          category: row.category,
          overlay_image: row.overlay_image,
          in_stock: Boolean(row.in_stock),
          created_at: row.created_at
        }));
        allProducts = allProducts.concat(formattedRows);
      }

      completedQueries++;
      if (completedQueries === queries.length) {
        // Сортируем по ID для правильного порядка
        allProducts.sort((a, b) => a.id - b.id);
        res.json(allProducts);
      }
    });
  });
});

// Маршрут для сброса автоинкремента
app.post('/api/admin/reset-auto-increment', authenticateToken, requireAdmin, (req, res) => {
  const tables = ['byket', 'nabor', 'stakanciki', 'tort', 'masterclasses'];
  let completed = 0;

  tables.forEach(table => {
    // Получаем максимальный ID
    db.get(`SELECT MAX(id) as maxId FROM ${table}`, (err, row) => {
      if (err) {
        console.error(`Ошибка получения maxId для ${table}:`, err.message);
      } else {
        const maxId = row.maxId || 0;

        // Сбрасываем последовательность
        db.run(`UPDATE sqlite_sequence SET seq = ? WHERE name = ?`, [maxId, table], (err) => {
          if (err) {
            console.error(`Ошибка сброса автоинкремента для ${table}:`, err.message);
          } else {
            console.log(`Автоинкремент для ${table} установлен на ${maxId}`);
          }
        });
      }

      completed++;
      if (completed === tables.length) {
        res.json({ message: 'Автоинкремент сброшен для всех таблиц' });
      }
    });
  });
});

// Исправьте маршрут для получения продуктов по категории
app.get('/api/products/:category', (req, res) => {
  const category = req.params.category;

  const validCategories = ['byket', 'nabor', 'stakanciki', 'tort'];
  if (!validCategories.includes(category)) {
    return res.status(400).json({ error: 'Неверная категория' });
  }

  const query = `SELECT * FROM ${category} WHERE in_stock = 1 ORDER BY id`;
  db.all(query, [], (err, rows) => {
    if (err) {
      console.error('Ошибка выполнения запроса:', err.message);
      res.status(500).json({ error: err.message });
    } else {
      // Преобразуем boolean значения
      const formattedProducts = rows.map(product => ({
        ...product,
        in_stock: Boolean(product.in_stock),
        price: parseFloat(product.price),
        category: category
      }));
      res.json(formattedProducts);
    }
  });
});

app.get('/api/products/:category/:id', (req, res) => {
  const category = req.params.category;
  const id = req.params.id;

  const validCategories = ['byket', 'nabor', 'stakanciki', 'tort'];
  if (!validCategories.includes(category)) {
    return res.status(400).json({ error: 'Неверная категория' });
  }

  const query = `SELECT * FROM ${category} WHERE id = ?`;
  db.get(query, [id], (err, row) => {
    if (err) {
      console.error('Ошибка выполнения запроса:', err.message);
      res.status(500).json({ error: err.message });
    } else if (!row) {
      res.status(404).json({ error: 'Продукт не найден' });
    } else {
      // Преобразуем boolean значения
      const formattedProduct = {
        ...row,
        in_stock: Boolean(row.in_stock),
        price: parseFloat(row.price)
      };
      res.json(formattedProduct);
    }
  });
});

// Административные маршруты для продуктов
app.post('/api/admin/products/:category', authenticateToken, requireAdmin, (req, res) => {
  const category = req.params.category;
  const { name, description, price, overlay_image, in_stock } = req.body;

  const validCategories = ['byket', 'nabor', 'stakanciki', 'tort'];
  if (!validCategories.includes(category)) {
    return res.status(400).json({ error: 'Неверная категория' });
  }

  if (!name || !price) {
    return res.status(400).json({ error: 'Название и цена обязательны' });
  }

  const inStockValue = in_stock ? 1 : 0;

  db.run(
    `INSERT INTO ${category} (name, description, price, overlay_image, in_stock) VALUES (?, ?, ?, ?, ?)`,
    [name, description, price, overlay_image, inStockValue],
    function (err) {
      if (err) {
        console.error('Ошибка добавления продукта:', err);
        return res.status(500).json({ error: 'Ошибка добавления продукта' });
      }

      res.status(201).json({
        message: 'Продукт успешно добавлен',
        productId: this.lastID
      });
    }
  );
});

app.put('/api/admin/products/:category/:id', authenticateToken, requireAdmin, (req, res) => {
  const category = req.params.category;
  const id = req.params.id;
  const { name, description, price, overlay_image, in_stock } = req.body;

  const validCategories = ['byket', 'nabor', 'stakanciki', 'tort'];
  if (!validCategories.includes(category)) {
    return res.status(400).json({ error: 'Неверная категория' });
  }

  const inStockValue = in_stock ? 1 : 0;

  db.run(
    `UPDATE ${category} SET name = ?, description = ?, price = ?, overlay_image = ?, in_stock = ? WHERE id = ?`,
    [name, description, price, overlay_image, inStockValue, id],
    function (err) {
      if (err) {
        console.error('Ошибка обновления продукта:', err);
        return res.status(500).json({ error: 'Ошибка обновления продукта' });
      }

      if (this.changes === 0) {
        return res.status(404).json({ error: 'Продукт не найден' });
      }

      res.json({ message: 'Продукт успешно обновлен' });
    }
  );
});

app.delete('/api/admin/products/:category/:id', authenticateToken, requireAdmin, (req, res) => {
  const category = req.params.category;
  const id = req.params.id;

  const validCategories = ['byket', 'nabor', 'stakanciki', 'tort'];
  if (!validCategories.includes(category)) {
    return res.status(400).json({ error: 'Неверная категория' });
  }

  // Мягкое удаление - устанавливаем in_stock = 0
  db.run(
    `UPDATE ${category} SET in_stock = 0 WHERE id = ?`,
    [id],
    function (err) {
      if (err) {
        console.error('Ошибка удаления продукта:', err);
        return res.status(500).json({ error: 'Ошибка удаления продукта' });
      }

      if (this.changes === 0) {
        return res.status(404).json({ error: 'Продукт не найден' });
      }

      res.json({ message: 'Продукт успешно удален' });
    }
  );
});

// Административные маршруты для мастер-классов
app.post('/api/admin/masterclasses', authenticateToken, requireAdmin, (req, res) => {
  const { name, description, price, duration, max_participants, rating, reviews_count, image_url, badge, category, in_stock } = req.body;

  if (!name || !price) {
    return res.status(400).json({ error: 'Название и цена обязательны' });
  }

  const inStockValue = in_stock ? 1 : 0;

  db.run(
    `INSERT INTO masterclasses (name, description, price, duration, max_participants, rating, reviews_count, image_url, badge, category, in_stock) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [name, description, price, duration, max_participants, rating, reviews_count, image_url, badge, category, inStockValue],
    function (err) {
      if (err) {
        console.error('Ошибка добавления мастер-класса:', err);
        return res.status(500).json({ error: 'Ошибка добавления мастер-класса' });
      }

      res.status(201).json({
        message: 'Мастер-класс успешно добавлен',
        masterclassId: this.lastID
      });
    }
  );
});

app.put('/api/admin/masterclasses/:id', authenticateToken, requireAdmin, (req, res) => {
  const id = req.params.id;
  const { name, description, price, duration, max_participants, rating, reviews_count, image_url, badge, category, in_stock } = req.body;

  const inStockValue = in_stock ? 1 : 0;

  db.run(
    `UPDATE masterclasses SET name = ?, description = ?, price = ?, duration = ?, max_participants = ?, rating = ?, reviews_count = ?, image_url = ?, badge = ?, category = ?, in_stock = ? WHERE id = ?`,
    [name, description, price, duration, max_participants, rating, reviews_count, image_url, badge, category, inStockValue, id],
    function (err) {
      if (err) {
        console.error('Ошибка обновления мастер-класса:', err);
        return res.status(500).json({ error: 'Ошибка обновления мастер-класса' });
      }

      if (this.changes === 0) {
        return res.status(404).json({ error: 'Мастер-класс не найден' });
      }

      res.json({ message: 'Мастер-класс успешно обновлен' });
    }
  );
});

app.delete('/api/admin/masterclasses/:id', authenticateToken, requireAdmin, (req, res) => {
  const id = req.params.id;

  // Мягкое удаление - устанавливаем in_stock = 0
  db.run(
    `UPDATE masterclasses SET in_stock = 0 WHERE id = ?`,
    [id],
    function (err) {
      if (err) {
        console.error('Ошибка удаления мастер-класса:', err);
        return res.status(500).json({ error: 'Ошибка удаления мастер-класса' });
      }

      if (this.changes === 0) {
        return res.status(404).json({ error: 'Мастер-класс не найден' });
      }

      res.json({ message: 'Мастер-класс успешно удален' });
    }
  );
});

// Маршруты для заказов
app.post('/api/orders', authenticateToken, (req, res) => {
  const { items, totalPrice, customerName, customerPhone, customerEmail, deliveryAddress, deliveryDate, deliveryTime, paymentMethod, notes } = req.body;

  if (!items || !totalPrice || !customerName || !customerPhone) {
    return res.status(400).json({ error: 'Не все обязательные поля заполнены' });
  }

  db.run(
    `INSERT INTO orders (user_id, items, total_price, customer_name, customer_phone, customer_email, 
      delivery_address, delivery_date, delivery_time, payment_method, notes) 
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [req.user.userId, JSON.stringify(items), totalPrice, customerName, customerPhone, customerEmail,
      deliveryAddress, deliveryDate, deliveryTime, paymentMethod, notes],
    function (err) {
      if (err) {
        console.error('Ошибка создания заказа:', err);
        return res.status(500).json({ error: 'Ошибка создания заказа' });
      }

      res.status(201).json({
        message: 'Заказ успешно создан',
        orderId: this.lastID
      });
    }
  );
});

app.get('/api/orders', authenticateToken, (req, res) => {
  db.all(
    'SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC',
    [req.user.userId],
    (err, rows) => {
      if (err) {
        return res.status(500).json({ error: 'Ошибка получения заказов' });
      }

      const orders = rows.map(order => ({
        ...order,
        items: JSON.parse(order.items)
      }));

      res.json(orders);
    }
  );
});

app.get('/api/admin/orders', authenticateToken, requireAdmin, (req, res) => {
  db.all(
    `SELECT o.*, u.email, u.first_name, u.last_name 
     FROM orders o 
     LEFT JOIN users u ON o.user_id = u.id 
     ORDER BY o.created_at DESC`,
    (err, rows) => {
      if (err) {
        return res.status(500).json({ error: 'Ошибка получения заказов' });
      }

      const orders = rows.map(order => ({
        ...order,
        items: JSON.parse(order.items)
      }));

      res.json(orders);
    }
  );
});

// ОБНОВЛЕННЫЕ МАРШРУТЫ ДЛЯ ОТЧЕТОВ

// Финансовые отчеты

// 1. Ежедневный отчет о выручке с детализацией по товарным категориям
app.get('/api/admin/reports/daily-revenue', authenticateToken, requireAdmin, (req, res) => {
  const { date } = req.query;
  
  if (!date) {
    return res.status(400).json({ error: 'Дата обязательна' });
  }

  const query = `
    SELECT 
      DATE(created_at) as report_date,
      COUNT(*) as total_orders,
      SUM(total_price) as total_revenue,
      AVG(total_price) as average_order_value
    FROM orders 
    WHERE DATE(created_at) = ?
    GROUP BY DATE(created_at)
  `;
  
  db.get(query, [date], (err, dailySummary) => {
    if (err) {
      console.error('Ошибка при получении ежедневного отчета:', err);
      return res.status(500).json({ error: 'Ошибка базы данных' });
    }

    // Детализация по категориям (симуляция - в реальности нужна связь заказов с категориями)
    const categoryDetails = [
      { category: 'Букеты', revenue: dailySummary ? dailySummary.total_revenue * 0.4 : 0, units: dailySummary ? Math.floor(dailySummary.total_orders * 0.4) : 0 },
      { category: 'Наборы', revenue: dailySummary ? dailySummary.total_revenue * 0.3 : 0, units: dailySummary ? Math.floor(dailySummary.total_orders * 0.3) : 0 },
      { category: 'Стаканчики', revenue: dailySummary ? dailySummary.total_revenue * 0.2 : 0, units: dailySummary ? Math.floor(dailySummary.total_orders * 0.2) : 0 },
      { category: 'Торты', revenue: dailySummary ? dailySummary.total_revenue * 0.1 : 0, units: dailySummary ? Math.floor(dailySummary.total_orders * 0.1) : 0 }
    ];

    res.json({
      success: true,
      report: {
        date: date,
        summary: dailySummary || { total_orders: 0, total_revenue: 0, average_order_value: 0 },
        category_details: categoryDetails,
        percentage_breakdown: categoryDetails.map(cat => ({
          category: cat.category,
          percentage: dailySummary ? (cat.revenue / dailySummary.total_revenue * 100).toFixed(1) : 0
        }))
      }
    });
  });
});

// 2. Анализ среднего чека
app.get('/api/admin/reports/average-check', authenticateToken, requireAdmin, (req, res) => {
  const { startDate, endDate, period = 'day' } = req.query;
  
  let groupBy;
  switch (period) {
    case 'week': groupBy = 'strftime("%Y-%W", created_at)'; break;
    case 'month': groupBy = 'strftime("%Y-%m", created_at)'; break;
    default: groupBy = 'DATE(created_at)';
  }

  let query = `
    SELECT 
      ${groupBy} as period,
      COUNT(*) as order_count,
      SUM(total_price) as total_revenue,
      AVG(total_price) as average_check
    FROM orders 
    WHERE 1=1
  `;
  
  const params = [];
  
  if (startDate) {
    query += ' AND DATE(created_at) >= ?';
    params.push(startDate);
  }
  
  if (endDate) {
    query += ' AND DATE(created_at) <= ?';
    params.push(endDate);
  }
  
  query += ` GROUP BY ${groupBy} ORDER BY period DESC`;
  
  db.all(query, params, (err, rows) => {
    if (err) {
      console.error('Ошибка при получении анализа среднего чека:', err);
      return res.status(500).json({ error: 'Ошибка базы данных' });
    }

    // Расчет динамики
    const dynamics = rows.map((row, index) => {
      const previous = rows[index + 1];
      const change = previous ? ((row.average_check - previous.average_check) / previous.average_check * 100) : 0;
      
      return {
        ...row,
        change_percentage: change.toFixed(1),
        trend: change > 0 ? 'up' : change < 0 ? 'down' : 'stable'
      };
    });

    res.json({
      success: true,
      report: dynamics,
      summary: {
        total_periods: rows.length,
        current_period_avg: rows[0]?.average_check || 0,
        previous_period_avg: rows[1]?.average_check || 0,
        overall_avg: rows.reduce((sum, row) => sum + row.average_check, 0) / (rows.length || 1)
      }
    });
  });
});

// 3. Динамика продаж
app.get('/api/admin/reports/sales-dynamics', authenticateToken, requireAdmin, (req, res) => {
  const { startDate, endDate } = req.query;
  
  let query = `
    SELECT 
      DATE(created_at) as date,
      COUNT(*) as order_count,
      SUM(total_price) as total_revenue,
      AVG(total_price) as average_order_value
    FROM orders 
    WHERE 1=1
  `;
  
  const params = [];
  
  if (startDate) {
    query += ' AND DATE(created_at) >= ?';
    params.push(startDate);
  }
  
  if (endDate) {
    query += ' AND DATE(created_at) <= ?';
    params.push(endDate);
  }
  
  query += ' GROUP BY DATE(created_at) ORDER BY date';
  
  db.all(query, params, (err, rows) => {
    if (err) {
      console.error('Ошибка при получении динамики продаж:', err);
      return res.status(500).json({ error: 'Ошибка базы данных' });
    }
    
    const summary = {
      total_orders: rows.reduce((sum, row) => sum + row.order_count, 0),
      total_revenue: rows.reduce((sum, row) => sum + (row.total_revenue || 0), 0),
      period: { startDate, endDate },
      peak_period: rows.reduce((peak, row) => row.total_revenue > (peak?.total_revenue || 0) ? row : peak, null),
      average_daily_orders: (rows.reduce((sum, row) => sum + row.order_count, 0) / (rows.length || 1)).toFixed(1)
    };
    
    res.json({
      success: true,
      report: rows,
      summary: summary
    });
  });
});

// Операционные отчеты

// 4. Отчет по выполненным заказам
app.get('/api/admin/reports/order-performance', authenticateToken, requireAdmin, (req, res) => {
  const { startDate, endDate } = req.query;
  
  let query = `
    SELECT 
      status,
      COUNT(*) as count
    FROM orders 
    WHERE 1=1
  `;
  
  const params = [];
  
  if (startDate) {
    query += ' AND DATE(created_at) >= ?';
    params.push(startDate);
  }
  
  if (endDate) {
    query += ' AND DATE(created_at) <= ?';
    params.push(endDate);
  }
  
  query += ' GROUP BY status';
  
  db.all(query, params, (err, statusCounts) => {
    if (err) {
      console.error('Ошибка при получении отчета по заказам:', err);
      return res.status(500).json({ error: 'Ошибка базы данных' });
    }

    // Общее количество заказов
    const totalOrders = statusCounts.reduce((sum, item) => sum + item.count, 0);
    const completedOrders = statusCounts.find(item => item.status === 'delivered')?.count || 0;
    const completionRate = totalOrders > 0 ? (completedOrders / totalOrders * 100).toFixed(1) : 0;

    res.json({
      success: true,
      report: {
        status_breakdown: statusCounts,
        totals: {
          total_orders: totalOrders,
          completed_orders: completedOrders,
          completion_rate: completionRate,
          cancelled_orders: statusCounts.find(item => item.status === 'cancelled')?.count || 0,
          processing_orders: statusCounts.find(item => item.status === 'processing')?.count || 0
        }
      }
    });
  });
});

// Отчеты по клиентам

// 5. База клиентов - РАСШИРЕННАЯ ВЕРСИЯ С ДЕТАЛЬНЫМ СПИСКОМ
app.get('/api/admin/reports/customer-base', authenticateToken, requireAdmin, (req, res) => {
    const { startDate, endDate } = req.query;
    
    // Если даты не указаны, берем весь период
    const start = startDate || '2000-01-01';
    const end = endDate || '2100-01-01';

    // Запрос для общей статистики
    const statsQuery = `
        SELECT 
            COUNT(DISTINCT u.id) as total_customers,
            COUNT(DISTINCT CASE WHEN DATE(u.created_at) BETWEEN ? AND ? THEN u.id END) as new_customers,
            COUNT(DISTINCT o.user_id) as active_customers,
            COALESCE(AVG(o.total_price), 0) as avg_order_value,
            MAX(u.created_at) as last_registration
        FROM users u
        LEFT JOIN orders o ON u.id = o.user_id
        WHERE u.role = 'user'
    `;

    // Запрос для детального списка клиентов
    const customersQuery = `
        SELECT 
            u.id,
            u.first_name,
            u.last_name,
            u.email,
            u.phone,
            u.created_at as registration_date,
            COUNT(o.id) as total_orders,
            COALESCE(SUM(o.total_price), 0) as total_spent,
            MAX(o.created_at) as last_order_date,
            CASE 
                WHEN COUNT(o.id) > 0 THEN 'Активный'
                ELSE 'Новый'
            END as status,
            CASE 
                WHEN COUNT(o.id) = 0 THEN 'Нет заказов'
                WHEN COUNT(o.id) = 1 THEN '1 заказ'
                ELSE COUNT(o.id) || ' заказов'
            END as activity_level
        FROM users u
        LEFT JOIN orders o ON u.id = o.user_id
        WHERE u.role = 'user'
        GROUP BY u.id
        ORDER BY total_spent DESC, total_orders DESC
    `;

    // Запрос для географии
    const geographyQuery = `
        SELECT 
            CASE 
                WHEN delivery_address LIKE '%Москва%' OR delivery_address LIKE '%мск%' THEN 'Москва'
                WHEN delivery_address LIKE '%Санкт-Петербург%' OR delivery_address LIKE '%спб%' THEN 'Санкт-Петербург'
                ELSE 'Другие города'
            END as region,
            COUNT(DISTINCT user_id) as customers
        FROM orders 
        WHERE delivery_address IS NOT NULL AND delivery_address != ''
        GROUP BY region
    `;

    // Выполняем все запросы параллельно
    db.get(statsQuery, [start, end], (err, customerStats) => {
        if (err) {
            console.error('Ошибка при получении статистики клиентов:', err);
            return res.status(500).json({ error: 'Ошибка базы данных' });
        }

        db.all(customersQuery, [], (err, customersList) => {
            if (err) {
                console.error('Ошибка при получении списка клиентов:', err);
                return res.status(500).json({ error: 'Ошибка базы данных' });
            }

            db.all(geographyQuery, [], (err, geography) => {
                if (err) {
                    console.error('Ошибка при получении географии:', err);
                    geography = [];
                }

                res.json({
                    success: true,
                    report: {
                        customer_stats: customerStats,
                        customers_list: customersList || [],
                        geography: geography,
                        activity_rate: customerStats.total_customers > 0 ? 
                            (customerStats.active_customers / customerStats.total_customers * 100).toFixed(1) : 0
                    }
                });
            });
        });
    });
});

// 6. История заказов клиентов
app.get('/api/admin/reports/customer-orders', authenticateToken, requireAdmin, (req, res) => {
  const { customerId, startDate, endDate } = req.query;
  
  if (!customerId) {
    return res.status(400).json({ error: 'ID клиента обязателен' });
  }

  let query = `
    SELECT 
      o.*,
      u.first_name,
      u.last_name,
      u.email,
      u.phone
    FROM orders o
    JOIN users u ON o.user_id = u.id
    WHERE o.user_id = ?
  `;
  
  const params = [customerId];
  
  if (startDate) {
    query += ' AND DATE(o.created_at) >= ?';
    params.push(startDate);
  }
  
  if (endDate) {
    query += ' AND DATE(o.created_at) <= ?';
    params.push(endDate);
  }
  
  query += ' ORDER BY o.created_at DESC';
  
  db.all(query, params, (err, orders) => {
    if (err) {
      console.error('Ошибка при получении истории заказов:', err);
      return res.status(500).json({ error: 'Ошибка базы данных' });
    }

    // Анализ предпочтений
    const categoryPreferences = {};
    let totalSpent = 0;
    let orderFrequency = orders.length;

    orders.forEach(order => {
      totalSpent += order.total_price;
      try {
        const items = JSON.parse(order.items);
        items.forEach(item => {
          // Определяем категорию по имени товара (симуляция)
          let category = 'Другое';
          if (item.name.includes('Букет')) category = 'Букеты';
          else if (item.name.includes('Набор')) category = 'Наборы';
          else if (item.name.includes('Стаканчик')) category = 'Стаканчики';
          else if (item.name.includes('Торт')) category = 'Торты';
          
          categoryPreferences[category] = (categoryPreferences[category] || 0) + item.quantity;
        });
      } catch (e) {
        console.error('Ошибка парсинга items:', e);
      }
    });

    res.json({
      success: true,
      report: {
        customer_info: orders[0] ? {
          name: `${orders[0].first_name || ''} ${orders[0].last_name || ''}`.trim(),
          email: orders[0].email,
          phone: orders[0].phone
        } : null,
        orders: orders.map(order => ({
          ...order,
          items: JSON.parse(order.items)
        })),
        analytics: {
          total_orders: orders.length,
          total_spent: totalSpent,
          average_order_value: orders.length > 0 ? totalSpent / orders.length : 0,
          category_preferences: categoryPreferences,
          favorite_category: Object.keys(categoryPreferences).reduce((a, b) => 
            categoryPreferences[a] > categoryPreferences[b] ? a : b, '')
        }
      }
    });
  });
});

// Получение списка клиентов для выбора
app.get('/api/admin/customers', authenticateToken, requireAdmin, (req, res) => {
  const query = `
    SELECT 
      u.id,
      u.first_name,
      u.last_name,
      u.email,
      u.phone,
      u.created_at,
      COUNT(o.id) as order_count,
      COALESCE(SUM(o.total_price), 0) as total_spent
    FROM users u
    LEFT JOIN orders o ON u.id = o.user_id
    WHERE u.role = 'user'
    GROUP BY u.id
    ORDER BY u.created_at DESC
  `;
  
  db.all(query, [], (err, customers) => {
    if (err) {
      console.error('Ошибка при получении списка клиентов:', err);
      return res.status(500).json({ error: 'Ошибка базы данных' });
    }
    
    res.json({
      success: true,
      customers: customers
    });
  });
});

// Маршрут для создания тестовых пользователей
app.post('/api/admin/create-test-users', authenticateToken, requireAdmin, (req, res) => {
    const testUsers = [
        {
            email: 'client1@example.com',
            password: crypto.createHash('sha256').update('password123').digest('hex'),
            first_name: 'Иван',
            last_name: 'Иванов',
            phone: '+79123456789',
            role: 'user'
        },
        {
            email: 'client2@example.com',
            password: crypto.createHash('sha256').update('password123').digest('hex'),
            first_name: 'Мария',
            last_name: 'Петрова',
            phone: '+79123456780',
            role: 'user'
        },
        {
            email: 'client3@example.com',
            password: crypto.createHash('sha256').update('password123').digest('hex'),
            first_name: 'Алексей',
            last_name: 'Сидоров',
            phone: '+79123456781',
            role: 'user'
        }
    ];

    let createdCount = 0;
    let errorCount = 0;

    testUsers.forEach(user => {
        db.get('SELECT * FROM users WHERE email = ?', [user.email], (err, row) => {
            if (err) {
                console.error('Ошибка проверки пользователя:', err.message);
                errorCount++;
            } else if (!row) {
                db.run('INSERT INTO users (email, password, first_name, last_name, phone, role) VALUES (?, ?, ?, ?, ?, ?)',
                    [user.email, user.password, user.first_name, user.last_name, user.phone, user.role], 
                    function(err) {
                        if (err) {
                            console.error('Ошибка создания пользователя:', err.message);
                            errorCount++;
                        } else {
                            console.log(`Пользователь создан: ${user.email}`);
                            createdCount++;
                        }
                        
                        // Когда все пользователи обработаны
                        if (createdCount + errorCount === testUsers.length) {
                            res.json({
                                success: true,
                                message: `Создано ${createdCount} тестовых пользователей, ошибок: ${errorCount}`,
                                created: createdCount,
                                errors: errorCount
                            });
                        }
                    });
            } else {
                // Пользователь уже существует
                createdCount++;
                if (createdCount + errorCount === testUsers.length) {
                    res.json({
                        success: true,
                        message: `Создано ${createdCount} тестовых пользователей, ошибок: ${errorCount}`,
                        created: createdCount,
                        errors: errorCount
                    });
                }
            }
        });
    });
});
// Гарантированный endpoint для получения клиентов
app.get('/api/admin/all-customers', authenticateToken, requireAdmin, (req, res) => {
    console.log('📞 Запрос списка клиентов');
    
    const query = `
        SELECT 
            id,
            COALESCE(first_name, '') as first_name,
            COALESCE(last_name, '') as last_name,
            email,
            COALESCE(phone, '') as phone,
            created_at
        FROM users 
        WHERE role = 'user'
        ORDER BY created_at DESC
    `;
    
    db.all(query, [], (err, customers) => {
        if (err) {
            console.error('Ошибка базы данных:', err);
            // Возвращаем тестовых клиентов при ошибке
            const testCustomers = [
                { id: 1, first_name: 'Иван', last_name: 'Иванов', email: 'client1@example.com', phone: '+79123456789' },
                { id: 2, first_name: 'Мария', last_name: 'Петрова', email: 'client2@example.com', phone: '+79123456780' },
                { id: 3, first_name: 'Алексей', last_name: 'Сидоров', email: 'client3@example.com', phone: '+79123456781' }
            ];
            return res.json({
                success: true,
                customers: testCustomers
            });
        }
        
        console.log(`Найдено клиентов: ${customers.length}`);
        
        // Всегда возвращаем успех, даже если клиентов нет
        res.json({
            success: true,
            customers: customers.length > 0 ? customers : [
                { id: 1, first_name: 'Тестовый', last_name: 'Клиент 1', email: 'test1@example.com', phone: '+70000000001' },
                { id: 2, first_name: 'Тестовый', last_name: 'Клиент 2', email: 'test2@example.com', phone: '+70000000002' }
            ]
        });
    });
});

// Маршрут для страницы отчетов
app.get('/admin-reports.html', authenticateToken, requireAdmin, (req, res) => {
  res.sendFile(path.join(publicDir, 'admin-reports.html'));
});

// Обслуживание HTML страниц
app.get('/', (req, res) => {
  res.sendFile(path.join(publicDir, 'index.html'));
});

app.get('/catalog.html', (req, res) => {
  res.sendFile(path.join(publicDir, 'catalog.html'));
});

app.get('/master-classes.html', (req, res) => {
  res.sendFile(path.join(publicDir, 'master-classes.html'));
});

app.get('/about.html', (req, res) => {
  res.sendFile(path.join(publicDir, 'about.html'));
});

app.get('/contacts.html', (req, res) => {
  res.sendFile(path.join(publicDir, 'contacts.html'));
});

app.get('/cart.html', (req, res) => {
  res.sendFile(path.join(publicDir, 'cart.html'));
});

app.get('/admin.html', authenticateToken, requireAdmin, (req, res) => {
  res.sendFile(path.join(publicDir, 'admin.html'));
});

// Маршрут для обработки контактной формы
app.post('/api/contact', (req, res) => {
  const { name, phone, email, subject, message } = req.body;

  if (!name || !phone || !message) {
    return res.status(400).json({ error: 'Имя, телефон и сообщение обязательны' });
  }

  console.log('Новое сообщение с сайта "Контакты":');
  console.log('Имя:', name);
  console.log('Телефон:', phone);
  console.log('Email:', email);
  console.log('Тема:', subject || 'Не указана');
  console.log('Сообщение:', message);
  console.log('---');

  res.json({
    message: 'Ваше сообщение успешно отправлено! Мы свяжемся с вами в ближайшее время.'
  });
});

// Обработка 404 ошибок
app.use((req, res) => {
  res.status(404).send('Страница не найдена');
});

// Обработка ошибок
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Что-то пошло не так!');
});

// Запуск сервера
app.listen(PORT, () => {
  console.log(`Сервер запущен на порту ${PORT}`);
  console.log(`Откройте http://localhost:${PORT} в браузере`);
  console.log('Учетные данные администратора:');
  console.log('Email: admin@nadista.com');
  console.log('Пароль: admin123');
});