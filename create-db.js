const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// Подключаемся к базе данных
const dbPath = path.join(__dirname, 'db', 'database.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Ошибка подключения к базе данных:', err.message);
  } else {
    console.log('Успешное подключение к базе данных');

    // Включаем обработку иностранных ключей
    db.run('PRAGMA foreign_keys = ON');

    // Создаем таблицу продуктов
    db.serialize(() => {

      // Создаем таблицу продуктов
      db.run(`CREATE TABLE products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        price REAL NOT NULL,
        category TEXT,
        overlay_image TEXT,
        in_stock BOOLEAN DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )`);

      // Создаем таблицы для каждой категории
      db.run(`CREATE TABLE byket (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        price REAL NOT NULL,
        category TEXT DEFAULT 'bouquets',
        overlay_image TEXT,
        in_stock BOOLEAN DEFAULT 1
      )`);

      db.run(`CREATE TABLE nabor (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        price REAL NOT NULL,
        category TEXT DEFAULT 'sets',
        overlay_image TEXT,
        in_stock BOOLEAN DEFAULT 1
      )`);

      db.run(`CREATE TABLE stakanciki (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        price REAL NOT NULL,
        category TEXT DEFAULT 'cups',
        overlay_image TEXT,
        in_stock BOOLEAN DEFAULT 1
      )`);

      db.run(`CREATE TABLE tort (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        price REAL NOT NULL,
        category TEXT DEFAULT 'cakes',
        overlay_image TEXT,
        in_stock BOOLEAN DEFAULT 1
      )`);

      // СОЗДАЕМ ТАБЛИЦУ МАСТЕР-КЛАССОВ
      db.run(`CREATE TABLE masterclasses (
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
      )`);

      // Добавляем начальные данные в таблицу products
      const products = [
        {
          name: 'Букеты из клубники в шоколаде',
          description: 'Роскошные букеты из отборной клубники в премиальном шоколаде и цветов',
          price: 1200,
          category: 'byket',
          overlay_image: '/images/products/byket4.jpg'
        },
        {
          name: 'Оригинальные наборы',
          description: 'Широкий выбор наборов со свежими ягодами в шоколаде',
          price: 850,
          category: 'nabor',
          overlay_image: '/images/products/nabor.jpg'
        },
        {
          name: 'Прекрасные стаканчики',
          description: 'Эксклюзивный подарок, из клубники в шоколаде в небольшом стаканчике',
          price: 1500,
          category: 'stakanciki',
          overlay_image: '/images/products/stakan.jpg'
        },
        {
          name: 'Торты',
          description: 'Сладкие подарки под любой повод. Персонализированный дизайн',
          price: 600,
          category: 'tort',
          overlay_image: '/images/products/tort.jpg'
        }
      ];

      // Добавляем данные в таблицу byket
      const byket = [
        {
          name: "Букет 'Романтика'",
          description: "Нежный букет из клубники в белом шоколаде с розами",
          price: 2500,
          overlay_image: "/images/products/byket.png"
        },
        {
          name: "Букет 'Премиум'",
          description: "Роскошный букет из отборной клубники в темном шоколаде",
          price: 3200,
          overlay_image: "/images/products/byket2.png"
        },
        {
          name: "Букет 'Нежность'",
          description: "Изящный букет из клубники в молочном шоколаде с пионами",
          price: 2800,
          overlay_image: "/images/products/byket3.png"
        },
        {
          name: "Букет 'Эксклюзив'",
          description: "Эксклюзивный букет с клубникой в шоколаде и орхидеями",
          price: 3800,
          overlay_image: "/images/products/byket4.jpg"
        },
        {
          name: "Букет 'Свадебный'",
          description: "Элегантный свадебный букет из клубники в белом шоколаде",
          price: 3500,
          overlay_image: "/images/products/byket5.png"
        },
        {
          name: "Букет 'Фестиваль'",
          description: "Яркий праздничный букет с разнообразными украшениями",
          price: 2900,
          overlay_image: "/images/products/byket6.png"
        }
      ];
      const nabor = [
        {
          name: "Набор 'Сладкоежка'",
          description: "Вкусный набор для настоящих сладкоежек",
          price: 1800,
          overlay_image: "/images/products/nabor.jpg"
        },
        {
          name: "Набор 'Праздничный'",
          description: "Набор для праздничного стола",
          price: 2200,
          overlay_image: "/images/products/nabor2.png"
        },
        {
          name: "Набор 'Фруктовый'",
          description: "Свежие фрукты в шоколадной глазури",
          price: 1900,
          overlay_image: "/images/products/nabor3.png"
        },
        {
          name: "Набор 'Карамельный'",
          description: "Ассорти карамели и ирисок",
          price: 1700,
          overlay_image: "/images/products/nabor4.png"
        },
        {
          name: "Набор 'Подарочный'",
          description: "Эксклюзивный набор в красивой упаковке",
          price: 2500,
          overlay_image: "/images/products/nabor5.png"
        },
        {
          name: "Набор 'Детский'",
          description: "Яркий набор с веселыми сладостями",
          price: 1500,
          overlay_image: "/images/products/nabor6.png"
        }
      ];

      const stakanciki = [
        {
          name: "Стаканчик 'Ягодный'",
          description: "Сладкий стаканчик с ягодами",
          price: 500,
          overlay_image: "/images/products/stakan.jpg"
        },
        {
          name: "Стаканчик 'Шоколадный'",
          description: "Нежный шоколадный мусс",
          price: 550,
          overlay_image: "/images/products/stakan2.png"
        },
        {
          name: "Стаканчик 'Клубничный'",
          description: "Воздушный клубничный крем",
          price: 500,
          overlay_image: "/images/products/stakan3.png"
        },
        {
          name: "Стаканчик 'Кофейный'",
          description: "Ароматный кофейный десерт",
          price: 600,
          overlay_image: "/images/products/stakan4.png"
        },
        {
          name: "Стаканчик 'Карамельный'",
          description: "Слоеный десерт с карамелью",
          price: 550,
          overlay_image: "/images/products/stakan5.png"
        },
        {
          name: "Стаканчик 'Малиновый'",
          description: "Нежный мусс со свежей малиной",
          price: 600,
          overlay_image: "/images/products/stakan6.png"
        }
      ];

      const tort = [
        {
          name: "Торт 'Шоколадный'",
          description: "Нежный шоколадный торт",
          price: 2000,
          overlay_image: "/images/products/tort.jpg"
        },
        {
          name: "Торт 'Клубничный'",
          description: "Классический американский десерт",
          price: 2200,
          overlay_image: "/images/products/tort2.png"
        },
        {
          name: "Торт 'Малиновый'",
          description: "Традиционный русский торт с медом",
          price: 2100,
          overlay_image: "/images/products/tort3.png"
        },
        {
          name: "Торт 'Фруктовый'",
          description: "Легкий бисквит со свежими фруктами",
          price: 2300,
          overlay_image: "/images/products/tort4.png"
        },
        {
          name: "Торт 'Кофейный'",
          description: "Пропитанный кофейным сиропом",
          price: 2100,
          overlay_image: "/images/products/tort5.png"
        },
        {
          name: "Торт 'Ягодный'",
          description: "С малиной и черникой",
          price: 2400,
          overlay_image: "/images/products/tort6.png"
        }
      ];

      // ДОБАВЛЯЕМ ДАННЫЕ В ТАБЛИЦУ МАСТЕР-КЛАССОВ
      const masterclasses = [
        {
          name: "Букеты из клубники в шоколаде",
          description: "Научитесь создавать роскошные букеты из отборной клубники в премиальном шоколаде. Освоите технику темперирования шоколада и оформления композиций.",
          price: 3500,
          duration: "3 часа",
          max_participants: 8,
          rating: 4.9,
          reviews_count: 24,
          image_url: "/images/products/masterclass.jpg",
          badge: "Популярный",
          category: "chocolate"
        },
        {
          name: "Японские моти с разными начинками",
          description: "Погрузитесь в мир японских сладостей. Научитесь готовить нежнейшие моти с традиционными и современными начинками, освоите технику лепки.",
          price: 2800,
          duration: "2.5 часа",
          max_participants: 6,
          rating: 4.8,
          reviews_count: 15,
          image_url: "/images/products/masterclass2.jpg",
          badge: "Новинка",
          category: "mochi"
        },
        {
          name: "Экслюзивные наборы из клубники в шоколаде",
          description: "Освойте искусство украшения тортов и пирожных. Научитесь работать с кремом, шоколадом, мастикой и создавать съедобные цветы и декоративные элементы.",
          price: 4200,
          duration: "4 часа",
          max_participants: 5,
          rating: 5.0,
          reviews_count: 18,
          image_url: "/images/products/masterclass1.jpg",
          badge: "Эксклюзив",
          category: "decoration"
        }
      ];

      // Подготавливаем запросы для вставки данных
      const insertProduct = db.prepare(`INSERT INTO products (name, description, price, category, overlay_image) VALUES (?, ?, ?, ?, ?)`);
      const insertByket = db.prepare(`INSERT INTO byket (name, description, price, overlay_image) VALUES (?, ?, ?, ?)`);
      const insertNabor = db.prepare(`INSERT INTO nabor (name, description, price, overlay_image) VALUES (?, ?, ?, ?)`);
      const insertStakanciki = db.prepare(`INSERT INTO stakanciki (name, description, price, overlay_image) VALUES (?, ?, ?, ?)`);
      const insertTort = db.prepare(`INSERT INTO tort (name, description, price, overlay_image) VALUES (?, ?, ?, ?)`);
      const insertMasterclass = db.prepare(`INSERT INTO masterclasses (name, description, price, duration, max_participants, rating, reviews_count, image_url, badge, category) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);

      // Вставляем данные в таблицу products
      products.forEach(product => {
        insertProduct.run(
          product.name,
          product.description,
          product.price,
          product.category,
          product.overlay_image
        );
      });

      // Вставляем данные в таблицу byket
      byket.forEach(item => {
        insertByket.run(
          item.name,
          item.description,
          item.price,
          item.overlay_image
        );
      });
      nabor.forEach(item => {
        insertNabor.run(
          item.name,
          item.description,
          item.price,
          item.overlay_image
        );
      });
      stakanciki.forEach(item => {
        insertStakanciki.run(
          item.name,
          item.description,
          item.price,
          item.overlay_image
        );
      });
      tort.forEach(item => {
        insertTort.run(
          item.name,
          item.description,
          item.price,
          item.overlay_image
        );
      });

      // ВСТАВЛЯЕМ ДАННЫЕ В ТАБЛИЦУ МАСТЕР-КЛАССОВ
      masterclasses.forEach(masterclass => {
        insertMasterclass.run(
          masterclass.name,
          masterclass.description,
          masterclass.price,
          masterclass.duration,
          masterclass.max_participants,
          masterclass.rating,
          masterclass.reviews_count,
          masterclass.image_url,
          masterclass.badge,
          masterclass.category
        );
      });

      // Завершаем подготовленные запросы
      insertProduct.finalize();
      insertByket.finalize();
      insertNabor.finalize();
      insertStakanciki.finalize();
      insertTort.finalize();
      insertMasterclass.finalize();

      console.log('Все таблицы созданы и заполнены тестовыми данными!');

      // Закрываем соединение с базой данных
      db.close((err) => {
        if (err) {
          console.error(err.message);
        } else {
          console.log('Соединение с базой данных закрыто');
        }
      });
    });
  }
});