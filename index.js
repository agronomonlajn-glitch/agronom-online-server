const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = process.env.PORT || 3000;

// --- Подключаем SQLite (файл users.db лежит рядом с index.js) ---
const db = new sqlite3.Database('./users.db');

// Создаём таблицу пользователей (если её ещё нет)
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identifier TEXT UNIQUE NOT NULL,
    name TEXT,
    password_hash TEXT NOT NULL
  );
`);

app.use(cors());               // Разрешаем запросы с других доменов (Flutter-приложение)
app.use(express.json());       // Позволяет читать JSON из тела запроса

// Простая проверка email/телефон — примерно как во Flutter
function isValidEmail(str) {
  return /^[\w.\-]+@[\w.\-]+\.\w+$/.test(str);
}

function isValidPhone(str) {
  const cleaned = str.replace(/[\s\-+()]/g, '');
  return /^\d{9,15}$/.test(cleaned);
}

// ------------- РЕГИСТРАЦИЯ -------------
app.post('/register', async (req, res) => {
  const { identifier, password, name } = req.body || {};

  if (!identifier || !password) {
    return res.status(400).json({ message: 'identifier и password обязательны' });
  }

  if (!(isValidEmail(identifier) || isValidPhone(identifier))) {
    return res.status(400).json({ message: 'Некорректный email или телефон' });
  }

  if (password.length < 6) {
    return res.status(400).json({ message: 'Пароль слишком короткий' });
  }

  try {
    const hash = await bcrypt.hash(password, 10);

    db.run(
      'INSERT INTO users (identifier, name, password_hash) VALUES (?, ?, ?)',
      [identifier, name || null, hash],
      function (err) {
        if (err) {
          if (err.message && err.message.includes('UNIQUE')) {
            return res.status(409).json({ message: 'Такой пользователь уже существует' });
          }
          console.error(err);
          return res.status(500).json({ message: 'Ошибка сервера' });
        }

        return res.status(200).json({
          ok: true,
          message: 'Регистрация успешна',
          userId: this.lastID,
        });
      }
    );
  } catch (e) {
    console.error(e);
    return res.status(500).json({ message: 'Ошибка сервера' });
  }
});

// ------------- ВХОД -------------
app.post('/login', (req, res) => {
  const { identifier, password } = req.body || {};

  if (!identifier || !password) {
    return res.status(400).json({ message: 'identifier и password обязательны' });
  }

  db.get(
    'SELECT * FROM users WHERE identifier = ?',
    [identifier],
    async (err, row) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ message: 'Ошибка сервера' });
      }

      if (!row) {
        return res.status(401).json({ message: 'Неверный логин или пароль' });
      }

      const match = await bcrypt.compare(password, row.password_hash);
      if (!match) {
        return res.status(401).json({ message: 'Неверный логин или пароль' });
      }

      return res.status(200).json({
        ok: true,
        message: 'Вход выполнен успешно',
        userId: row.id,
      });
    }
  );
});

// ------------- СТАРТ СЕРВЕРА -------------
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
