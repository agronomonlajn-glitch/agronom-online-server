// index.js
const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

const app = express();

// ---------- МИДЛВАРЫ ----------
app.use(cors());
app.use(express.json());

// ---------- БАЗА ДАННЫХ ----------
const db = new sqlite3.Database('./users.db');

// Таблица пользователей.
// provider = 'local' | 'google' | 'apple' ...
// для local/password: providerId = identifier
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      identifier TEXT NOT NULL,   -- email или телефон
      passwordHash TEXT,          -- для local
      name TEXT,
      provider TEXT NOT NULL DEFAULT 'local',
      providerId TEXT,
      UNIQUE(provider, providerId)
    )
  `);
});

// ---------- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ----------

function sendError(res, message, code = 400) {
  res.status(code).json({ success: false, message });
}

// ---------- ПРОСТО ПРОВЕРКА, ЧТО СЕРВЕР ЖИВОЙ ----------
app.get('/', (req, res) => {
  res.json({ ok: true, message: 'Agronom Online auth server' });
});

// ---------- РЕГИСТРАЦИЯ (email / телефон + пароль) ----------
app.post('/register', async (req, res) => {
  const { identifier, password, name } = req.body || {};

  if (!identifier || !password || !name) {
    return sendError(res, 'Не хватает данных (identifier, password, name)', 400);
  }

  try {
    const saltRounds = 10;
    const hash = await bcrypt.hash(password, saltRounds);

    const stmt = db.prepare(`
      INSERT INTO users (identifier, passwordHash, name, provider, providerId)
      VALUES (?, ?, ?, 'local', ?)
    `);

    stmt.run(identifier, hash, name, identifier, function (err) {
      if (err) {
        if (err.code === 'SQLITE_CONSTRAINT') {
          return sendError(res, 'Такой пользователь уже существует', 409);
        }
        console.error('Ошибка при INSERT /register:', err);
        return sendError(res, 'Внутренняя ошибка сервера', 500);
      }

      res.json({
        success: true,
        message: 'Регистрация успешна',
        userId: this.lastID,
      });
    });
  } catch (e) {
    console.error('Ошибка /register:', e);
    return sendError(res, 'Внутренняя ошибка сервера', 500);
  }
});

// ---------- ВХОД (email / телефон + пароль) ----------
app.post('/login', (req, res) => {
  const { identifier, password } = req.body || {};

  if (!identifier || !password) {
    return sendError(res, 'Не хватает данных (identifier, password)', 400);
  }

  db.get(
    `
    SELECT * FROM users
    WHERE provider = 'local' AND identifier = ?
  `,
    [identifier],
    async (err, row) => {
      if (err) {
        console.error('Ошибка SELECT /login:', err);
        return sendError(res, 'Внутренняя ошибка сервера', 500);
      }

      if (!row || !row.passwordHash) {
        return sendError(res, 'Неверный логин или пароль', 401);
      }

      const isOk = await bcrypt.compare(password, row.passwordHash);
      if (!isOk) {
        return sendError(res, 'Неверный логин или пароль', 401);
      }

      res.json({
        success: true,
        message: 'Вход выполнен успешно',
        userId: row.id,
      });
    }
  );
});

// ---------- ВХОД/РЕГИСТРАЦИЯ ЧЕРЕЗ GOOGLE ----------
app.post('/auth/google', (req, res) => {
  const { googleId, email, name } = req.body || {};

  if (!googleId || !email) {
    return sendError(res, 'Не хватает данных googleId / email', 400);
  }

  // Ищем пользователя по связке provider + providerId
  db.get(
    `
    SELECT * FROM users
    WHERE provider = 'google' AND providerId = ?
  `,
    [googleId],
    (err, row) => {
      if (err) {
        console.error('Ошибка SELECT /auth/google:', err);
        return sendError(res, 'Внутренняя ошибка сервера', 500);
      }

      if (row) {
        // Уже есть такой пользователь — просто логин
        return res.json({
          success: true,
          message: 'Вход через Google выполнен',
          userId: row.id,
        });
      }

      // Если нет — создаём нового
      const insert = db.prepare(`
        INSERT INTO users (identifier, passwordHash, name, provider, providerId)
        VALUES (?, NULL, ?, 'google', ?)
      `);

      insert.run(email, name || '', googleId, function (err2) {
        if (err2) {
          console.error('Ошибка INSERT /auth/google:', err2);
          return sendError(res, 'Не удалось создать пользователя Google', 500);
        }

        res.json({
          success: true,
          message: 'Пользователь Google создан и вошёл',
          userId: this.lastID,
        });
      });
    }
  );
});

// ---------- ЗАПУСК СЕРВЕРА ----------
const PORT = process.env.PORT || 10000;

app.listen(PORT, () => {
  console.log(`Сервер работает на порту ${PORT}`);
});
