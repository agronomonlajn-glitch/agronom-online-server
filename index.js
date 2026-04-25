const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');

const app = express();

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET;
const GOOGLE_WEB_CLIENT_ID =
  process.env.GOOGLE_WEB_CLIENT_ID ||
  '485824520166-clrt7ck6mol80vu59nmua0ob17bt78e4.apps.googleusercontent.com';
const googleClient = new OAuth2Client(GOOGLE_WEB_CLIENT_ID);

app.use(cors());
app.use(express.json());

const db = new sqlite3.Database('./users.db');

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      identifier TEXT NOT NULL,
      passwordHash TEXT,
      name TEXT,
      provider TEXT NOT NULL DEFAULT 'local',
      providerId TEXT,
      photoUrl TEXT,
      UNIQUE(provider, providerId)
    )
  `);

  db.all('PRAGMA table_info(users)', (error, columns) => {
    if (error) {
      console.error('Failed to inspect users table schema:', error);
      return;
    }

    const columnNames = columns.map((column) => column.name);
    if (!columnNames.includes('photoUrl')) {
      db.run('ALTER TABLE users ADD COLUMN photoUrl TEXT', (alterError) => {
        if (alterError && !String(alterError.message).includes('duplicate column')) {
          console.error('Failed to add photoUrl column:', alterError);
        }
      });
    }
  });
});

class InvalidGoogleTokenError extends Error {
  constructor(message = 'Invalid Google token') {
    super(message);
    this.name = 'InvalidGoogleTokenError';
  }
}

function sendError(res, message, code = 400) {
  res.status(code).json({ success: false, message });
}

function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (error, row) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(row || null);
    });
  });
}

function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function onRun(error) {
      if (error) {
        reject(error);
        return;
      }
      resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}

function buildUserResponse(user, provider = user.provider || 'local') {
  return {
    id: user.id,
    email: user.identifier,
    name: user.name || '',
    photoUrl: user.photoUrl || null,
    provider,
  };
}

function buildAuthResponse(user, message, provider = user.provider || 'local') {
  if (!JWT_SECRET) {
    throw new Error('JWT_SECRET is not configured');
  }

  const token = jwt.sign(
    {
      userId: user.id,
      email: user.identifier,
      provider,
    },
    JWT_SECRET,
    { expiresIn: '30d' },
  );

  return {
    success: true,
    message,
    token,
    userId: user.id,
    user: buildUserResponse(user, provider),
  };
}

async function verifyGoogleIdToken(idToken) {
  try {
    const ticket = await googleClient.verifyIdToken({
      idToken,
      audience: GOOGLE_WEB_CLIENT_ID,
    });
    const payload = ticket.getPayload();

    if (!payload?.sub || !payload?.email) {
      throw new InvalidGoogleTokenError();
    }

    return payload;
  } catch (error) {
    console.error('Google token verification failed:', error);
    throw new InvalidGoogleTokenError();
  }
}

app.get('/', (req, res) => {
  res.json({ ok: true, message: 'Agronom Online auth server' });
});

app.post('/register', async (req, res) => {
  const { identifier, password, name } = req.body || {};

  if (!identifier || !password || !name) {
    return sendError(
      res,
      'Не хватает данных (identifier, password, name)',
      400,
    );
  }

  try {
    const saltRounds = 10;
    const hash = await bcrypt.hash(password, saltRounds);

    const result = await dbRun(
      `
        INSERT INTO users (identifier, passwordHash, name, provider, providerId)
        VALUES (?, ?, ?, 'local', ?)
      `,
      [identifier, hash, name, identifier],
    );

    res.json({
      success: true,
      message: 'Регистрация успешна',
      userId: result.lastID,
    });
  } catch (error) {
    if (error.code === 'SQLITE_CONSTRAINT') {
      return sendError(res, 'Такой пользователь уже существует', 409);
    }

    console.error('Ошибка /register:', error);
    return sendError(res, 'Внутренняя ошибка сервера', 500);
  }
});

app.post('/login', async (req, res) => {
  const { identifier, password } = req.body || {};

  if (!identifier || !password) {
    return sendError(res, 'Не хватает данных (identifier, password)', 400);
  }

  try {
    const row = await dbGet(
      `
        SELECT * FROM users
        WHERE provider = 'local' AND identifier = ?
      `,
      [identifier],
    );

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
  } catch (error) {
    console.error('Ошибка /login:', error);
    return sendError(res, 'Внутренняя ошибка сервера', 500);
  }
});

app.post('/auth/google', async (req, res) => {
  const requestBody = req.body || {};
  const {
    idToken,
    googleId,
    email,
    name,
    photoUrl,
    accessToken,
  } = requestBody;

  if (!idToken) {
    return sendError(res, 'Invalid Google token', 401);
  }

  try {
    const payload = await verifyGoogleIdToken(idToken);
    const verifiedGoogleId = payload.sub;
    const verifiedEmail = String(payload.email).trim().toLowerCase();
    const resolvedName = payload.name || name || '';
    const resolvedPhotoUrl = payload.picture || photoUrl || null;

    if (googleId && googleId !== verifiedGoogleId) {
      console.warn('Google ID mismatch detected, using verified token value');
    }
    if (email && String(email).trim().toLowerCase() !== verifiedEmail) {
      console.warn('Google email mismatch detected, using verified token value');
    }
    if (accessToken) {
      console.log('Google accessToken received for diagnostics');
    }

    let user =
      (await dbGet(
        `
          SELECT * FROM users
          WHERE provider = 'google' AND providerId = ?
        `,
        [verifiedGoogleId],
      )) ||
      (await dbGet(
        `
          SELECT * FROM users
          WHERE LOWER(identifier) = LOWER(?)
        `,
        [verifiedEmail],
      ));

    if (user) {
      const nextProvider = user.provider === 'google' ? 'google' : user.provider;
      await dbRun(
        `
          UPDATE users
          SET identifier = ?, name = ?, provider = ?, providerId = ?, photoUrl = ?
          WHERE id = ?
        `,
        [
          verifiedEmail,
          resolvedName || user.name || '',
          nextProvider,
          verifiedGoogleId,
          resolvedPhotoUrl,
          user.id,
        ],
      );

      user = await dbGet('SELECT * FROM users WHERE id = ?', [user.id]);

      return res.json(
        buildAuthResponse(user, 'Вход через Google выполнен', 'google'),
      );
    }

    const insertResult = await dbRun(
      `
        INSERT INTO users (identifier, passwordHash, name, provider, providerId, photoUrl)
        VALUES (?, NULL, ?, 'google', ?, ?)
      `,
      [verifiedEmail, resolvedName, verifiedGoogleId, resolvedPhotoUrl],
    );

    user = await dbGet('SELECT * FROM users WHERE id = ?', [insertResult.lastID]);

    return res.json(
      buildAuthResponse(user, 'Вход через Google выполнен', 'google'),
    );
  } catch (error) {
    if (error instanceof InvalidGoogleTokenError) {
      return sendError(res, 'Invalid Google token', 401);
    }

    console.error('Google auth failed:', error);
    return sendError(res, 'Google auth failed', 500);
  }
});

app.listen(PORT, () => {
  console.log(`Сервер работает на порту ${PORT}`);
});
