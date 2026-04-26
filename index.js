const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');

const app = express();

const PORT = process.env.PORT || 10000;
const JWT_SECRET =
  process.env.JWT_SECRET ||
  (process.env.NODE_ENV === 'production' ? '' : 'dev_secret');
const GOOGLE_WEB_CLIENT_ID =
  process.env.GOOGLE_WEB_CLIENT_ID ||
  '485824520166-clrt7ck6mol80vu59nmua0ob17bt78e4.apps.googleusercontent.com';
const GOOGLE_ANDROID_CLIENT_ID = process.env.GOOGLE_ANDROID_CLIENT_ID;
const googleClient = new OAuth2Client();

app.use(cors());
app.use(express.json());

const db = new sqlite3.Database('./users.db');

function ensureColumn(columnNames, name, sql) {
  if (!columnNames.includes(name)) {
    db.run(sql, (error) => {
      if (error && !String(error.message).includes('duplicate column')) {
        console.error(`Failed to add ${name} column:`, error);
      }
    });
  }
}

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      identifier TEXT,
      passwordHash TEXT,
      password TEXT,
      name TEXT,
      provider TEXT NOT NULL DEFAULT 'local',
      providerId TEXT,
      photoUrl TEXT,
      email TEXT,
      phone TEXT,
      UNIQUE(provider, providerId)
    )
  `);

  db.all('PRAGMA table_info(users)', (error, columns) => {
    if (error) {
      console.error('Failed to inspect users table schema:', error);
      return;
    }

    const columnNames = columns.map((column) => column.name);
    ensureColumn(columnNames, 'identifier', 'ALTER TABLE users ADD COLUMN identifier TEXT');
    ensureColumn(columnNames, 'passwordHash', 'ALTER TABLE users ADD COLUMN passwordHash TEXT');
    ensureColumn(columnNames, 'password', 'ALTER TABLE users ADD COLUMN password TEXT');
    ensureColumn(columnNames, 'name', 'ALTER TABLE users ADD COLUMN name TEXT');
    ensureColumn(columnNames, 'provider', "ALTER TABLE users ADD COLUMN provider TEXT NOT NULL DEFAULT 'local'");
    ensureColumn(columnNames, 'providerId', 'ALTER TABLE users ADD COLUMN providerId TEXT');
    ensureColumn(columnNames, 'photoUrl', 'ALTER TABLE users ADD COLUMN photoUrl TEXT');
    ensureColumn(columnNames, 'email', 'ALTER TABLE users ADD COLUMN email TEXT');
    ensureColumn(columnNames, 'phone', 'ALTER TABLE users ADD COLUMN phone TEXT');

    if (columnNames.includes('email')) {
      db.run(
        `
          UPDATE users
          SET identifier = LOWER(email)
          WHERE (identifier IS NULL OR TRIM(identifier) = '')
            AND email IS NOT NULL
            AND TRIM(email) != ''
        `,
        (migrationError) => {
          if (migrationError) {
            console.error('Failed to backfill identifier from email:', migrationError);
          }
        },
      );
    }

    if (columnNames.includes('phone')) {
      db.run(
        `
          UPDATE users
          SET identifier = phone
          WHERE (identifier IS NULL OR TRIM(identifier) = '')
            AND phone IS NOT NULL
            AND TRIM(phone) != ''
        `,
        (migrationError) => {
          if (migrationError) {
            console.error('Failed to backfill identifier from phone:', migrationError);
          }
        },
      );
    }

    db.run(
      `
        UPDATE users
        SET provider = 'local'
        WHERE provider IS NULL OR TRIM(provider) = ''
      `,
      (migrationError) => {
        if (migrationError) {
          console.error('Failed to backfill provider column:', migrationError);
        }
      },
    );
  });
});

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

function normalizeEmail(value) {
  const trimmed = String(value || '').trim();
  return trimmed ? trimmed.toLowerCase() : null;
}

function normalizePhone(value) {
  const trimmed = String(value || '').trim();
  if (!trimmed) {
    return null;
  }

  const hasPlus = trimmed.startsWith('+');
  const digitsOnly = trimmed.replace(/\D/g, '');
  if (!digitsOnly) {
    return null;
  }

  return hasPlus ? `+${digitsOnly}` : digitsOnly;
}

function resolveContact(body = {}) {
  const email = normalizeEmail(body.email);
  const phone = normalizePhone(body.phone);
  const rawContact = String(
    body.emailOrPhone || body.contact || body.identifier || '',
  ).trim();

  if (email) {
    return {
      type: 'email',
      identifier: email,
      email,
      phone: null,
    };
  }

  if (phone) {
    return {
      type: 'phone',
      identifier: phone,
      email: null,
      phone,
    };
  }

  if (rawContact.includes('@')) {
    const normalizedEmail = normalizeEmail(rawContact);
    return normalizedEmail
      ? {
          type: 'email',
          identifier: normalizedEmail,
          email: normalizedEmail,
          phone: null,
        }
      : null;
  }

  const normalizedPhone = normalizePhone(rawContact);
  return normalizedPhone
    ? {
        type: 'phone',
        identifier: normalizedPhone,
        email: null,
        phone: normalizedPhone,
      }
    : null;
}

function buildUserResponse(user, provider = user.provider || 'local') {
  return {
    id: user.id,
    name: user.name || '',
    email: normalizeEmail(user.email) || null,
    phone: normalizePhone(user.phone) || null,
    provider,
  };
}

function buildAuthResponse(user, message, provider = user.provider || 'local') {
  if (!JWT_SECRET) {
    throw new Error('JWT_SECRET is not configured');
  }

  const token = jwt.sign(
    {
      id: user.id,
      email: user.email || null,
      phone: user.phone || null,
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

function logAuthSuccess(endpoint, user, responseBody) {
  const tokenPreview = typeof responseBody.token === 'string'
    ? `${responseBody.token.slice(0, 12)}...`
    : 'missing';
  console.log(`[Auth] ${endpoint} success for user ${user.id}`);
  console.log(`[Auth] ${endpoint} token created: ${tokenPreview}`);
  console.log(
    `[Auth] ${endpoint} response: ${JSON.stringify({
      success: responseBody.success,
      user: responseBody.user,
    })}`,
  );
}

function decodeJwtPayloadUnsafe(idToken) {
  if (!idToken) return null;

  try {
    const parts = String(idToken).split('.');
    if (parts.length !== 3) {
      return null;
    }

    const normalizedPayload = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const paddedPayload = normalizedPayload.padEnd(
      Math.ceil(normalizedPayload.length / 4) * 4,
      '=',
    );
    return JSON.parse(Buffer.from(paddedPayload, 'base64').toString('utf8'));
  } catch (error) {
    console.error('[GoogleAuth] failed to decode token payload:', error.message);
    return null;
  }
}

async function verifyGoogleIdToken(idToken) {
  const allowedAudiences = [
    GOOGLE_WEB_CLIENT_ID,
    GOOGLE_ANDROID_CLIENT_ID,
  ].filter(Boolean);
  const decodedPayload = decodeJwtPayloadUnsafe(idToken);

  console.log(
    '[GoogleAuth] env GOOGLE_WEB_CLIENT_ID exists:',
    Boolean(process.env.GOOGLE_WEB_CLIENT_ID),
  );
  console.log(
    '[GoogleAuth] env GOOGLE_WEB_CLIENT_ID:',
    process.env.GOOGLE_WEB_CLIENT_ID,
  );
  console.log(
    '[GoogleAuth] env GOOGLE_ANDROID_CLIENT_ID exists:',
    Boolean(process.env.GOOGLE_ANDROID_CLIENT_ID),
  );
  console.log(
    '[GoogleAuth] env GOOGLE_ANDROID_CLIENT_ID:',
    process.env.GOOGLE_ANDROID_CLIENT_ID,
  );
  console.log('[GoogleAuth] effective audiences:', allowedAudiences);
  console.log('[GoogleAuth] idToken exists:', Boolean(idToken));
  console.log('[GoogleAuth] idToken length:', idToken ? idToken.length : 0);
  if (decodedPayload) {
    console.log('[GoogleAuth] token aud:', decodedPayload.aud);
    console.log('[GoogleAuth] token iss:', decodedPayload.iss);
    console.log('[GoogleAuth] token email:', decodedPayload.email);
  }

  try {
    const ticket = await googleClient.verifyIdToken({
      idToken,
      audience: allowedAudiences,
    });
    const payload = ticket.getPayload();

    if (!payload?.sub || !payload?.email) {
      return null;
    }

    return payload;
  } catch (error) {
    console.error('[GoogleAuth] verifyIdToken failed:', error.message);
    return null;
  }
}

async function findExistingEmailPhoneUser(contact) {
  return dbGet(
    `
      SELECT * FROM users
      WHERE provider IN ('local', 'email_phone') AND (
        LOWER(identifier) = LOWER(?)
        OR (LOWER(email) = LOWER(?) AND ? IS NOT NULL)
        OR (phone = ? AND ? IS NOT NULL)
      )
    `,
    [
      contact.identifier,
      contact.email,
      contact.email,
      contact.phone,
      contact.phone,
    ],
  );
}

async function verifyLocalPassword(user, password) {
  if (user.passwordHash) {
    return bcrypt.compare(password, user.passwordHash);
  }

  if (typeof user.password === 'string' && user.password === password) {
    const passwordHash = await bcrypt.hash(password, 10);
    await dbRun('UPDATE users SET passwordHash = ? WHERE id = ?', [
      passwordHash,
      user.id,
    ]);
    return true;
  }

  return false;
}

async function handleRegister(req, res) {
  const endpoint = req.originalUrl || req.path;
  const requestBody = req.body || {};
  const name = String(requestBody.name || '').trim();
  const password = String(requestBody.password || '').trim();
  const contact = resolveContact(requestBody);

  console.log(`[Auth] ${endpoint} called`);
  console.log(`[Auth] ${endpoint} body keys:`, Object.keys(requestBody));

  if (!contact || !password || !name) {
    return sendError(res, 'Не хватает данных (name, emailOrPhone, password)', 400);
  }

  try {
    const existingUser = await findExistingEmailPhoneUser(contact);
    if (existingUser) {
      console.log(`[Auth] ${endpoint} existing user found: ${existingUser.id}`);
      return sendError(res, 'Пользователь уже существует', 409);
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const result = await dbRun(
      `
        INSERT INTO users (
          identifier,
          passwordHash,
          name,
          provider,
          providerId,
          photoUrl,
          email,
          phone
        )
        VALUES (?, ?, ?, 'email_phone', ?, NULL, ?, ?)
      `,
      [
        contact.identifier,
        passwordHash,
        name,
        contact.identifier,
        contact.email,
        contact.phone,
      ],
    );

    const user = await dbGet('SELECT * FROM users WHERE id = ?', [result.lastID]);
    console.log(`[Auth] ${endpoint} user created: ${user.id}`);
    const responseBody = buildAuthResponse(
      user,
      'Регистрация выполнена',
      'email_phone',
    );
    logAuthSuccess(endpoint, user, responseBody);
    return res.json(responseBody);
  } catch (error) {
    console.error(`[Auth] ${endpoint} failed:`, error);
    return sendError(res, 'Внутренняя ошибка сервера', 500);
  }
}

async function handleLogin(req, res) {
  const endpoint = req.originalUrl || req.path;
  const requestBody = req.body || {};
  const password = String(requestBody.password || '').trim();
  const contact = resolveContact(requestBody);

  console.log(`[Auth] ${endpoint} called`);
  console.log(`[Auth] ${endpoint} body keys:`, Object.keys(requestBody));

  if (!contact || !password) {
    return sendError(res, 'Не хватает данных (emailOrPhone, password)', 400);
  }

  try {
    const user = await findExistingEmailPhoneUser(contact);
    if (!user) {
      console.log(`[Auth] ${endpoint} user not found`);
      return sendError(res, 'Пользователь не найден', 404);
    }

    console.log(`[Auth] ${endpoint} found user: ${user.id}`);
    const passwordMatches = await verifyLocalPassword(user, password);
    if (!passwordMatches) {
      return sendError(res, 'Неверный пароль', 401);
    }

    const freshUser = await dbGet('SELECT * FROM users WHERE id = ?', [user.id]);
    const responseBody = buildAuthResponse(
      freshUser,
      'Вход выполнен',
      'email_phone',
    );
    logAuthSuccess(endpoint, freshUser, responseBody);
    return res.json(responseBody);
  } catch (error) {
    console.error(`[Auth] ${endpoint} failed:`, error);
    return sendError(res, 'Внутренняя ошибка сервера', 500);
  }
}

app.get('/', (req, res) => {
  res.json({ ok: true, message: 'Agronom Online auth server' });
});

app.post(['/register', '/auth/register'], handleRegister);
app.post(['/login', '/auth/login'], handleLogin);

app.post('/auth/google', async (req, res) => {
  const requestBody = req.body || {};
  console.log('[GoogleAuth] body keys:', Object.keys(requestBody));
  console.log(
    '[GoogleAuth] idToken from body exists:',
    Boolean(requestBody.idToken),
  );
  console.log(
    '[GoogleAuth] accessToken from body exists:',
    Boolean(requestBody.accessToken),
  );

  const { idToken, googleId, email, name, photoUrl, accessToken } = requestBody;

  if (!idToken) {
    return sendError(res, 'Invalid Google token', 401);
  }

  try {
    const payload = await verifyGoogleIdToken(idToken);
    if (!payload) {
      return sendError(res, 'Invalid Google token', 401);
    }

    const verifiedGoogleId = payload.sub;
    const verifiedEmail = normalizeEmail(payload.email);
    const resolvedName = String(payload.name || name || '').trim();
    const resolvedPhotoUrl = payload.picture || photoUrl || null;

    if (googleId && googleId !== verifiedGoogleId) {
      console.warn('Google ID mismatch detected, using verified token value');
    }
    if (email && normalizeEmail(email) !== verifiedEmail) {
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
          WHERE LOWER(identifier) = LOWER(?) OR LOWER(email) = LOWER(?)
        `,
        [verifiedEmail, verifiedEmail],
      ));

    if (user) {
      const nextProvider = user.provider === 'google' ? 'google' : user.provider;
      await dbRun(
        `
          UPDATE users
          SET
            identifier = ?,
            name = ?,
            provider = ?,
            providerId = ?,
            photoUrl = ?,
            email = ?,
            phone = NULL
          WHERE id = ?
        `,
        [
          verifiedEmail,
          resolvedName || user.name || '',
          nextProvider,
          verifiedGoogleId,
          resolvedPhotoUrl,
          verifiedEmail,
          user.id,
        ],
      );

      user = await dbGet('SELECT * FROM users WHERE id = ?', [user.id]);
      const responseBody = buildAuthResponse(
        user,
        'Вход через Google выполнен',
        'google',
      );
      logAuthSuccess('/auth/google', user, responseBody);
      return res.json(responseBody);
    }

    const insertResult = await dbRun(
      `
        INSERT INTO users (
          identifier,
          passwordHash,
          name,
          provider,
          providerId,
          photoUrl,
          email,
          phone
        )
        VALUES (?, NULL, ?, 'google', ?, ?, ?, NULL)
      `,
      [
        verifiedEmail,
        resolvedName,
        verifiedGoogleId,
        resolvedPhotoUrl,
        verifiedEmail,
      ],
    );

    user = await dbGet('SELECT * FROM users WHERE id = ?', [insertResult.lastID]);
    const responseBody = buildAuthResponse(
      user,
      'Вход через Google выполнен',
      'google',
    );
    logAuthSuccess('/auth/google', user, responseBody);
    return res.json(responseBody);
  } catch (error) {
    console.error('Google auth failed:', error);
    return sendError(res, 'Google auth failed', 500);
  }
});

app.listen(PORT, () => {
  if (!process.env.JWT_SECRET && process.env.NODE_ENV !== 'production') {
    console.warn('[Auth] JWT_SECRET is missing, using dev_secret fallback');
  }
  console.log(`Auth server listening on port ${PORT}`);
});
