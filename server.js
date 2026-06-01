// server.js — главный сервер игры
require('dotenv').config();
const express    = require('express');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const helmet     = require('helmet');
const cors       = require('cors');
const rateLimit  = require('express-rate-limit');
const path       = require('path');
const db         = require('./db');

const app  = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_dev_secret_change_in_prod';

// ====== MIDDLEWARE ======
app.use(helmet({ contentSecurityPolicy: false })); // CSP отключаем — canvas игра
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// Rate limiting — защита от брутфорса
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 минут
  max: 20,
  message: { error: 'Слишком много попыток. Подождите 15 минут.' }
});
const emailLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 час
  max: 5,
  message: { error: 'Слишком много запросов кода. Подождите час.' }
});

// ====== EMAIL ======
const transporter = nodemailer.createTransport({
  host:   process.env.MAIL_HOST   || 'smtp.gmail.com',
  port:   parseInt(process.env.MAIL_PORT || '587'),
  secure: process.env.MAIL_SECURE === 'true',
  auth: {
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_PASS,
  },
});

async function sendEmail(to, subject, html) {
  try {
    await transporter.sendMail({
      from: process.env.MAIL_FROM || 'Killer Game <noreply@killergame.com>',
      to, subject, html
    });
    return true;
  } catch (e) {
    console.error('Email error:', e.message);
    return false;
  }
}

function genCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// ====== JWT HELPER ======
function signToken(userId) {
  return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: '30d' });
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Не авторизован' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Токен недействителен' });
  }
}

// ====== HELPERS ======
function userToGameData(u) {
  return {
    nick:        u.nick,
    coins:       u.coins,
    crystals:    u.crystals,
    speedLv:     u.speed_lv,
    bestEndless: u.best_endless,
    wins:        u.wins,
    fighter:     u.fighter,
    unlocked:    JSON.parse(u.unlocked || '["bogdan"]'),
    cratesSm:    u.crates_sm,
    cratesMd:    u.crates_md,
    cratesLg:    u.crates_lg,
    lang:        u.lang,
    mobile:      u.mobile === 1,
    diff:        u.diff,
    soundVol:    u.sound_vol,
    musicVol:    u.music_vol,
    bestNick:    u.best_nick,
  };
}

// ====== МАРШРУТЫ АВТОРИЗАЦИИ ======

// POST /api/register — регистрация
app.post('/api/register', authLimiter, async (req, res) => {
  const { email, nick, password } = req.body;

  // Валидация
  if (!email || !nick || !password)
    return res.status(400).json({ error: 'Заполни все поля' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).json({ error: 'Неверный формат email' });
  if (!/^[\p{L}\p{N}]+$/u.test(nick) || nick.length < 2 || nick.length > 20)
    return res.status(400).json({ error: 'Ник: 2–20 символов, только буквы и цифры' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Пароль минимум 6 символов' });

  // Проверяем занятость email и ника
  const existEmail = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existEmail) return res.status(409).json({ error: 'Этот email уже зарегистрирован' });

  const existNick = db.prepare('SELECT id FROM users WHERE nick = ?').get(nick);
  if (existNick) return res.status(409).json({ error: 'Этот ник уже занят, выбери другой' });

  const hash = await bcrypt.hash(password, 12);

  const result = db.prepare(`
    INSERT INTO users (email, nick, password, verified)
    VALUES (?, ?, ?, 1)
  `).run(email.toLowerCase(), nick, hash);

  const token = signToken(result.lastInsertRowid);
  const user  = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);

  // Приветственное письмо (не обязательно ждать)
  sendEmail(email, '🎮 Добро пожаловать в Killer: Выживание!', `
    <div style="font-family:Arial,sans-serif;background:#0a000f;color:#fff;padding:32px;border-radius:12px;max-width:480px">
      <h1 style="color:#ff2244;font-size:28px;margin-bottom:8px">🔪 KILLER: Выживание</h1>
      <p style="color:#aaa;font-size:16px">Аккаунт создан успешно!</p>
      <hr style="border-color:#330011;margin:20px 0">
      <p>Твой ник: <strong style="color:#ffd700">${nick}</strong></p>
      <p>Удачи в игре! Выживи как можно дольше 🏃</p>
    </div>
  `);

  res.json({ token, data: userToGameData(user) });
});

// POST /api/login — вход
app.post('/api/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ error: 'Введи email и пароль' });

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase());
  if (!user) return res.status(401).json({ error: 'Неверный email или пароль' });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ error: 'Неверный email или пароль' });

  const token = signToken(user.id);
  res.json({ token, data: userToGameData(user) });
});

// POST /api/forgot — отправить код восстановления
app.post('/api/forgot', emailLimiter, async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Введи email' });

  const user = db.prepare('SELECT id, nick FROM users WHERE email = ?').get(email.toLowerCase());
  // Отвечаем одинаково — не раскрываем существование аккаунта
  if (!user) return res.json({ ok: true });

  // Удаляем старые коды
  db.prepare('DELETE FROM verify_codes WHERE email = ? AND type = ?').run(email.toLowerCase(), 'reset');

  const code    = genCode();
  const expires = new Date(Date.now() + 15 * 60 * 1000).toISOString(); // 15 минут

  db.prepare(`
    INSERT INTO verify_codes (email, code, type, expires_at)
    VALUES (?, ?, 'reset', ?)
  `).run(email.toLowerCase(), code, expires);

  await sendEmail(email, '🔑 Код восстановления — Killer Game', `
    <div style="font-family:Arial,sans-serif;background:#0a000f;color:#fff;padding:32px;border-radius:12px;max-width:480px">
      <h1 style="color:#ff2244;font-size:28px;margin-bottom:8px">🔪 KILLER: Выживание</h1>
      <p style="color:#aaa">Запрос на восстановление аккаунта</p>
      <hr style="border-color:#330011;margin:20px 0">
      <p>Привет, <strong style="color:#ffd700">${user.nick}</strong>!</p>
      <p>Твой код подтверждения:</p>
      <div style="background:#1a0008;border:2px solid #ff2244;border-radius:12px;padding:20px;text-align:center;margin:16px 0">
        <span style="color:#ff2244;font-size:42px;font-weight:700;letter-spacing:8px">${code}</span>
      </div>
      <p style="color:#888;font-size:14px">Код действителен 15 минут.</p>
      <p style="color:#888;font-size:14px">Если это не ты — просто проигнорируй письмо.</p>
    </div>
  `);

  res.json({ ok: true });
});

// POST /api/reset — подтвердить код и сбросить пароль
app.post('/api/reset', authLimiter, async (req, res) => {
  const { email, code, newPassword } = req.body;

  if (!email || !code || !newPassword)
    return res.status(400).json({ error: 'Все поля обязательны' });
  if (newPassword.length < 6)
    return res.status(400).json({ error: 'Пароль минимум 6 символов' });

  const row = db.prepare(`
    SELECT * FROM verify_codes
    WHERE email = ? AND code = ? AND type = 'reset' AND used = 0
    ORDER BY id DESC LIMIT 1
  `).get(email.toLowerCase(), code.trim());

  if (!row) return res.status(400).json({ error: 'Неверный код' });
  if (new Date(row.expires_at) < new Date())
    return res.status(400).json({ error: 'Код устарел, запроси новый' });

  // Помечаем код как использованный
  db.prepare('UPDATE verify_codes SET used = 1 WHERE id = ?').run(row.id);

  const hash = await bcrypt.hash(newPassword, 12);
  const user = db.prepare('UPDATE users SET password = ? WHERE email = ? RETURNING *')
    .get(hash, email.toLowerCase());

  if (!user) return res.status(404).json({ error: 'Аккаунт не найден' });

  const token = signToken(user.id);
  res.json({ token, data: userToGameData(user) });
});

// POST /api/check-nick — проверить свободен ли ник
app.post('/api/check-nick', async (req, res) => {
  const { nick } = req.body;
  if (!nick) return res.json({ available: false });
  const exists = db.prepare('SELECT id FROM users WHERE nick = ?').get(nick);
  res.json({ available: !exists });
});

// POST /api/change-nick — сменить ник (авторизованный)
app.post('/api/change-nick', authMiddleware, async (req, res) => {
  const { nick } = req.body;
  if (!nick || !/^[\p{L}\p{N}]+$/u.test(nick) || nick.length < 2 || nick.length > 20)
    return res.status(400).json({ error: 'Ник: 2–20 символов, только буквы и цифры' });

  const exists = db.prepare('SELECT id FROM users WHERE nick = ? AND id != ?').get(nick, req.user.id);
  if (exists) return res.status(409).json({ error: 'Этот ник уже занят' });

  db.prepare('UPDATE users SET nick = ? WHERE id = ?').run(nick, req.user.id);
  res.json({ ok: true, nick });
});

// GET /api/me — получить данные текущего пользователя
app.get('/api/me', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
  res.json({ data: userToGameData(user) });
});

// POST /api/save — сохранить игровые данные
app.post('/api/save', authMiddleware, (req, res) => {
  const d = req.body;
  if (!d) return res.status(400).json({ error: 'Нет данных' });

  db.prepare(`
    UPDATE users SET
      coins        = ?,
      crystals     = ?,
      speed_lv     = ?,
      best_endless = ?,
      wins         = ?,
      fighter      = ?,
      unlocked     = ?,
      crates_sm    = ?,
      crates_md    = ?,
      crates_lg    = ?,
      lang         = ?,
      mobile       = ?,
      diff         = ?,
      sound_vol    = ?,
      music_vol    = ?,
      best_nick    = ?,
      lb_data      = ?
    WHERE id = ?
  `).run(
    d.coins        ?? 200,
    d.crystals     ?? 10,
    d.speedLv      ?? 0,
    d.bestEndless  ?? 0,
    d.wins         ?? 0,
    d.fighter      || 'bogdan',
    JSON.stringify(d.unlocked || ['bogdan']),
    d.cratesSm     ?? 0,
    d.cratesMd     ?? 0,
    d.cratesLg     ?? 0,
    d.lang         || 'ru',
    d.mobile       ? 1 : 0,
    d.diff         || 'normal',
    d.soundVol     ?? 0.8,
    d.musicVol     ?? 0.5,
    d.bestNick     || '',
    JSON.stringify(d.lb || []),
    req.user.id
  );

  res.json({ ok: true });
});

// GET /api/leaderboard — таблица лидеров (публичная)
app.get('/api/leaderboard', (req, res) => {
  const rows = db.prepare(`
    SELECT nick, best_endless, wins
    FROM users
    ORDER BY best_endless DESC, wins DESC
    LIMIT 100
  `).all();
  res.json(rows);
});

// ====== ФРОНТЕНД — все остальные пути отдают игру ======
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'игра.html'));
});

// ====== СТАРТ ======
app.listen(PORT, () => {
  console.log(`🎮 Killer Game Server запущен на порту ${PORT}`);
  console.log(`📂 База данных: ${process.env.DB_PATH || 'game.db'}`);
});
