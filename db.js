// db.js — инициализация базы данных SQLite
const Database = require('better-sqlite3');
const path = require('path');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'game.db');
const db = new Database(DB_PATH);

// Включаем WAL для лучшей производительности
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// ====== СОЗДАНИЕ ТАБЛИЦ ======
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    email        TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    nick         TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password     TEXT    NOT NULL,
    verified     INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT    NOT NULL DEFAULT (datetime('now')),

    -- Игровые данные
    coins        INTEGER NOT NULL DEFAULT 200,
    crystals     INTEGER NOT NULL DEFAULT 10,
    speed_lv     INTEGER NOT NULL DEFAULT 0,
    best_endless INTEGER NOT NULL DEFAULT 0,
    wins         INTEGER NOT NULL DEFAULT 0,
    fighter      TEXT    NOT NULL DEFAULT 'bogdan',
    unlocked     TEXT    NOT NULL DEFAULT '["bogdan"]',
    crates_sm    INTEGER NOT NULL DEFAULT 0,
    crates_md    INTEGER NOT NULL DEFAULT 0,
    crates_lg    INTEGER NOT NULL DEFAULT 0,
    lang         TEXT    NOT NULL DEFAULT 'ru',
    mobile       INTEGER NOT NULL DEFAULT 1,
    diff         TEXT    NOT NULL DEFAULT 'normal',
    sound_vol    REAL    NOT NULL DEFAULT 0.8,
    music_vol    REAL    NOT NULL DEFAULT 0.5,
    best_nick    TEXT    NOT NULL DEFAULT '',
    lb_data      TEXT    NOT NULL DEFAULT '[]'
  );

  CREATE TABLE IF NOT EXISTS verify_codes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    email      TEXT    NOT NULL COLLATE NOCASE,
    code       TEXT    NOT NULL,
    type       TEXT    NOT NULL DEFAULT 'reset',
    expires_at TEXT    NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0
  );
`);

module.exports = db;
