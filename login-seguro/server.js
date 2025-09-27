// server.js — listo para local y Render
const path = require('path');

// Carga .env cuando existe (local). En Render las vars vienen del panel.
require('dotenv').config({ path: path.join(__dirname, '.env') });

const express = require('express');
const session = require('express-session');
const bcrypt  = require('bcryptjs');
const helmet  = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();

// ===== Config =====
const PORT = process.env.PORT || 3000;
const EXPECTED_USER = 'santiago cantillo';               // usuario permitido (minúsculas)
const HASH = process.env.USER_SANTIAGO_CANTILLO_HASH || '';
const AUTH_DEBUG = String(process.env.AUTH_DEBUG || '').toLowerCase() === 'true';

// ===== Diagnóstico opcional =====
if (AUTH_DEBUG) {
  try {
    console.log('[BOOT] __dirname =', __dirname);
    console.log('[BOOT] ENV hash presente?', !!HASH);
    console.log('[BOOT] Hash prefix    =', (HASH || '').slice(0, 12));
    console.log('[BOOT] Match "$4nt14go#"? =>', bcrypt.compareSync('$4nt14go#', HASH));
  } catch (e) {
    console.log('[BOOT] ERROR compareSync:', e.message);
  }
}

// ===== Middlewares base =====
app.use(helmet());
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// Sesiones
app.set('trust proxy', 1);
app.use(session({
  name: 'sid',
  secret: process.env.SESSION_SECRET || 'devsecret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production', // en Render es true (HTTPS)
    maxAge: 1000 * 60 * 60, // 1h
  },
}));

// Rate limit en /login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
});

// Normaliza usuario: trim, minúsculas, colapsa espacios
const normalizeUser = (s) =>
  String(s || '').trim().toLowerCase().replace(/\s+/g, ' ');

// “BD” mínima: usuario -> hash leído de env
const USERS = {
  [EXPECTED_USER]: HASH,
};

// Auth guard
function requireAuth(req, res, next) {
  if (req.session.user) return next();
  return res.redirect('/login.html');
}

// Archivos estáticos (frontend)
app.use(express.static(path.join(__dirname, 'public')));

// Raíz → login
app.get('/', (_req, res) => res.redirect('/login.html'));

// Healthcheck
app.get('/healthz', (_req, res) => res.type('text').send('ok'));

// API de login
app.post('/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  const userKey = normalizeUser(username);
  const pwd = String(password || '');

  if (AUTH_DEBUG) {
    console.log('[LOGIN] raw username =', username);
    console.log('[LOGIN] userKey      =', userKey);
    console.log('[LOGIN] pwdLength    =', pwd.length);
    console.log('[LOGIN] hashPrefix   =', (USERS[userKey] || '').slice(0, 12));
  }

  if (!userKey) {
    return res.status(400).json({ ok: false, msg: 'Ingresa tu nombre de usuario.' });
  }
  if (pwd.length < 8) {
    return res.status(400).json({ ok: false, msg: 'La contraseña debe tener al menos 8 caracteres.' });
  }

  const hash = USERS[userKey];
  if (!hash || !hash.startsWith('$2')) {
    return res.status(401).json({ ok: false, msg: 'Usuario o contraseña inválidos.' });
  }

  try {
    const ok = await bcrypt.compare(pwd, hash);
    if (AUTH_DEBUG) console.log('[LOGIN] bcrypt.compare =>', ok);
    if (!ok) return res.status(401).json({ ok: false, msg: 'Usuario o contraseña inválidos.' });
  } catch (e) {
    if (AUTH_DEBUG) console.error('[LOGIN] compare error:', e);
    return res.status(500).json({ ok: false, msg: 'Error al validar credenciales.' });
  }

  // Éxito: crea sesión
  req.session.user = { name: userKey };
  return res.json({ ok: true, redirect: '/go' });
});

// Ruta protegida -> redirección final
app.get('/go', requireAuth, (_req, res) => {
  res.redirect(process.env.ADAFRUIT_URL || '/');
});

// Logout
app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('sid');
    res.redirect('/login.html');
  });
});

// Arranque
app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});
