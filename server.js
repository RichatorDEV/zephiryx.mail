const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');

const app = express();
const port = process.env.PORT || 8080;

app.use(cors({
  origin: ['https://unlockedvalle.github.io', 'https://unlockedvalle.github.io/zephiryx.mail'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const SECRET_KEY = process.env.SECRET_KEY || 'zephiryx-secret-key';
const DOMAIN = 'zephiryx.com';

// Initialize DB
(async () => {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL
      );
      CREATE TABLE IF NOT EXISTS profiles (
        user_id INTEGER PRIMARY KEY REFERENCES users(id),
        display_name VARCHAR(255),
        profile_picture VARCHAR(255)
      );
      CREATE TABLE IF NOT EXISTS accounts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        email VARCHAR(255) UNIQUE NOT NULL
      );
      CREATE TABLE IF NOT EXISTS emails (
        id SERIAL PRIMARY KEY,
        from_email VARCHAR(255) NOT NULL,
        to_email VARCHAR(255) NOT NULL,
        subject VARCHAR(255),
        body TEXT,
        sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_spam BOOLEAN DEFAULT FALSE,
        is_draft BOOLEAN DEFAULT FALSE,
        is_sent BOOLEAN DEFAULT FALSE
      );
    `);
  } catch (err) {
    console.error('Error creating tables', err);
  } finally {
    client.release();
  }
})();

// Middleware for token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token requerido' });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token inválido' });
    req.user = user;
    next();
  });
};

// Check if prefix is available
app.get('/api/check_prefix', async (req, res) => {
  const { prefix } = req.query;
  try {
    const result = await pool.query('SELECT * FROM accounts WHERE email = $1', [`${prefix}@${DOMAIN}`]);
    res.json({ available: result.rows.length === 0 });
  } catch (error) {
    res.status(500).json({ error: 'Error al comprobar prefijo' });
  }
});

// Register
app.post('/api/register', async (req, res) => {
  const { username, password, display_name, profile_picture } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
  }
  try {
    const hash = await bcrypt.hash(password, 10);
    const userResult = await pool.query(
      'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id',
      [username, hash]
    );
    const userId = userResult.rows[0].id;
    await pool.query(
      'INSERT INTO profiles (user_id, display_name, profile_picture) VALUES ($1, $2, $3)',
      [userId, display_name || username, profile_picture || null]
    );
    await pool.query(
      'INSERT INTO accounts (user_id, email) VALUES ($1, $2)',
      [userId, `${username}@${DOMAIN}`]
    );
    const token = jwt.sign({ username, userId }, SECRET_KEY, { expiresIn: '1h' });
    res.status(201).json({ message: 'Usuario registrado', token });
  } catch (error) {
    res.status(400).json({ error: 'Error al registrar: ' + error.message });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }
    const token = jwt.sign({ username, userId: user.id }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    res.status(500).json({ error: 'Error en login' });
  }
});

// Get profile
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM profiles WHERE user_id = $1', [req.user.userId]);
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener perfil' });
  }
});

// Update profile
app.put('/api/profile', authenticateToken, async (req, res) => {
  const { display_name, profile_picture, password } = req.body;
  try {
    if (display_name || profile_picture) {
      await pool.query(
        'UPDATE profiles SET display_name = COALESCE($1, display_name), profile_picture = COALESCE($2, profile_picture) WHERE user_id = $3',
        [display_name, profile_picture, req.user.userId]
      );
    }
    if (password) {
      const hash = await bcrypt.hash(password, 10);
      await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, req.user.userId]);
    }
    res.json({ message: 'Perfil actualizado' });
  } catch (error) {
    res.status(500).json({ error: 'Error al actualizar perfil' });
  }
});

// Get accounts
app.get('/api/accounts', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT email FROM accounts WHERE user_id = $1', [req.user.userId]);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener cuentas' });
  }
});

// Add account (login and add to user)
app.post('/api/accounts', authenticateToken, async (req, res) => {
  const { email, password } = req.body;
  if (!email.endsWith(`@${DOMAIN}`)) {
    return res.status(400).json({ error: 'Correo debe ser del dominio @zephiryx.com' });
  }
  try {
    const username = email.split('@')[0];
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: 'Credenciales inválidas para la cuenta' });
    }
    await pool.query('INSERT INTO accounts (user_id, email) VALUES ($1, $2) ON CONFLICT DO NOTHING', [req.user.userId, email]);
    res.status(201).json({ message: 'Cuenta añadida' });
  } catch (error) {
    res.status(400).json({ error: 'Error al añadir cuenta: ' + error.message });
  }
});

// Get emails (inbox, sent, spam, drafts)
app.get('/api/emails/:type', authenticateToken, async (req, res) => {
  const { type } = req.params;
  try {
    const userEmails = await pool.query('SELECT email FROM accounts WHERE user_id = $1', [req.user.userId]);
    const emails = userEmails.rows.map(row => row.email);
    let query = '';
    let params = [emails];
    
    if (type === 'inbox') {
      query = 'SELECT * FROM emails WHERE to_email = ANY($1) AND is_spam = FALSE AND is_draft = FALSE ORDER BY sent_at DESC';
    } else if (type === 'sent') {
      query = 'SELECT * FROM emails WHERE from_email = ANY($1) AND is_sent = TRUE ORDER BY sent_at DESC';
    } else if (type === 'spam') {
      query = 'SELECT * FROM emails WHERE to_email = ANY($1) AND is_spam = TRUE ORDER BY sent_at DESC';
    } else if (type === 'drafts') {
      query = 'SELECT * FROM emails WHERE from_email = ANY($1) AND is_draft = TRUE ORDER BY sent_at DESC';
    } else {
      return res.status(400).json({ error: 'Tipo de bandeja inválido' });
    }

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener correos' });
  }
});

// Send email
app.post('/api/emails', authenticateToken, async (req, res) => {
  const { to, subject, body, from, is_draft } = req.body;
  try {
    if (!to || !from) {
      return res.status(400).json({ error: 'De y Para son requeridos' });
    }
    if (!to.endsWith(`@${DOMAIN}`) || !from.endsWith(`@${DOMAIN}`)) {
      return res.status(400).json({ error: 'Solo se permiten correos dentro del dominio @zephiryx.com' });
    }
    const toUsername = to.split('@')[0];
    const userCheck = await pool.query('SELECT * FROM users WHERE username = $1', [toUsername]);
    if (!is_draft && userCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Usuario destinatario no existe' });
    }
    // Basic spam detection
    const spamKeywords = ['oferta', 'gratis', 'promoción', 'descuento'];
    const isSpam = spamKeywords.some(keyword => body.toLowerCase().includes(keyword) || subject.toLowerCase().includes(keyword));
    await pool.query(
      'INSERT INTO emails (from_email, to_email, subject, body, is_spam, is_draft, is_sent) VALUES ($1, $2, $3, $4, $5, $6, $7)',
      [from, to, subject, body, isSpam && !is_draft, is_draft || false, !is_draft]
    );
    res.status(201).json({ message: is_draft ? 'Borrador guardado' : 'Correo enviado' });
  } catch (error) {
    res.status(500).json({ error: 'Error al enviar correo: ' + error.message });
  }
});

app.listen(port, () => {
  console.log(`Servidor corriendo en puerto ${port}`);
});
