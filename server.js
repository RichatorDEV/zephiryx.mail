const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');

const app = express();
const port = process.env.PORT || 8080;

app.use(cors({
  origin: ['https://unlockedvalle.github.io', 'https://unlockedvalle.github.io/zephiryx.mail'],
  methods: ['GET', 'POST', 'OPTIONS'],
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
      CREATE TABLE IF NOT EXISTS emails (
        id SERIAL PRIMARY KEY,
        from_email VARCHAR(255) NOT NULL,
        to_email VARCHAR(255) NOT NULL,
        subject VARCHAR(255),
        body TEXT,
        sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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

// Register
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
  }
  try {
    const hash = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (username, password_hash) VALUES ($1, $2)', [username, hash]);
    res.status(201).json({ message: 'Usuario registrado' });
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
    const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    res.status(500).json({ error: 'Error en login' });
  }
});

// Get emails
app.get('/api/emails', authenticateToken, async (req, res) => {
  try {
    const userEmail = `${req.user.username}@${DOMAIN}`;
    const result = await pool.query(
      'SELECT * FROM emails WHERE to_email = $1 ORDER BY sent_at DESC',
      [userEmail]
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener correos' });
  }
});

// Send email
app.post('/api/emails', authenticateToken, async (req, res) => {
  const { to, subject, body, from } = req.body;
  try {
    // Validate domain
    if (!to.endsWith(`@${DOMAIN}`) || !from.endsWith(`@${DOMAIN}`)) {
      return res.status(400).json({ error: 'Solo se permiten correos dentro del dominio @zephiryx.com' });
    }
    // Validate recipient exists
    const toUsername = to.split('@')[0];
    const userCheck = await pool.query('SELECT * FROM users WHERE username = $1', [toUsername]);
    if (userCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Usuario destinatario no existe' });
    }
    // Store email
    await pool.query(
      'INSERT INTO emails (from_email, to_email, subject, body) VALUES ($1, $2, $3, $4)',
      [from, to, subject, body]
    );
    res.status(201).json({ message: 'Correo enviado' });
  } catch (error) {
    res.status(500).json({ error: 'Error al enviar correo: ' + error.message });
  }
});

app.listen(port, () => {
  console.log(`Servidor corriendo en puerto ${port}`);
});
