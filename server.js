const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

const SECRET_KEY = process.env.SECRET_KEY || 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6';

// Initialize database tables
const initializeDatabase = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL
      );
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS profiles (
        user_id INTEGER PRIMARY KEY REFERENCES users(id),
        display_name VARCHAR(255),
        profile_picture VARCHAR(255)
      );
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS accounts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        email VARCHAR(255) UNIQUE NOT NULL
      );
    `);
    await pool.query(`
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
    console.log('Database tables initialized successfully');
  } catch (error) {
    console.error('Error initializing database:', error);
  }
};

// Run database initialization
initializeDatabase();

app.post('/api/register', async (req, res) => {
  const { username, password, display_name, profile_picture } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const userResult = await pool.query(
      'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id',
      [username, hashedPassword]
    );
    const userId = userResult.rows[0].id;
    await pool.query(
      'INSERT INTO profiles (user_id, display_name, profile_picture) VALUES ($1, $2, $3)',
      [userId, display_name || username, profile_picture || `https://via.placeholder.com/100?text=${username.charAt(0).toUpperCase()}&bg=3b82f6`]
    );
    await pool.query(
      'INSERT INTO accounts (user_id, email) VALUES ($1, $2)',
      [userId, `${username}@zephiryx.com`]
    );
    const token = jwt.sign({ userId, username }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    res.status(400).json({ error: 'Error al registrar usuario' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];
    if (user && await bcrypt.compare(password, user.password_hash)) {
      const token = jwt.sign({ userId: user.id, username }, SECRET_KEY, { expiresIn: '1h' });
      res.json({ token });
    } else {
      res.status(401).json({ error: 'Credenciales inválidas' });
    }
  } catch (error) {
    res.status(400).json({ error: 'Error al iniciar sesión' });
  }
});

app.get('/api/check_prefix', async (req, res) => {
  const { prefix } = req.query;
  try {
    const result = await pool.query('SELECT 1 FROM users WHERE username = $1', [prefix]);
    res.json({ available: result.rows.length === 0 });
  } catch (error) {
    res.status(400).json({ error: 'Error al verificar prefijo' });
  }
});

app.get('/api/profile', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const result = await pool.query('SELECT display_name, profile_picture FROM profiles WHERE user_id = $1', [decoded.userId]);
    res.json(result.rows[0]);
  } catch (error) {
    res.status(401).json({ error: 'Token inválido' });
  }
});

app.put('/api/profile', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  const { display_name, profile_picture, password } = req.body;
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const updates = [];
    const values = [decoded.userId];
    if (display_name) {
      updates.push(`display_name = $${values.length + 1}`);
      values.push(display_name);
    }
    if (profile_picture) {
      updates.push(`profile_picture = $${values.length + 1}`);
      values.push(profile_picture);
    }
    if (updates.length > 0) {
      await pool.query(`UPDATE profiles SET ${updates.join(', ')} WHERE user_id = $1`, values);
    }
    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      await pool.query('UPDATE users SET password_hash = $2 WHERE id = $1', [decoded.userId, hashedPassword]);
    }
    res.json({ message: 'Perfil actualizado' });
  } catch (error) {
    res.status(400).json({ error: 'Error al actualizar perfil' });
  }
});

app.get('/api/accounts', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const result = await pool.query('SELECT email FROM accounts WHERE user_id = $1', [decoded.userId]);
    res.json(result.rows);
  } catch (error) {
    res.status(401).json({ error: 'Token inválido' });
  }
});

app.post('/api/accounts', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  const { email, password } = req.body;
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const prefix = email.split('@')[0];
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (username, password_hash) VALUES ($1, $2)', [prefix, hashedPassword]);
    await pool.query('INSERT INTO accounts (user_id, email) VALUES ($1, $2)', [decoded.userId, email]);
    res.json({ message: 'Cuenta añadida' });
  } catch (error) {
    res.status(400).json({ error: 'Error al añadir cuenta' });
  }
});

app.post('/api/emails', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  const { from, to, subject, body, is_draft } = req.body;
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const spamWords = ['win', 'free', 'money', 'prize'];
    const isSpam = spamWords.some(word => body.toLowerCase().includes(word));
    await pool.query(
      'INSERT INTO emails (from_email, to_email, subject, body, is_spam, is_draft, is_sent) VALUES ($1, $2, $3, $4, $5, $6, $7)',
      [from, to, subject, body, isSpam, is_draft, !is_draft]
    );
    res.json({ message: is_draft ? 'Borrador guardado' : 'Correo enviado' });
  } catch (error) {
    res.status(400).json({ error: 'Error al enviar correo: ' + error.message });
  }
});

app.get('/api/emails/:type', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  const { type } = req.params;
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    let query;
    let values = [decoded.userId];
    if (type === 'inbox') {
      query = `
        SELECT e.* FROM emails e
        JOIN accounts a ON e.to_email = a.email
        WHERE a.user_id = $1 AND e.is_draft = FALSE AND e.is_spam = FALSE AND e.is_sent = TRUE
      `;
    } else if (type === 'sent') {
      query = `
        SELECT e.* FROM emails e
        JOIN accounts a ON e.from_email = a.email
        WHERE a.user_id = $1 AND e.is_draft = FALSE AND e.is_sent = TRUE
      `;
    } else if (type === 'spam') {
      query = `
        SELECT e.* FROM emails e
        JOIN accounts a ON e.to_email = a.email
        WHERE a.user_id = $1 AND e.is_spam = TRUE
      `;
    } else if (type === 'drafts') {
      query = `
        SELECT e.* FROM emails e
        JOIN accounts a ON e.from_email = a.email
        WHERE a.user_id = $1 AND e.is_draft = TRUE
      `;
    } else {
      return res.status(400).json({ error: 'Tipo de bandeja inválido' });
    }
    const result = await pool.query(query, values);
    res.json(result.rows);
  } catch (error) {
    res.status(400).json({ error: 'Error al cargar correos' });
  }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});
