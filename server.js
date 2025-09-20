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

// Initialize database tables and columns
const initializeDatabase = async () => {
  try {
    // Create tables if they don't exist
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL
      );
    `);
    console.log('Table users initialized');

    await pool.query(`
      CREATE TABLE IF NOT EXISTS profiles (
        user_id INTEGER PRIMARY KEY REFERENCES users(id),
        display_name VARCHAR(255),
        profile_picture VARCHAR(255)
      );
    `);
    console.log('Table profiles initialized');

    await pool.query(`
      CREATE TABLE IF NOT EXISTS accounts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        email VARCHAR(255) UNIQUE NOT NULL
      );
    `);
    console.log('Table accounts initialized');

    await pool.query(`
      CREATE TABLE IF NOT EXISTS emails (
        id SERIAL PRIMARY KEY,
        from_email VARCHAR(255) NOT NULL,
        to_email VARCHAR(255) NOT NULL,
        subject VARCHAR(255),
        body TEXT,
        sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log('Table emails initialized');

    // Check and add missing columns to emails table
    const columnsResult = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'emails';
    `);
    const existingColumns = columnsResult.rows.map(row => row.column_name);

    if (!existingColumns.includes('is_spam')) {
      await pool.query('ALTER TABLE emails ADD COLUMN is_spam BOOLEAN DEFAULT FALSE;');
      console.log('Added column is_spam to emails table');
    } else {
      console.log('Column is_spam already exists in emails table');
    }

    if (!existingColumns.includes('is_draft')) {
      await pool.query('ALTER TABLE emails ADD COLUMN is_draft BOOLEAN DEFAULT FALSE;');
      console.log('Added column is_draft to emails table');
    } else {
      console.log('Column is_draft already exists in emails table');
    }

    if (!existingColumns.includes('is_sent')) {
      await pool.query('ALTER TABLE emails ADD COLUMN is_sent BOOLEAN DEFAULT FALSE;');
      console.log('Added column is_sent to emails table');
    } else {
      console.log('Column is_sent already exists in emails table');
    }

    console.log('Database tables and columns initialized successfully');
  } catch (error) {
    console.error('Error initializing database:', error.message, error.stack);
    throw error; // Re-throw to prevent server from starting with an invalid database
  }
};

// Run database initialization and ensure server only starts if successful
(async () => {
  try {
    await initializeDatabase();
    const PORT = process.env.PORT || 8080;
    app.listen(PORT, () => {
      console.log(`Servidor corriendo en puerto ${PORT}`);
    });
  } catch (error) {
    console.error('Failed to start server due to database initialization error:', error.message);
    process.exit(1);
  }
})();

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
    console.error('Error in /api/register:', error.message, error.stack);
    res.status(400).json({ error: 'Error al registrar usuario: ' + error.message });
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
    console.error('Error in /api/login:', error.message, error.stack);
    res.status(400).json({ error: 'Error al iniciar sesión: ' + error.message });
  }
});

app.get('/api/check_prefix', async (req, res) => {
  const { prefix } = req.query;
  try {
    const result = await pool.query('SELECT 1 FROM users WHERE username = $1', [prefix]);
    res.json({ available: result.rows.length === 0 });
  } catch (error) {
    console.error('Error in /api/check_prefix:', error.message, error.stack);
    res.status(400).json({ error: 'Error al verificar prefijo: ' + error.message });
  }
});

app.get('/api/profile', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const result = await pool.query('SELECT display_name, profile_picture FROM profiles WHERE user_id = $1', [decoded.userId]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Perfil no encontrado' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error in /api/profile:', error.message, error.stack);
    res.status(401).json({ error: 'Token inválido: ' + error.message });
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
    console.error('Error in /api/profile PUT:', error.message, error.stack);
    res.status(400).json({ error: 'Error al actualizar perfil: ' + error.message });
  }
});

app.get('/api/accounts', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const result = await pool.query('SELECT email FROM accounts WHERE user_id = $1', [decoded.userId]);
    res.json(result.rows);
  } catch (error) {
    console.error('Error in /api/accounts:', error.message, error.stack);
    res.status(401).json({ error: 'Token inválido: ' + error.message });
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
    console.error('Error in /api/accounts POST:', error.message, error.stack);
    res.status(400).json({ error: 'Error al añadir cuenta: ' + error.message });
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
    console.error('Error in /api/emails POST:', error.message, error.stack);
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
    console.error('Error in /api/emails/:type:', error.message, error.stack);
    res.status(400).json({ error: 'Error al cargar correos: ' + error.message });
  }
});
