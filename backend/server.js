const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Configuration
const SECRET_KEY = process.env.SECRET_KEY || 'c0dc0d0964e2fc14a28771e236c5df75fbd73bd286b1f7443a017eed77538968';
const INITIAL_BALANCE = 100;
const PORT = process.env.PORT || 3000;

// Initialize PostgreSQL connection pool (Neon)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// Test database connection
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('Database connection error:', err);
  } else {
    console.log('Connected to PostgreSQL database');
    initializeDatabase();
  }
});

// Create tables
async function initializeDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        balance REAL DEFAULT ${INITIAL_BALANCE},
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        banned INTEGER DEFAULT 0,
        is_admin INTEGER DEFAULT 0
      )
    `);
    console.log('Users table ready');

    await pool.query(`
      CREATE TABLE IF NOT EXISTS feedback (
        id SERIAL PRIMARY KEY,
        username TEXT NOT NULL,
        message TEXT NOT NULL,
        submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('Feedback table ready');

    // Create default users
    await createOrUpdateUser('admin', 'admin123', true);
    await createOrUpdateUser('testuser', 'password123', false);
  } catch (error) {
    console.error('Error initializing database:', error);
  }
}

// Utility: Create or update user
async function createOrUpdateUser(username, password, isAdmin = false) {
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const checkUser = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    
    if (checkUser.rows.length > 0) {
      await pool.query(
        'UPDATE users SET password = $1, is_admin = $2 WHERE username = $3',
        [hashedPassword, isAdmin ? 1 : 0, username]
      );
      console.log(`User '${username}' updated.`);
    } else {
      await pool.query(
        'INSERT INTO users (username, password, is_admin) VALUES ($1, $2, $3)',
        [username, hashedPassword, isAdmin ? 1 : 0]
      );
      console.log(`User '${username}' created.`);
    }
  } catch (error) {
    console.error(`Error creating/updating user '${username}':`, error);
  }
}

// Middleware: Authenticate token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Leaderboard
app.get('/leaderboard', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT username, balance, banned FROM users WHERE is_admin = 0 ORDER BY balance DESC LIMIT 100'
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Leaderboard error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Register
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (username, password) VALUES ($1, $2)',
      [username, hashedPassword]
    );
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    if (error.code === '23505') { // Unique constraint violation
      return res.status(400).json({ error: 'Username already exists' });
    }
    console.error('Register error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login
app.post('/login', async (req, res) => {
  try {
    const { username, password, adminLogin } = req.body;

    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    if (user.banned) {
      return res.status(403).json({ error: 'Account is banned' });
    }
    
    if (!adminLogin && user.is_admin) {
      return res.status(403).json({ error: 'Admins must log in from the admin portal' });
    }
    
    if (adminLogin && !user.is_admin) {
      return res.status(403).json({ error: 'Only admins can log in here' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username, is_admin: user.is_admin },
      SECRET_KEY,
      { expiresIn: '1h' }
    );

    res.json({
      token,
      balance: user.balance,
      is_admin: user.is_admin
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Balance routes
app.get('/balance', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT balance FROM users WHERE id = $1', [req.user.id]);
    res.json({ balance: result.rows[0].balance });
  } catch (error) {
    console.error('Balance error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/update-balance', authenticateToken, async (req, res) => {
  try {
    const { amount } = req.body;
    await pool.query('UPDATE users SET balance = balance + $1 WHERE id = $2', [amount, req.user.id]);

    const result = await pool.query('SELECT balance FROM users WHERE id = $1', [req.user.id]);
    res.json({ balance: result.rows[0].balance });
  } catch (error) {
    console.error('Update balance error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Feedback
app.post('/feedback', authenticateToken, async (req, res) => {
  try {
    const { message } = req.body;
    if (!message) {
      return res.status(400).json({ error: 'Message is required' });
    }

    await pool.query(
      'INSERT INTO feedback (username, message) VALUES ($1, $2)',
      [req.user.username, message]
    );
    res.json({ message: 'Feedback submitted successfully' });
  } catch (error) {
    console.error('Feedback error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/admin/feedback', authenticateToken, async (req, res) => {
  try {
    if (!req.user.is_admin) {
      return res.status(403).json({ error: 'Admins only' });
    }

    const result = await pool.query('SELECT * FROM feedback ORDER BY submitted_at DESC');
    res.json(result.rows);
  } catch (error) {
    console.error('Admin feedback error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin: Reset & Ban
app.post('/admin/reset-balance', authenticateToken, async (req, res) => {
  try {
    if (!req.user.is_admin) {
      return res.status(403).json({ error: 'Admins only' });
    }
    
    const { username } = req.body;
    await pool.query('UPDATE users SET balance = 0 WHERE username = $1', [username]);
    res.json({ message: 'Balance reset to zero' });
  } catch (error) {
    console.error('Reset balance error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/admin/set-ban', authenticateToken, async (req, res) => {
  try {
    if (!req.user.is_admin) {
      return res.status(403).json({ error: 'Admins only' });
    }
    
    const { username, banned } = req.body;
    await pool.query('UPDATE users SET banned = $1 WHERE username = $2', [banned ? 1 : 0, username]);
    res.json({ message: banned ? 'User banned' : 'User unbanned' });
  } catch (error) {
    console.error('Set ban error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/admin/summary', authenticateToken, async (req, res) => {
  try {
    if (!req.user.is_admin) {
      return res.status(403).json({ error: 'Admins only' });
    }

    const result = await pool.query('SELECT username, balance FROM users WHERE is_admin = 0');
    const users = result.rows;
    const totalUsers = users.length;
    const totalEarnings = users.reduce((acc, user) => acc + user.balance, 0);

    res.json({
      totalUsers,
      totalEarnings,
      users
    });
  } catch (error) {
    console.error('Admin summary error:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Health check endpoint for Render
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK' });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});

// Graceful shutdown
process.on('SIGINT', async () => {
  await pool.end();
  process.exit();
});

process.on('SIGTERM', async () => {
  await pool.end();
  process.exit();
});