const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Configuration
const SECRET_KEY = 'your-secret-key-here';
const INITIAL_BALANCE = 100;
const PORT = 3000;
const DB_FILE = './casino_editable.db';

// Initialize SQLite Database
const db = new sqlite3.Database(DB_FILE, (err) => {
  if (err) {
    console.error('Database connection error:', err);
  } else {
    console.log('Connected to SQLite database');
    initializeDatabase();
    createOrUpdateUser('admin', 'admin123', true);      // Admin account
    createOrUpdateUser('testuser', 'password123', false); // Test user
  }
});

// Create tables
function initializeDatabase() {
  db.serialize(() => {
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        balance REAL DEFAULT ${INITIAL_BALANCE},
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        banned INTEGER DEFAULT 0,
        is_admin INTEGER DEFAULT 0
      )
    `, (err) => {
      if (err) console.error('Error creating users table:', err);
      else console.log('Users table ready');
    });

    db.run(`
      CREATE TABLE IF NOT EXISTS feedback (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        message TEXT NOT NULL,
        submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `, (err) => {
      if (err) console.error('Error creating feedback table:', err);
      else console.log('Feedback table ready');
    });
  });
}

// Utility: Create or update user
async function createOrUpdateUser(username, password, isAdmin = false) {
  const hashedPassword = await bcrypt.hash(password, 10);
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
    if (err) {
      console.error('Error checking user:', err);
    } else if (row) {
      db.run(
        'UPDATE users SET password = ?, is_admin = ? WHERE username = ?',
        [hashedPassword, isAdmin ? 1 : 0, username],
        (err) => {
          if (err) console.error(`Failed to update user '${username}':`, err);
          else console.log(`User '${username}' updated.`);
        }
      );
    } else {
      db.run(
        'INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
        [username, hashedPassword, isAdmin ? 1 : 0],
        (err) => {
          if (err) console.error(`Failed to insert user '${username}':`, err);
          else console.log(`User '${username}' created.`);
        }
      );
    }
  });
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
app.get('/leaderboard', (req, res) => {
  db.all(
    'SELECT username, balance, banned FROM users WHERE is_admin = 0 ORDER BY balance DESC LIMIT 100',
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Internal server error' });
      res.json(rows);
    }
  );
});

// Register
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password are required' });

    const hashedPassword = await bcrypt.hash(password, 10);
    db.run(
      'INSERT INTO users (username, password) VALUES (?, ?)',
      [username, hashedPassword],
      function (err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint failed')) {
            return res.status(400).json({ error: 'Username already exists' });
          }
          throw err;
        }
        res.status(201).json({ message: 'User registered successfully' });
      }
    );
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login
app.post('/login', (req, res) => {
  const { username, password, adminLogin } = req.body;

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err) return res.status(500).json({ error: 'Internal server error' });
    if (!user) return res.status(401).json({ error: 'Invalid username or password' });

    if (user.banned) return res.status(403).json({ error: 'Account is banned' });
    if (!adminLogin && user.is_admin) return res.status(403).json({ error: 'Admins must log in from the admin portal' });
    if (adminLogin && !user.is_admin) return res.status(403).json({ error: 'Only admins can log in here' });

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) return res.status(401).json({ error: 'Invalid username or password' });

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
  });
});

// Balance routes
app.get('/balance', authenticateToken, (req, res) => {
  db.get('SELECT balance FROM users WHERE id = ?', [req.user.id], (err, row) => {
    if (err) return res.status(500).json({ error: 'Internal server error' });
    res.json({ balance: row.balance });
  });
});

app.post('/update-balance', authenticateToken, (req, res) => {
  const { amount } = req.body;
  db.run('UPDATE users SET balance = balance + ? WHERE id = ?', [amount, req.user.id], function (err) {
    if (err) return res.status(500).json({ error: 'Internal server error' });

    db.get('SELECT balance FROM users WHERE id = ?', [req.user.id], (err, row) => {
      if (err) return res.status(500).json({ error: 'Internal server error' });
      res.json({ balance: row.balance });
    });
  });
});

// Feedback
app.post('/feedback', authenticateToken, (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: 'Message is required' });

  db.run('INSERT INTO feedback (username, message) VALUES (?, ?)', [req.user.username, message], function (err) {
    if (err) return res.status(500).json({ error: 'Internal server error' });
    res.json({ message: 'Feedback submitted successfully' });
  });
});

app.get('/admin/feedback', authenticateToken, (req, res) => {
  if (!req.user.is_admin) return res.status(403).json({ error: 'Admins only' });

  db.all('SELECT * FROM feedback ORDER BY submitted_at DESC', (err, rows) => {
    if (err) return res.status(500).json({ error: 'Internal server error' });
    res.json(rows);
  });
});

// Admin: Reset & Ban
app.post('/admin/reset-balance', authenticateToken, (req, res) => {
  if (!req.user.is_admin) return res.status(403).json({ error: 'Admins only' });
  const { username } = req.body;
  db.run('UPDATE users SET balance = 0 WHERE username = ?', [username], function (err) {
    if (err) return res.status(500).json({ error: 'Internal server error' });
    res.json({ message: 'Balance reset to zero' });
  });
});

app.post('/admin/set-ban', authenticateToken, (req, res) => {
  if (!req.user.is_admin) return res.status(403).json({ error: 'Admins only' });
  const { username, banned } = req.body;
  db.run('UPDATE users SET banned = ? WHERE username = ?', [banned ? 1 : 0, username], function (err) {
    if (err) return res.status(500).json({ error: 'Internal server error' });
    res.json({ message: banned ? 'User banned' : 'User unbanned' });
  });
});

app.get('/admin/summary', authenticateToken, (req, res) => {
  if (!req.user.is_admin) return res.status(403).json({ error: 'Admins only' });

  db.all('SELECT username, balance FROM users WHERE is_admin = 0', (err, users) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch users' });

    const totalUsers = users.length;
    const totalEarnings = users.reduce((acc, user) => acc + user.balance, 0);

    res.json({
      totalUsers,
      totalEarnings,
      users
    });
  });
});


// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

// Graceful shutdown
process.on('SIGINT', () => {
  db.close();
  process.exit();
});
