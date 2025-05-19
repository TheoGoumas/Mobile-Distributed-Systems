# RestaurantApp
// backend.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mysql = require('mysql2/promise');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  console.error('❌ JWT_SECRET is not defined in environment variables');
  process.exit(1);
}

// Middleware setup
app.use(cors({
  origin: 'http://localhost:3000',
  credentials: true,
}));
app.use(bodyParser.json());
app.use(cookieParser());

// Database pool creation
const dbPool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'restaurantprogram',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// Test DB connection
dbPool.getConnection()
  .then(() => console.log('✅ Successfully connected to DB'))
  .catch((err) => {
    console.error('❌ Failed to connect to DB:', err);
    process.exit(1);
  });

// Middleware JWT authentication
function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Μη εξουσιοδοτημένος.' });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // Αποθηκεύουμε τα δεδομένα του χρήστη
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Μη έγκυρο token.' });
  }
}

// Register route
app.post('/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: 'Όλα τα πεδία πρέπει να συμπληρωθούν.' });
    }

    const [existing] = await dbPool.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (existing.length > 0) {
      return res.status(400).json({ message: 'Το email χρησιμοποιείται ήδη.' });
    }

    const hashedPwd = await bcrypt.hash(password, 10);
    const [insertResult] = await dbPool.execute(
      'INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
      [name, email, hashedPwd]
    );

    const userId = insertResult.insertId;
    const token = jwt.sign({ userId, name, email }, JWT_SECRET, { expiresIn: '1h' });

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'None',
    });

    res.status(201).json({ message: 'Εγγραφή ολοκληρώθηκε επιτυχώς!', token });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ message: 'Προέκυψε σφάλμα κατά την εγγραφή.', details: err.message });
  }
});

// Login route
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Όλα τα πεδία είναι υποχρεωτικά.' });
    }

    const [users] = await dbPool.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (users.length === 0) {
      return res.status(400).json({ message: 'Λάθος email ή κωδικός.' });
    }

    const user = users[0];
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ message: 'Λάθος email ή κωδικός.' });
    }

    const token = jwt.sign({ userId: user.id, name: user.name, email }, JWT_SECRET, { expiresIn: '1h' });
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'None',
    });

    res.status(200).json({ message: 'Σύνδεση επιτυχής!', token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Σφάλμα κατά τη σύνδεση.', details: err.message });
  }
});

// Restaurants search endpoint
app.get('/restaurants', async (req, res) => {
  try {
    const { name = '', location = '' } = req.query;

    let sqlQuery = 'SELECT * FROM restaurants WHERE 1=1';
    const params = [];

    if (name) {
      sqlQuery += ' AND name LIKE ?';
      params.push(`%${name}%`);
    }
    if (location) {
      sqlQuery += ' AND location LIKE ?';
      params.push(`%${location}%`);
    }

    const [restaurants] = await dbPool.execute(sqlQuery, params);
    res.status(200).json(restaurants);
  } catch (err) {
    console.error('Restaurants fetch error:', err);
    res.status(500).json({ error: 'Σφάλμα κατά την αναζήτηση εστιατορίων.' });
  }
});

// Get reservations (protected)
app.get('/reservations', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    const [reservations] = await dbPool.execute(
      'SELECT * FROM reservations WHERE user_id = ?',
      [userId]
    );

    res.status(200).json(reservations);
  } catch (err) {
    console.error('Reservations fetch error:', err);
    res.status(500).json({ error: 'Σφάλμα κατά την ανάκτηση των κρατήσεων.' });
  }
});

// Make reservation (protected)
app.post('/reservations', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { restaurant_id, date, time, people_count } = req.body;
    if (!restaurant_id || !date || !time || !people_count) {
      return res.status(400).json({ error: 'Όλα τα πεδία είναι υποχρεωτικά.' });
    }

    await dbPool.execute(
      'INSERT INTO reservations (user_id, restaurant_id, date, time, people_count) VALUES (?, ?, ?, ?, ?)',
      [userId, restaurant_id, date, time, people_count]
    );

    res.status(201).json({ message: 'Η κράτηση πραγματοποιήθηκε με επιτυχία!' });
  } catch (err) {
    console.error('Reservation error:', err);
    res.status(500).json({ error: 'Σφάλμα κατά την κράτηση.' });
  }
});

// Update reservation (protected)
app.put('/reservations/:id', authenticateToken, async (req, res) => {
  try {
    const reservationId = req.params.id;
    const userId = req.user.userId;
    const { restaurant_id, date, time, people_count } = req.body;

    // Έλεγχος αν η κράτηση ανήκει στον χρήστη
    const [rows] = await dbPool.execute(
      'SELECT * FROM reservations WHERE reservation_id = ? AND user_id = ?',
      [reservationId, userId]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Δεν βρέθηκε η κράτηση ή δεν έχεις δικαίωμα επεξεργασίας.' });
    }

    // Ενημέρωση κράτησης
    await dbPool.execute(
      `UPDATE reservations 
       SET restaurant_id = ?, date = ?, time = ?, people_count = ? 
       WHERE reservation_id = ?`,
      [restaurant_id, date, time, people_count, reservationId]
    );

    res.json({ message: 'Η κράτηση τροποποιήθηκε επιτυχώς.' });
  } catch (err) {
    console.error('Update reservation error:', err);
    res.status(500).json({ error: 'Σφάλμα κατά την τροποποίηση της κράτησης.' });
  }
});

// Delete reservation (protected)
app.delete('/reservations/:id', authenticateToken, async (req, res) => {
  try {
    const reservationId = req.params.id;
    const userId = req.user.userId;

    // Έλεγχος αν η κράτηση ανήκει στον χρήστη
    const [rows] = await dbPool.execute(
      'SELECT * FROM reservations WHERE reservation_id = ? AND user_id = ?',
      [reservationId, userId]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Δεν βρέθηκε η κράτηση ή δεν έχεις δικαίωμα διαγραφής.' });
    }

    // Διαγραφή κράτησης
    await dbPool.execute('DELETE FROM reservations WHERE reservation_id = ?', [reservationId]);

    res.json({ message: 'Η κράτηση διαγράφηκε επιτυχώς.' });
  } catch (err) {
    console.error('Delete reservation error:', err);
    res.status(500).json({ error: 'Σφάλμα κατά τη διαγραφή της κράτησης.' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server started on port ${PORT}`);
});
