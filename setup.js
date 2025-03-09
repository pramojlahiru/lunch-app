const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();

// Connect to database
const db = new sqlite3.Database('database.sqlite');

async function createAdmin() {
  try {
    const username = 'admin';
    const password = await bcrypt.hash('admin123', 10);
    
    db.run(
      'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
      [username, password, 'admin'],
      function(err) {
        if (err) {
          console.error('Error creating admin:', err.message);
        } else {
          console.log('Admin user created successfully');
        }
        db.close(); // Close the database connection
      }
    );
  } catch (err) {
    console.error('Error:', err);
    db.close();
  }
}

// First create the tables (if not existing)
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user'
  )`, () => {
    // After ensuring tables exist, create admin
    createAdmin();
  });
});