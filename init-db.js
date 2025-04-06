const db = require('./db');

async function initializeDatabase() {
  try {
    // Create users table
    await db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        email VARCHAR(255),
        display_name VARCHAR(255),
        role VARCHAR(50) DEFAULT 'user',
        google_id VARCHAR(255)
      )
    `);

    // Create lunch_preferences table
    await db.run(`
      CREATE TABLE IF NOT EXISTS lunch_preferences (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        preference VARCHAR(10) CHECK(preference IN ('veg', 'chicken', 'fish')),
        date DATE DEFAULT CURRENT_DATE,
        UNIQUE(user_id, date)
      )
    `);

    console.log('PostgreSQL tables created successfully');
  } catch (err) {
    console.error('Error initializing database:', err);
  }
}

initializeDatabase();