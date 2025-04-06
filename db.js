const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT || 5432,
});

// Test the connection
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('Error connecting to PostgreSQL:', err);
  } else {
    console.log('Successfully connected to PostgreSQL');
  }
});

module.exports = {
  query: (text, params) => pool.query(text, params),
  get: async (text, params) => {
    const result = await pool.query(text, params);
    return result.rows[0];
  },
  all: async (text, params) => {
    const result = await pool.query(text, params);
    return result.rows;
  },
  run: async (text, params) => {
    await pool.query(text, params);
  }
}; 