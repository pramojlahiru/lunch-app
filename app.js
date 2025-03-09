const express = require('express');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('database.sqlite');

const app = express();

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
  secret: process.env.SESSION_SECRET || 'super-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production' }
}));
app.use(passport.initialize());
app.use(passport.session());

// EJS setup
app.set('view engine', 'ejs');

// Passport configuration
passport.use(new LocalStrategy(
  async (username, password, done) => {
    try {
      const user = await new Promise((resolve, reject) => {
        db.get('SELECT * FROM users WHERE username = ?', [username], 
          (err, row) => err ? reject(err) : resolve(row));
      });
      
      if (!user) return done(null, false);
      if (await bcrypt.compare(password, user.password)) return done(null, user);
      return done(null, false);
    } catch (err) { return done(err); }
  }
));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
  db.get('SELECT * FROM users WHERE id = ?', [id], (err, user) => done(err, user));
});

// Routes
app.get('/', (req, res) => res.redirect('/login'));

app.get('/login', (req, res) => res.render('login', { 
  error: req.query.error 
}));

app.post('/login', passport.authenticate('local', {
  successRedirect: '/home',
  failureRedirect: '/login?error=1'
}));

app.get('/logout', (req, res) => {
  req.logout();
  res.redirect('/login');
});

app.get('/home', ensureAuthenticated, async (req, res) => {
  try {
    const preference = await new Promise((resolve, reject) => {
      db.get(
        'SELECT preference FROM lunch_preferences WHERE user_id = ? AND date = date("now", "+1 day")',
        [req.user.id],
        (err, row) => err ? reject(err) : resolve(row)
      );
    });
    res.render('home', { 
      user: req.user, 
      preference: preference?.preference,
      success: req.query.success 
    });
  } catch (err) {
    console.error(err);
    res.redirect('/login');
  }
});

app.post('/preference', ensureAuthenticated, async (req, res) => {
  try {
    await new Promise((resolve, reject) => {
      db.run(
        'INSERT OR REPLACE INTO lunch_preferences (user_id, preference, date) VALUES (?, ?, date("now", "+1 day"))',
        [req.user.id, req.body.preference],
        (err) => err ? reject(err) : resolve()
      );
    });
    res.redirect('/home?success=1');
  } catch (err) {
    console.error(err);
    res.redirect('/home');
  }
});

app.get('/admin', ensureAuthenticated, ensureAdmin, async (req, res) => {
  try {
    const preferences = await new Promise((resolve, reject) => {
      db.all(
        `SELECT date, preference, COUNT(*) as count 
         FROM lunch_preferences 
         GROUP BY date, preference 
         ORDER BY date DESC`,
        (err, rows) => err ? reject(err) : resolve(rows)
      );
    });
    res.render('admin', { preferences });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

// Middleware
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect('/login');
}

function ensureAdmin(req, res, next) {
  if (req.user?.role === 'admin') return next();
  res.status(403).send('Forbidden');
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));