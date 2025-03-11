require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
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

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL,
  scope: ['profile', 'email']
}, 
async (accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.emails[0].value;
    const username = email.split('@')[0];
    
    // Check existing user (both local and Google)
    const existingUser = await new Promise((resolve, reject) => {
      db.get(
        'SELECT * FROM users WHERE google_id = ? OR email = ?',
        [profile.id, email],
        (err, row) => {
          if (err) reject(err);
          resolve(row);
        }
      );
    });

    if (existingUser) {
      // Merge accounts if needed
      if (!existingUser.google_id && existingUser.email === email) {
        await new Promise((resolve, reject) => {
          db.run(
            'UPDATE users SET google_id = ? WHERE id = ?',
            [profile.id, existingUser.id],
            (err) => err ? reject(err) : resolve()
          );
        });
      }
      return done(null, existingUser);
    }

    // Create new Google user
    const { lastID } = await new Promise((resolve, reject) => {
      db.run(
        'INSERT INTO users (google_id, email, display_name, role, username) VALUES (?, ?, ?, ?, ?)',
        [profile.id, email, profile.displayName, 'user', username],
        function(err) {
          if (err) reject(err);
          resolve({ lastID: this.lastID });
        }
      );
    });

    // Get full user data
    const newUser = await new Promise((resolve, reject) => {
      db.get(
        'SELECT * FROM users WHERE id = ?',
        [lastID],
        (err, row) => {
          if (err) reject(err);
          resolve(row);
        }
      );
    });

    done(null, newUser);
  } catch (err) {
    done(err);
  }
}));

passport.serializeUser((user, done) => {
  try {
    // Verify user object structure
    if (!user?.id) {
      throw new Error('Invalid user object for serialization');
    }
    done(null, user.id);
  } catch (err) {
    done(err);
  }
});
// passport.deserializeUser((id, done) => {
//   db.get('SELECT * FROM users WHERE id = ?', [id], (err, user) => done(err, user));
// });
// Deserialization (enhanced error handling)
passport.deserializeUser(async (id, done) => {
  try {
    const user = await new Promise((resolve, reject) => {
      db.get(
        'SELECT id, username, email, display_name, role, google_id FROM users WHERE id = ?',
        [id],
        (err, row) => {
          if (err) return reject(err);
          resolve(row);
        }
      );
    });

    if (!user) {
      return done(new Error('User not found in database'));
    }

    // Ensure proper user object structure
    const userData = {
      id: user.id,
      username: user.username,
      email: user.email,
      displayName: user.display_name,
      role: user.role,
      googleId: user.google_id
    };

    done(null, userData);
  } catch (err) {
    done(err);
  }
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

app.get('/logout', (req, res, next) => {
  req.logout((err) => {
    if (err) { return next(err); }
    res.redirect('/login');
  });
});

app.get('/home', ensureAuthenticated, async (req, res) => {
  try {
    const preferences = await new Promise((resolve, reject) => {
      db.all(
        'SELECT date, preference FROM lunch_preferences WHERE user_id = ?',
        [req.user.id],
        (err, rows) => err ? reject(err) : resolve(rows)
      );
    });

    const preferencesMap = preferences.reduce((acc, p) => {
      acc[p.date] = p.preference;
      return acc;
    }, {});

    res.render('home', { 
      user: req.user,
      preferences: preferencesMap,
      success: req.query.success 
    });
  } catch (err) {
    console.error(err);
    res.redirect('/login');
  }
});

app.post('/preference', ensureAuthenticated, async (req, res) => {
  try {
    const { preference, date } = req.body;
    
    // Server-side validation
    const selectedDate = new Date(date);
    const now = new Date();
    const istOffset = 330 * 60 * 1000; // IST offset in milliseconds
    const istTime = new Date(now.getTime() + istOffset);
    
    // Date constraints
    const todayIST = new Date(istTime);
    todayIST.setHours(0,0,0,0);
    
    let minDate = new Date(todayIST);
    if (istTime.getHours() >= 10) { // After 10 AM IST
      minDate.setDate(minDate.getDate() + 1);
    }
    
    const maxDate = new Date(minDate);
    maxDate.setDate(maxDate.getDate() + 2);
    
    // Validate date range
    if (selectedDate < minDate || selectedDate > maxDate) {
      return res.status(400).send('Invalid date selection');
    }
    
    // Validate weekends
    const day = selectedDate.getDay();
    if (day === 0 || day === 6) {
      return res.status(400).send('Weekends are not allowed');
    }

    await new Promise((resolve, reject) => {
      db.run(
        'INSERT OR REPLACE INTO lunch_preferences (user_id, preference, date) VALUES (?, ?, ?)',
        [req.user.id, preference, date],
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
        )});

    // Group by date
    const groupedData = preferences.reduce((acc, item) => {
      if (!acc[item.date]) {
        acc[item.date] = {
          total: 0,
          details: []
        };
      }
      acc[item.date].total += item.count;
      acc[item.date].details.push(item);
      return acc;
    }, {});

    res.render('admin', { groupedData: Object.entries(groupedData) });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

// Google Login Route
app.get('/auth/google',
  passport.authenticate('google', {
    prompt: 'select_account'
  })
);

// Google Callback Route
app.get('/auth/google/callback', 
  passport.authenticate('google', {
    failureRedirect: '/login',
    successRedirect: '/home'
  })
);

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