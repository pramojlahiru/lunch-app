require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const bcrypt = require('bcrypt');
const db = require('./db');
const rateLimit = require('express-rate-limit');
const { Parser } = require('json2csv');

const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('resources'));
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

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many login attempts, please try again later.'
});
app.use('/login', limiter);

// Passport configuration
passport.use(new LocalStrategy(
    async (username, password, done) => {
      try {
        const user = await db.get('SELECT * FROM users WHERE username = $1', [username]);
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

        const existingUser = await db.get(
            'SELECT * FROM users WHERE google_id = $1 OR email = $2',
            [profile.id, email]
        );

        if (existingUser) {
          if (!existingUser.google_id && existingUser.email === email) {
            await db.run(
                'UPDATE users SET google_id = $1 WHERE id = $2',
                [profile.id, existingUser.id]
            );
          }
          return done(null, existingUser);
        }

        const { lastID } = await db.run(
            'INSERT INTO users (google_id, email, display_name, role, username) VALUES ($1, $2, $3, $4, $5)',
            [profile.id, email, profile.displayName, 'user', username]
        );

        const newUser = await db.get(
            'SELECT * FROM users WHERE id = $1',
            [lastID]
        );

        done(null, newUser);
      } catch (err) {
        done(err);
      }
    }));

passport.serializeUser((user, done) => {
  try {
    if (!user?.id) throw new Error('Invalid user object for serialization');
    done(null, user.id);
  } catch (err) {
    done(err);
  }
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await db.get(
        'SELECT id, username, email, display_name, role, google_id FROM users WHERE id = $1',
        [id]
    );

    if (!user) return done(new Error('User not found in database'));
    done(null, {
      id: user.id,
      username: user.username,
      email: user.email,
      displayName: user.display_name,
      role: user.role,
      googleId: user.google_id
    });
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
    if (err) return next(err);
    res.redirect('/login');
  });
});

app.get('/home', ensureAuthenticated, async (req, res) => {
  try {
    const preferences = await db.all(
      'SELECT date, preference FROM lunch_preferences WHERE user_id = $1',
      [req.user.id]
    );

    const preferencesMap = preferences.reduce((acc, p) => {
      acc[p.date] = p.preference;
      return acc;
    }, {});

    res.render('home', {
      user: req.user,
      preferences: preferencesMap,
      success: req.query.success,
      isEdit: req.query.edit
    });
  } catch (err) {
    console.error(err);
    res.redirect('/login');
  }
});

app.post('/preference', ensureAuthenticated, async (req, res) => {
  try {
    const { preference, date } = req.body;
    if (!date) return res.status(400).json({ error: 'Date selection is required' });

    const isEdit = await checkExistingPreference(req.user.id, date);
    const selectedDate = new Date(date);
    const now = new Date();

    // Date validation logic
    const today = new Date(now);
    today.setHours(0, 0, 0, 0);

    const skipWeekends = (date) => {
      const day = date.getDay();
      if (day === 0) date.setDate(date.getDate() + 1);
      else if (day === 6) date.setDate(date.getDate() + 2);
      return date;
    };

    let minDate = new Date(today);
    if (now.getHours() >= 10) minDate.setDate(minDate.getDate() + 1);
    minDate = skipWeekends(minDate);

    let maxDate = new Date(minDate);
    maxDate.setDate(maxDate.getDate() + 2);
    maxDate = skipWeekends(maxDate);

    const selectedDateUpper = new Date(selectedDate);
    selectedDateUpper.setHours(0, 0, 0, 0);

    if (selectedDate < minDate || selectedDateUpper > maxDate) {
      return res.status(400).json({ error: 'Invalid date selection' });
    }

    if ([0, 6].includes(selectedDate.getDay())) {
      return res.status(400).json({ error: 'Weekends are not allowed' });
    }

    await db.run(
        'INSERT INTO lunch_preferences (user_id, preference, date) VALUES ($1, $2, $3) ON CONFLICT (user_id, date) DO UPDATE SET preference = EXCLUDED.preference',
        [req.user.id, preference, date]
    );

    res.json({ message: isEdit ? 'Preference updated successfully!' : 'Preference saved successfully!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server Error' });
  }
});

app.get('/admin', ensureAuthenticated, ensureAdmin, async (req, res) => {
  try {
    const preferences = await db.all(
        `SELECT lp.date, lp.preference, 
        COUNT(*) as count,
        string_agg(u.display_name, ',') as display_names
         FROM lunch_preferences lp
         JOIN users u ON u.id = lp.user_id
         GROUP BY lp.date, lp.preference 
         ORDER BY lp.date DESC`
    );

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

    res.render('admin', {
      user: req.user,
      groupedData: Object.entries(groupedData),
      currentPath: req.path
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

app.get('/export-preferences', ensureAuthenticated, ensureAdmin, async (req, res) => {
  try {
    const preferences = await db.all(
        `SELECT lp.date, lp.preference, u.display_name 
               FROM lunch_preferences lp
               JOIN users u ON u.id = lp.user_id`
    );

    const fields = ['date', 'preference', 'display_name'];
    const parser = new Parser({ fields });
    const csv = parser.parse(preferences);

    res.header('Content-Type', 'text/csv');
    res.attachment('preferences.csv');
    res.send(csv);
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

// User Management Routes
app.get('/admin/users', ensureAuthenticated, ensureAdmin, async (req, res) => {
  try {
    const users = await db.all('SELECT id, display_name, username, email, role, google_id FROM users');

    res.render('admin-users', {
      user: req.user, //Logged-in user
      currentUser: req.user,
      users: users,
      currentPath: req.path
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

app.post('/admin/users/:id/role', ensureAuthenticated, ensureAdmin, async (req, res) => {
  try {
    if (req.params.id === req.user.id) {
      throw new AppError('Cannot modify your own role', 403);
    }
    const { role } = req.body;
    await db.run(
        'UPDATE users SET role = $1 WHERE id = $2',
        [role, req.params.id]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update role' });
  }
});

app.post('/admin/users/:id/delete', ensureAuthenticated, ensureAdmin, async (req, res) => {
  try {
    await db.run('DELETE FROM users WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// Enhanced Preferences Management
app.get('/admin/preferences', ensureAuthenticated, ensureAdmin, async (req, res) => {
  try {
    const preferences = await db.all(`
                SELECT lp.id, lp.date, lp.preference, 
                    u.id as user_id, u.display_name, u.email
                FROM lunch_preferences lp
                JOIN users u ON lp.user_id = u.id
                ORDER BY lp.date DESC
            `);

    res.render('admin-preferences', {
      user: req.user,
      preferences: preferences,
      currentPath: req.path
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

app.post('/admin/preferences/:id/delete', ensureAuthenticated, ensureAdmin, async (req, res) => {
  try {
    await db.run('DELETE FROM lunch_preferences WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete preference' });
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

async function checkExistingPreference(userId, date) {
  const existing = await db.get(
      'SELECT 1 FROM lunch_preferences WHERE user_id = $1 AND date = $2',
      [userId, date]
  );
  return !!existing;
}

// Error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
