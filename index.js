require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const { Client, Intents } = require('discord.js');
const { REST } = require('@discordjs/rest');
const { Routes } = require('discord-api-types/v9');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const PDFDocument = require('pdfkit');
const path = require('path');
const multer = require('multer');
const bcrypt = require('bcrypt');

// Configuration
const config = {
  token: process.env.BOT_TOKEN,
  clientId: process.env.CLIENT_ID,
  guildId: process.env.GUILD_ID,
  dashboardUrl: process.env.DASHBOARD_URL || 'https://ia-dashboard.example.com',
  dashboardAdmin: process.env.DASHBOARD_USER,
  dashboardAdminPass: process.env.DASHBOARD_PASS,
};

// Multer Setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, 'public', 'uploads');
    fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => cb(null, `${Date.now()}_${file.originalname}`),
});
const upload = multer({ storage });

// Discord Bot Setup
const client = new Client({ intents: [Intents.FLAGS.GUILDS] });
(async () => {
  const commands = [{ name: 'ia-dashboard', description: 'Get IA Dashboard link' }];
  await new REST({ version: '9' }).setToken(config.token)
    .put(Routes.applicationGuildCommands(config.clientId, config.guildId), { body: commands });
})();
client.on('interactionCreate', async interaction => {
  if (!interaction.isCommand() || interaction.commandName !== 'ia-dashboard') return;
  interaction.reply({ content: `🔗 Dashboard: ${config.dashboardUrl}`, ephemeral: true });
});
client.login(config.token);

// SQLite DB Setup
const db = new sqlite3.Database('./ia.db', err => {
  if (err) console.error('DB Open Error:', err);
});
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS cases (id INTEGER PRIMARY KEY, caseNum TEXT UNIQUE, complainant TEXT, officer TEXT, incidentDate TEXT, summary TEXT, severity TEXT, status TEXT DEFAULT 'Open', assigned TEXT, createdBy TEXT, createdAt TEXT)`);
  db.run('CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY, caseNum TEXT, author TEXT, content TEXT, createdAt TEXT)');
  db.run('CREATE TABLE IF NOT EXISTS attachments (id INTEGER PRIMARY KEY, caseNum TEXT, url TEXT)');
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    passwordHash TEXT,
    role TEXT DEFAULT 'user'
  )`);

  // Seed admin user
  db.get('SELECT COUNT(*) AS cnt FROM users WHERE username = ?', [config.dashboardAdmin], (err, row) => {
    if (!err && row.cnt === 0) {
      const hash = bcrypt.hashSync(config.dashboardAdminPass, 10);
      db.run('INSERT INTO users (username, passwordHash, role) VALUES (?, ?, ?)', [config.dashboardAdmin, hash, 'admin']);
    }
  });

  // Force seed bcsointernal
  const forceUser = 'bcsointernal';
  const forcePass = 'casesia2236';
  const forceHash = bcrypt.hashSync(forcePass, 10);
  db.get('SELECT COUNT(*) AS cnt FROM users WHERE username = ?', [forceUser], (err2, row2) => {
    if (!err2 && row2.cnt === 0) {
      db.run('INSERT INTO users (username, passwordHash, role) VALUES (?, ?, ?)', [forceUser, forceHash, 'admin']);
    } else {
      db.run('UPDATE users SET role = ?, passwordHash = ? WHERE username = ?', ['admin', forceHash, forceUser]);
    }
  });
});

// Express Setup
const app = express();
const PORT = process.env.PORT || 3000;
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

const expressLayouts = require('express-ejs-layouts');
app.use(expressLayouts);

app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({ secret: 'ia_secret', resave: false, saveUninitialized: false }));
app.use((req, res, next) => { res.locals.session = req.session; next(); });
app.use('/static', express.static(path.join(__dirname, 'public')));

// Auth Middleware
function ensureAuth(req, res, next) {
  if (req.session.user) return next();
  res.redirect('/login');
}
function ensureAdmin(req, res, next) {
  if (req.session.role === 'admin') return next();
  res.status(403).send('Forbidden');
}

// Login & Session
app.get('/login', (req, res) => res.render('login', { title: 'Login', error: null }));
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err || !user || !bcrypt.compareSync(password, user.passwordHash)) {
      return res.render('login', { title: 'Login', error: 'Invalid credentials' });
    }
    req.session.user = user.username;
    req.session.role = user.role;
    res.redirect('/');
  });
});
app.get('/logout', (req, res) => req.session.destroy(() => res.redirect('/login')));

// Admin Users
app.get('/admin/users', ensureAuth, ensureAdmin, (req, res) => {
  db.all('SELECT id, username, role FROM users', [], (err, users) => {
    if (err) return res.status(500).send('DB error');
    res.render('users', { title: 'Manage Users', users });
  });
});
app.post('/admin/users/add', ensureAuth, ensureAdmin, (req, res) => {
  const { username, password, role } = req.body;
  const hash = bcrypt.hashSync(password, 10);
  db.run('INSERT INTO users (username, passwordHash, role) VALUES (?, ?, ?)', [username, hash, role || 'user'], err => {
    if (err) return res.status(500).send('Insert error');
    res.redirect('/admin/users');
  });
});
app.post('/admin/users/:id/delete', ensureAuth, ensureAdmin, (req, res) => {
  db.run('DELETE FROM users WHERE id = ?', [req.params.id], err => {
    if (err) return res.status(500).send('Delete error');
    res.redirect('/admin/users');
  });
});

// Dashboard Home
app.get('/', ensureAuth, (req, res) => {
  const { q } = req.query;
  let sql = 'SELECT * FROM cases';
  const params = [];
  if (q) {
    sql += ' WHERE caseNum LIKE ? OR officer LIKE ?';
    params.push(`%${q}%`, `%${q}%`);
  }
  sql += ' ORDER BY createdAt DESC';
  db.all(sql, params, (err, cases) => {
    if (err) return res.status(500).send('DB error');
    res.render('index', { title: 'Dashboard', cases });
  });
});

// New Case
app.get('/case/new', ensureAuth, (req, res) => res.render('new', { title: 'New Case' }));
app.post('/case/new', ensureAuth, upload.array('evidence', 10), (req, res) => {
  const { complainant, officer, incidentDate, summary, severity, assigned } = req.body;
  const files = req.files || [];
  const stamp = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  db.get('SELECT COUNT(*) AS cnt FROM cases WHERE createdAt LIKE ?', [`${stamp}%`], (e, row) => {
    const caseNum = `IA-${stamp}-${String(row.cnt + 1).padStart(3, '0')}`;
    const now = new Date().toISOString();
    db.run('INSERT INTO cases(caseNum,complainant,officer,incidentDate,summary,severity,assigned,createdBy,createdAt) VALUES(?,?,?,?,?,?,?,?,?)',
      [caseNum, complainant, officer, incidentDate, summary, severity, assigned, req.session.user, now], err => {
        files.forEach(f => {
          const url = `/static/uploads/${f.filename}`;
          db.run('INSERT INTO attachments(caseNum,url) VALUES(?,?)', [caseNum, url]);
        });
        res.redirect(`/case/${caseNum}`);
      });
  });
});

// View Case
app.get('/case/:caseNum', ensureAuth, (req, res) => {
  const cn = req.params.caseNum;
  db.get('SELECT * FROM cases WHERE caseNum = ?', [cn], (e, caseData) => {
    if (!caseData) return res.status(404).send('Not found');
    db.all('SELECT * FROM comments WHERE caseNum = ? ORDER BY createdAt', [cn], (e2, comments) => {
      db.all('SELECT url FROM attachments WHERE caseNum = ?', [cn], (e3, attachments) => {
        res.render('case', { title: `Case ${cn}`, caseData, comments, attachments });
      });
    });
  });
});

// Edit Case
app.get('/case/:caseNum/edit', ensureAuth, (req, res) => {
  const cn = req.params.caseNum;
  db.get('SELECT * FROM cases WHERE caseNum = ?', [cn], (err, caseData) => {
    if (err || !caseData) return res.status(404).send('Case not found');
    res.render('edit', { title: `Edit Case ${cn}`, caseData });
  });
});
app.post('/case/:caseNum/edit', ensureAuth, (req, res) => {
  const cn = req.params.caseNum;
  const { status, assigned, severity } = req.body;
  db.run('UPDATE cases SET status = ?, assigned = ?, severity = ? WHERE caseNum = ?',
    [status, assigned, severity, cn],
    () => res.redirect(`/case/${cn}`));
});

// Comment
app.post('/case/:caseNum/comment', ensureAuth, (req, res) => {
  const cn = req.params.caseNum;
  const content = req.body.comment;
  const now = new Date().toISOString();
  db.run('INSERT INTO comments(caseNum, author, content, createdAt) VALUES (?, ?, ?, ?)',
    [cn, req.session.user, content, now],
    () => res.redirect(`/case/${cn}`));
});

// Export PDF
app.get('/case/:caseNum/export', ensureAuth, (req, res) => {
  const cn = req.params.caseNum;
  db.get('SELECT * FROM cases WHERE caseNum = ?', [cn], (e, row) => {
    res.setHeader('Content-Disposition', `attachment; filename="IA_${cn}.pdf"`);
    const doc = new PDFDocument();
    doc.pipe(res);
    doc.fontSize(18).text(`IA Case ${cn}`, { align: 'center' }).moveDown();
    doc.fontSize(12)
      .text(`Complainant: ${row.complainant}`)
      .text(`Officer: ${row.officer}`)
      .text(`Date: ${row.incidentDate}`)
      .text(`Severity: ${row.severity}`)
      .text(`Status: ${row.status}`)
      .text(`Assigned: ${row.assigned}`).moveDown()
      .text('Summary:').moveDown()
      .text(row.summary);
    db.all('SELECT url FROM attachments WHERE caseNum = ?', [cn], (e2, atts) => {
      if (atts.length) {
        doc.moveDown().text('Attachments:');
        atts.forEach(a => doc.text(a.url));
      }
      doc.end();
    });
  });
});

// Heartbeat
app.get('/heartbeat', (req, res) => res.sendStatus(200));

// Start Server
app.listen(PORT, () => console.log(`Dashboard running on port ${PORT}`));
