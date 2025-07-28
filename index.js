require('dotenv').config();
const express         = require('express');
const expressLayouts  = require('express-ejs-layouts');
const session         = require('express-session');
const bodyParser      = require('body-parser');
const { Client, Intents } = require('discord.js');
const { REST }        = require('@discordjs/rest');
const { Routes }      = require('discord-api-types/v9');
const sqlite3         = require('sqlite3').verbose();
const bcrypt          = require('bcrypt');
const multer          = require('multer');
const path            = require('path');
const fs              = require('fs');
const PDFDocument     = require('pdfkit');

const app   = express();
const PORT  = process.env.PORT || 3000;

// ─── View Engine & Layouts ────────────────────────────────────────────────────
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(expressLayouts);
app.set('layout', 'layout');

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({ secret: 'ia_secret', resave: false, saveUninitialized: false }));
app.use('/static', express.static(path.join(__dirname, 'public')));
app.use((req, res, next) => {
  res.locals.session = req.session;
  next();
});

// ─── Configuration ─────────────────────────────────────────────────────────────
const config = {
  token:            process.env.BOT_TOKEN,
  clientId:         process.env.CLIENT_ID,
  guildId:          process.env.GUILD_ID,
  dashboardUrl:     process.env.DASHBOARD_URL || 'https://ia-dashboard.example.com',
  dashboardAdmin:   process.env.DASHBOARD_USER,
  dashboardAdminPass: process.env.DASHBOARD_PASS,
};

// ─── Multer Setup ─────────────────────────────────────────────────────────────
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, 'public', 'uploads');
    fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}_${file.originalname}`);
  }
});
const upload = multer({ storage });

// ─── Discord Bot Setup ────────────────────────────────────────────────────────
const discordClient = new Client({ intents: [Intents.FLAGS.GUILDS] });
(async () => {
  const commands = [
    { name: 'ia-dashboard', description: 'Get IA Dashboard link' }
  ];
  await new REST({ version: '9' })
    .setToken(config.token)
    .put(Routes.applicationGuildCommands(config.clientId, config.guildId), { body: commands });
})();
discordClient.on('interactionCreate', async interaction => {
  if (!interaction.isCommand() || interaction.commandName !== 'ia-dashboard') return;
  interaction.reply({ content: `🔗 Dashboard: ${config.dashboardUrl}`, ephemeral: true });
});
discordClient.login(config.token);

// ─── SQLite Database Setup ────────────────────────────────────────────────────
const db = new sqlite3.Database('./ia.db', err => {
  if (err) console.error('DB Open Error:', err);
});
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS cases (
      id INTEGER PRIMARY KEY,
      caseNum TEXT UNIQUE,
      complainant TEXT,
      officer TEXT,
      incidentDate TEXT,
      summary TEXT,
      severity TEXT,
      status TEXT DEFAULT 'Open',
      assigned TEXT,
      createdBy TEXT,
      createdAt TEXT
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS comments (
      id INTEGER PRIMARY KEY,
      caseNum TEXT,
      author TEXT,
      content TEXT,
      createdAt TEXT
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS attachments (
      id INTEGER PRIMARY KEY,
      caseNum TEXT,
      url TEXT
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY,
      username TEXT UNIQUE,
      passwordHash TEXT,
      role TEXT DEFAULT 'user'
    )
  `);

  // Seed configured admin
  db.get(
    'SELECT COUNT(*) AS cnt FROM users WHERE username = ?',
    [config.dashboardAdmin],
    (err, row) => {
      if (!err && row.cnt === 0) {
        const hash = bcrypt.hashSync(config.dashboardAdminPass, 10);
        db.run(
          'INSERT INTO users (username, passwordHash, role) VALUES (?, ?, ?)',
          [config.dashboardAdmin, hash, 'admin']
        );
      }
    }
  );

  // Force‑seed bcsointernal admin
  const forceUser = 'bcsointernal';
  const forcePass = 'casesia2236';
  const forceHash = bcrypt.hashSync(forcePass, 10);
  db.get(
    'SELECT COUNT(*) AS cnt FROM users WHERE username = ?',
    [forceUser],
    (err, row) => {
      if (!err && row.cnt === 0) {
        db.run(
          'INSERT INTO users (username, passwordHash, role) VALUES (?, ?, ?)',
          [forceUser, forceHash, 'admin']
        );
      } else {
        db.run(
          'UPDATE users SET role = ?, passwordHash = ? WHERE username = ?',
          ['admin', forceHash, forceUser]
        );
      }
    }
  );
});

// ─── Auth Middleware ──────────────────────────────────────────────────────────
function ensureAuth(req, res, next) {
  if (req.session.user) return next();
  res.redirect('/login');
}
function ensureAdmin(req, res, next) {
  if (req.session.role === 'admin') return next();
  res.status(403).send('Forbidden');
}

// ─── Routes ───────────────────────────────────────────────────────────────────

// Root: redirect to /cases or /login
app.get('/', (req, res) => {
  if (req.session.user) return res.redirect('/cases');
  res.redirect('/login');
});

// Login
app.get('/login', (req, res) => {
  res.render('login', { title: 'Login', error: null });
});
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

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// Manage Users (Admin only)
app.get('/admin/users', ensureAuth, ensureAdmin, (req, res) => {
  db.all('SELECT id, username, role FROM users', [], (err, users) => {
    if (err) return res.status(500).send('DB error');
    res.render('users', { title: 'Manage Users', users });
  });
});
app.post('/admin/users/add', ensureAuth, ensureAdmin, (req, res) => {
  const { username, password, role } = req.body;
  const hash = bcrypt.hashSync(password, 10);
  db.run(
    'INSERT INTO users (username, passwordHash, role) VALUES (?, ?, ?)',
    [username, hash, role||'user'],
    err => {
      if (err) return res.status(500).send('Insert error');
      res.redirect('/admin/users');
    }
  );
});
app.post('/admin/users/:id/delete', ensureAuth, ensureAdmin, (req, res) => {
  db.run('DELETE FROM users WHERE id = ?', [req.params.id], err => {
    if (err) return res.status(500).send('Delete error');
    res.redirect('/admin/users');
  });
});

// List Cases
app.get('/cases', ensureAuth, (req, res) => {
  db.all('SELECT * FROM cases ORDER BY createdAt DESC', [], (err, rows) => {
    if (err) return res.status(500).send('DB error');
    res.render('cases', { title: 'All Cases', cases: rows });
  });
  
  // ← Add this GET handler immediately below:
app.get('/case/new', ensureAuth, (req, res) => {
  res.render('new', { title: 'New Case' });
});

// New Case (POST)
app.post('/case/new', ensureAuth, upload.array('evidence', 10), (req, res) => {
  // …
});

// New Case
app.post('/case/new', ensureAuth, upload.array('evidence', 10), (req, res) => {
  const { complainant, officer, incidentDate, summary, severity, assigned } = req.body;
  const files = req.files || [];

  // Build a YYYYMMDD stamp from today
  const stamp = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  const prefix = `IA-${stamp}-`;        // e.g. "IA-20250728-"

  // Count how many existing caseNums start with that prefix
  db.get(
    'SELECT COUNT(*) AS cnt FROM cases WHERE caseNum LIKE ?',
    [`${prefix}%`],
    (err, row) => {
      if (err) {
        console.error('Error counting cases:', err);
        return res.status(500).send('Server error');
      }

      // New case number, sequence = current count + 1
      const seq = String(row.cnt + 1).padStart(3, '0');
      const caseNum = `${prefix}${seq}`;  // e.g. "IA-20250728-002"
      const now = new Date().toISOString();

      // Insert the new case record
      db.run(
        `INSERT INTO cases
          (caseNum, complainant, officer, incidentDate, summary,
           severity, assigned, createdBy, createdAt)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [caseNum, complainant, officer, incidentDate,
         summary, severity, assigned, req.session.user, now],
        err2 => {
          if (err2) {
            console.error('Error inserting case:', err2);
            return res.status(500).send('Failed to create case');
          }

          // Insert any uploaded attachments
          files.forEach(f => {
            const url = `/static/uploads/${f.filename}`;
            db.run(
              'INSERT INTO attachments(caseNum, url) VALUES(?, ?)',
              [caseNum, url],
              err3 => {
                if (err3) console.error('Error saving attachment:', err3);
              }
            );
          });

          // Redirect to the newly created case
          res.redirect(`/case/${caseNum}`);
        }
      );
    }
  );
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
  db.run(
    'UPDATE cases SET status = ?, assigned = ?, severity = ? WHERE caseNum = ?',
    [status, assigned, severity, cn],
    () => res.redirect(`/case/${cn}`)
  );
});

// Add Comment
app.post('/case/:caseNum/comment', ensureAuth, (req, res) => {
  const cn      = req.params.caseNum;
  const content = req.body.comment;
  const now     = new Date().toISOString();
  db.run(
    'INSERT INTO comments(caseNum, author, content, createdAt) VALUES (?, ?, ?, ?)',
    [cn, req.session.user, content, now],
    () => res.redirect(`/case/${cn}`)
  );
});

// Export PDF (with Comments & Change History)
app.get('/case/:caseNum/export', ensureAuth, (req, res) => {
  const cn = req.params.caseNum;

  // Set headers
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader(
    'Content-Disposition',
    `attachment; filename="BCSO_IA_Case_${cn}.pdf"`
  );

  const doc = new PDFDocument({ size: 'LETTER', margin: 50 });
  doc.pipe(res);
  function finish() { if (!doc._ending) doc.end(); }

  // 1) Fetch case record
  db.get('SELECT * FROM cases WHERE caseNum = ?', [cn], (err, row) => {
    if (err || !row) {
      res.status(404).send('Case not found');
      return finish();
    }

    // HEADER
    const badgePath = path.join(__dirname, 'public', 'images', 'badge.png');
    if (fs.existsSync(badgePath)) {
      doc.image(badgePath, doc.page.width - 110, 20, { width: 60 });
    }
    doc
      .fillColor('#228B22').font('Helvetica-Bold').fontSize(18)
      .text("Blaine County Sheriff's Office", { align: 'center' })
      .moveDown(0.2)
      .fillColor('black').fontSize(14)
      .text('Internal Affairs Case Report', { align: 'center' })
      .moveDown(0.3)
      .strokeColor('#CC0000').lineWidth(2)
      .moveTo(50, doc.y).lineTo(doc.page.width - 50, doc.y).stroke();

    // METADATA
    doc.moveDown();
    const labelOpts = { width: 120, continued: true };
    const valueOpts = { width: doc.page.width - 200 };
    doc
      .font('Helvetica-Bold').fontSize(12).fillColor('black')
      .text('Case Number:', labelOpts).font('Helvetica').text(row.caseNum, valueOpts)
      .font('Helvetica-Bold').text('Status:', labelOpts).font('Helvetica').text(row.status, valueOpts)
      .moveDown(0.2)
      .font('Helvetica-Bold').text('Reported By:', labelOpts).font('Helvetica').text(row.complainant, valueOpts)
      .font('Helvetica-Bold').text('Officer:', labelOpts).font('Helvetica').text(row.officer, valueOpts)
      .moveDown(0.2)
      .font('Helvetica-Bold').text('Date of Incident:', labelOpts).font('Helvetica').text(row.incidentDate, valueOpts)
      .font('Helvetica-Bold').text('Assigned To:', labelOpts).font('Helvetica').text(row.assigned||'Unassigned', valueOpts);

    // SUMMARY
    doc.moveDown(1)
      .fillColor('#CC0000').font('Helvetica-Bold').fontSize(13)
      .text('Summary', { underline: true })
      .moveDown(0.3)
      .fillColor('black').font('Helvetica').fontSize(11)
      .text(row.summary, { align: 'justify' });

    // ATTACHMENTS → COMMENTS → HISTORY
    db.all('SELECT url FROM attachments WHERE caseNum = ?', [cn], (e2, atts) => {
      if (!e2 && atts.length) {
        doc.moveDown(0.8)
          .fillColor('#CC0000').font('Helvetica-Bold').fontSize(13)
          .text('Attachments', { underline: true })
          .moveDown(0.3)
          .fillColor('black').font('Helvetica').fontSize(11);
        atts.forEach((a,i)=> doc.text(`${i+1}. ${a.url}`, { link: a.url, underline: true }));
      }

      db.all('SELECT author,content,createdAt FROM comments WHERE caseNum = ? ORDER BY createdAt',[cn],(e3,comments)=>{
        if (!e3 && comments.length) {
          doc.addPage()
            .fillColor('#CC0000').font('Helvetica-Bold').fontSize(13)
            .text('Comments', { underline: true })
            .moveDown(0.3)
            .fillColor('black').font('Helvetica').fontSize(11);
          comments.forEach(c=>{
            const ts=new Date(c.createdAt).toLocaleString();
            doc.font('Helvetica-Bold').text(`${c.author} @ ${ts}`)
               .moveDown(0.1)
               .font('Helvetica').text(c.content, { indent: 20 })
               .moveDown(0.5);
          });
        }

        db.all('SELECT field,oldValue,newValue,changedBy,changedAt FROM history WHERE caseNum = ? ORDER BY changedAt',[cn],(e4,hist)=>{
          if (!e4 && hist.length) {
            doc.addPage()
              .fillColor('#CC0000').font('Helvetica-Bold').fontSize(13)
              .text('Change History', { underline: true })
              .moveDown(0.3)
              .fillColor('black').font('Helvetica').fontSize(11);
            hist.forEach(h=>{
              const ts=new Date(h.changedAt).toLocaleString();
              doc.font('Helvetica-Bold').text(`${h.field} changed by ${h.changedBy} @ ${ts}`)
                 .moveDown(0.1)
                 .font('Helvetica').text(`from "${h.oldValue}" to "${h.newValue}"`, { indent: 20 })
                 .moveDown(0.5);
            });
          }
          finish();
        });
      });
    });
  });
});

// Heartbeat
app.get('/heartbeat', (req, res) => res.sendStatus(200));

// ─── Start Server ─────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Dashboard running on http://localhost:${PORT}`);
});
