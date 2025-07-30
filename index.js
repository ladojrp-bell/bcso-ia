require('dotenv').config();
const express         = require('express');
const expressLayouts  = require('express-ejs-layouts');
const session         = require('express-session');
const bodyParser      = require('body-parser');
const { Client, Intents } = require('discord.js');
const { REST }        = require('@discordjs/rest');
const { Routes }      = require('discord-api-types/v9');
const { Pool }        = require('pg');
const bcrypt          = require('bcrypt');
const path            = require('path');
const fs              = require('fs');
const PDFDocument     = require('pdfkit');

const app   = express();
const PORT  = process.env.PORT || 3000;

// ─── View Engine & Layouts ───────────────────────────────────────────────
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(expressLayouts);
app.set('layout', 'layout');

// ─── Middleware ─────────────────────────────────────────────────────────
app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({ secret: 'ia_secret', resave: false, saveUninitialized: false }));
app.use('/static', express.static(path.join(__dirname, 'public')));
app.use('/images', express.static(path.join(__dirname, 'images')));
app.use((req, res, next) => {
  res.locals.session = req.session;
  res.locals.user    = req.session.user;
  res.locals.role    = req.session.role;
  next();
});

// ─── Config ─────────────────────────────────────────────────────────────
const config = {
  token:            process.env.BOT_TOKEN,
  clientId:         process.env.CLIENT_ID,
  guildId:          process.env.GUILD_ID,
  dashboardUrl:     process.env.DASHBOARD_URL || 'https://ia-dashboard.example.com',
  dashboardAdmin:   process.env.DASHBOARD_USER,
  dashboardAdminPass:process.env.DASHBOARD_PASS,
};

// ─── Discord Bot Setup ─────────────────────────────────────────────────
const discordClient = new Client({ intents: [Intents.FLAGS.GUILDS] });
(async () => {
  const commands = [{ name: 'ia-dashboard', description: 'Get IA Dashboard link' }];
  await new REST({ version: '9' })
    .setToken(config.token)
    .put(Routes.applicationGuildCommands(config.clientId, config.guildId), { body: commands });
})();
discordClient.on('interactionCreate', async interaction => {
  if (!interaction.isCommand() || interaction.commandName !== 'ia-dashboard') return;
  interaction.reply({ content: `🔗 Dashboard: ${config.dashboardUrl}`, ephemeral: true });
});
discordClient.login(config.token);

// ─── Postgres Pool ──────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ─── Initialize Tables & Seed Admins ────────────────────────────────────
;(async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS cases (
      id SERIAL PRIMARY KEY,
      caseNum TEXT UNIQUE,
      complainant TEXT,
      officer TEXT,
      incidentDate DATE,
      summary TEXT,
      severity TEXT,
      status TEXT DEFAULT 'Open',
      assigned TEXT,
      createdBy TEXT,
      createdAt TIMESTAMPTZ
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS comments (
      id SERIAL PRIMARY KEY,
      caseNum TEXT,
      author TEXT,
      content TEXT,
      createdAt TIMESTAMPTZ
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS attachments (
      id SERIAL PRIMARY KEY,
      caseNum TEXT,
      url TEXT
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE,
      passwordHash TEXT,
      role TEXT DEFAULT 'user'
    );
  `);
  // **Equipment tables** (run once in your DB if you haven't yet):
  // await pool.query(`
  //   CREATE TABLE IF NOT EXISTS equipment (
  //     id SERIAL PRIMARY KEY,
  //     type TEXT,
  //     model TEXT,
  //     serial_number TEXT,
  //     status TEXT DEFAULT 'In Stock',
  //     notes TEXT,
  //     created_at TIMESTAMPTZ DEFAULT NOW()
  //   );
  // `);
  // await pool.query(`
  //   CREATE TABLE IF NOT EXISTS equipment_history (
  //     id SERIAL PRIMARY KEY,
  //     equipment_id INT REFERENCES equipment(id),
  //     action TEXT,
  //     officer TEXT,
  //     case_num TEXT,
  //     notes TEXT,
  //     timestamp TIMESTAMPTZ DEFAULT NOW()
  //   );
  // `);
  // **UOF reviews table**:
  // await pool.query(`
  //   CREATE TABLE IF NOT EXISTS uof_reviews (
  //     case_num TEXT PRIMARY KEY,
  //     review_date DATE,
  //     reviewer TEXT,
  //     findings TEXT,
  //     policy_sections TEXT,
  //     recommended_actions TEXT
  //   );
  // `);

  // seed configured admin
  const adminHash = bcrypt.hashSync(config.dashboardAdminPass, 10);
  await pool.query(
    `INSERT INTO users(username,passwordhash,role)
     SELECT $1,$2,'admin' WHERE NOT EXISTS(SELECT 1 FROM users WHERE username=$1)`,
    [config.dashboardAdmin, adminHash]
  );
  // force-seed bcsointernal
  const bcsoHash = bcrypt.hashSync('casesia2236', 10);
  await pool.query(
    `INSERT INTO users(username,passwordhash,role)
     SELECT $1,$2,'admin' WHERE NOT EXISTS(SELECT 1 FROM users WHERE username=$1)`,
    ['bcsointernal', bcsoHash]
  );
})();

// ─── Auth Middleware ─────────────────────────────────────────────────────
function ensureAuth(req, res, next) {
  if (req.session.user) return next();
  res.redirect('/login');
}
function ensureAdmin(req, res, next) {
  if (req.session.role === 'admin') return next();
  res.status(403).send('Forbidden');
}

// ─── Routes ──────────────────────────────────────────────────────────────

// Home → /cases or /login
app.get('/', (req, res) =>
  req.session.user
    ? res.redirect('/cases')
    : res.redirect('/login')
);

// Login / Logout
app.get('/login', (req, res) =>
  res.render('login', { title:'Login', error:null })
);
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE username=$1',[username]);
    const user = rows[0];
    if (!user || !bcrypt.compareSync(password, user.passwordhash)) {
      return res.render('login',{ title:'Login', error:'Invalid credentials' });
    }
    req.session.user = user.username;
    req.session.role = user.role;
    res.redirect('/');
  } catch (e) {
    console.error(e);
    res.status(500).send('Server error');
  }
});
app.get('/logout',(req,res)=>
  req.session.destroy(()=>res.redirect('/login'))
);

// Manage Users (Admin)
app.get('/admin/users', ensureAuth, ensureAdmin, async (req,res)=>{
  try {
    const { rows:users } = await pool.query('SELECT id,username,role FROM users');
    res.render('users',{ title:'Manage Users', users });
  } catch(e){ console.error(e); res.status(500).send('DB error'); }
});
app.post('/admin/users/add', ensureAuth, ensureAdmin, async (req,res)=>{
  const { username,password,role } = req.body;
  const hash = bcrypt.hashSync(password,10);
  try {
    await pool.query(
      'INSERT INTO users(username,passwordhash,role) VALUES($1,$2,$3)',
      [username,hash,role||'user']
    );
    res.redirect('/admin/users');
  } catch(e){ console.error(e); res.status(500).send('Insert error'); }
});
app.post('/admin/users/:id/delete', ensureAuth, ensureAdmin, async (req,res)=>{
  try {
    await pool.query('DELETE FROM users WHERE id=$1',[req.params.id]);
    res.redirect('/admin/users');
  } catch(e){ console.error(e); res.status(500).send('Delete error'); }
});

// List All Cases
app.get('/cases', ensureAuth, async (req,res)=>{
  try {
    const { rows } = await pool.query(`
      SELECT
        casenum    AS "caseNum",
        status,
        assigned,
        createdby  AS "createdBy",
        createdat  AS "createdAt"
      FROM cases
      ORDER BY createdat DESC
    `);
    const formatted = rows.map(c=>({
      ...c,
      createdAt: new Date(c.createdAt)
        .toLocaleString('en-US',{ timeZone:'America/New_York' })
    }));
    res.render('cases',{ title:'All Cases', cases:formatted });
  } catch(e){ console.error(e); res.status(500).send('DB error'); }
});

// New Case Form
app.get('/case/new', ensureAuth, (req,res)=>
  res.render('new',{ title:'New Case' })
);

// Create Case (link‑based evidence)
app.post('/case/new', ensureAuth, async (req,res)=>{
  const {
    complainant, officer, incidentDate,
    summary, severity, assigned, evidenceLinks
  } = req.body;
  const now   = new Date().toISOString();
  const stamp = now.slice(0,10).replace(/-/g,'');
  const prefix= `IA-${stamp}-`;
  try {
    const { rows:c } = await pool.query(
      'SELECT COUNT(*)::int AS cnt FROM cases WHERE casenum LIKE $1',
      [`${prefix}%`]
    );
    const seq     = String(c[0].cnt+1).padStart(3,'0');
    const caseNum = `${prefix}${seq}`;

    await pool.query(
      `INSERT INTO cases
         (casenum,complainant,officer,incidentdate,summary,
          severity,assigned,createdby,createdat)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [caseNum,complainant,officer,incidentDate,summary,severity,assigned,req.session.user,now]
    );

    const links = (evidenceLinks||'')
      .split(/\r?\n/).map(l=>l.trim()).filter(Boolean);

    for (const url of links) {
      await pool.query(
        'INSERT INTO attachments(casenum,url) VALUES($1,$2)',
        [caseNum,url]
      );
    }

    res.redirect(`/case/${caseNum}`);
  } catch(err){
    console.error('Error creating case:',err);
    res.status(500).send('Failed to create case');
  }
});

// View Case
app.get('/case/:caseNum', ensureAuth, async (req,res)=>{
  const cn = req.params.caseNum;
  try {
    const { rows } = await pool.query(`
      SELECT
        casenum         AS "caseNum",
        status,
        assigned,
        severity,
        incidentdate    AS "incidentDate",
        createdby       AS "createdBy",
        createdat       AS "createdAt",
        summary
      FROM cases WHERE casenum=$1
    `,[cn]);
    if (!rows[0]) return res.status(404).send('Not found');

    let caseData = rows[0];
    caseData.incidentDate = new Date(caseData.incidentDate)
      .toLocaleString('en-US',{
        timeZone:'America/New_York',
        month:'long',day:'numeric',year:'numeric'
      });
    caseData.createdAt    = new Date(caseData.createdAt)
      .toLocaleString('en-US',{ timeZone:'America/New_York' });

    let { rows:comments } = await pool.query(`
      SELECT author,content,createdat AS "createdAt"
        FROM comments WHERE casenum=$1 ORDER BY createdat
    `,[cn]);
    comments = comments.map(c=>({
      ...c,
      createdAt:new Date(c.createdAt)
        .toLocaleString('en-US',{ timeZone:'America/New_York' })
    }));

    const { rows:attachments } = await pool.query(
      'SELECT url FROM attachments WHERE casenum=$1',[cn]
    );

    // For equipment assignment form
    const { rows:equipmentList } = await pool.query(
      'SELECT * FROM equipment ORDER BY type,model'
    );

    res.render('case',{
      title:`Case ${cn}`,
      caseData, comments, attachments, equipmentList
    });
  } catch(e){
    console.error(e);
    res.status(500).send('DB error');
  }
});

// Edit Case Form & Submit
app.get('/case/:caseNum/edit', ensureAuth, async (req,res)=>{
  const cn = req.params.caseNum;
  try {
    const { rows } = await pool.query(`
      SELECT
        casenum         AS "caseNum",
        complainant,
        officer,
        incidentdate    AS "incidentDate",
        summary,
        severity,
        status,
        assigned
      FROM cases WHERE casenum=$1
    `,[cn]);
    const caseData = rows[0];
    if (!caseData) return res.status(404).send('Not found');
    caseData.incidentDate = new Date(caseData.incidentDate)
      .toISOString().slice(0,10);
    res.render('edit',{ title:`Edit Case ${cn}`, caseData });
  } catch(e){
    console.error(e);
    res.status(500).send('DB error');
  }
});
app.post('/case/:caseNum/edit', ensureAuth, async (req,res)=>{
  const cn = req.params.caseNum;
  const { status, assigned, severity } = req.body;
  try {
    await pool.query(
      'UPDATE cases SET status=$1,assigned=$2,severity=$3 WHERE casenum=$4',
      [status,assigned,severity,cn]
    );
    res.redirect(`/case/${cn}`);
  } catch(e){
    console.error(e);
    res.status(500).send('Update error');
  }
});

// Add Comment
app.post('/case/:caseNum/comment', ensureAuth, async (req,res)=>{
  const cn = req.params.caseNum;
  const now= new Date().toISOString();
  try {
    await pool.query(
      'INSERT INTO comments(casenum,author,content,createdat) VALUES($1,$2,$3,$4)',
      [cn,req.session.user,req.body.comment,now]
    );
    res.redirect(`/case/${cn}`);
  } catch(e){
    console.error(e);
    res.status(500).send('Comment error');
  }
});

// Delete Case (Admin)
app.post('/case/:caseNum/delete', ensureAuth, ensureAdmin, async (req,res)=>{
  const cn=req.params.caseNum;
  try {
    await pool.query('DELETE FROM cases WHERE casenum=$1',[cn]);
    res.redirect('/cases');
  } catch(err){
    console.error(err);
    res.status(500).send('Failed to delete case');
  }
});

// Export PDF
app.get('/case/:caseNum/export', ensureAuth, async (req,res)=>{
  const cn=req.params.caseNum;
  res.setHeader('Content-Type','application/pdf');
  res.setHeader('Content-Disposition',`attachment; filename="BCSO_IA_Case_${cn}.pdf"`);
  const doc=new PDFDocument({ size:'LETTER', margin:50 });
  doc.pipe(res);
  try {
    const { rows:caseRows } = await pool.query('SELECT * FROM cases WHERE casenum=$1',[cn]);
    const caseData = caseRows[0];
    if (!caseData) return res.status(404).send('Not found');

    const badgePath = path.join(__dirname,'public','images','badge.png');
    if (fs.existsSync(badgePath)) {
      doc.image(badgePath, doc.page.width-110,20,{ width:60 });
    }

    doc
      .fillColor('#228B22').font('Helvetica-Bold').fontSize(18)
      .text("Blaine County Sheriff's Office",{align:'center'})
      .moveDown(0.2).fillColor('black').fontSize(14)
      .text('Internal Affairs Case Report',{align:'center'})
      .moveDown(0.3).strokeColor('#CC0000').lineWidth(2)
      .moveTo(50,doc.y).lineTo(doc.page.width-50,doc.y).stroke();

    doc.moveDown();
    const labelOpts={ width:120, continued:true };
    const valueOpts={ width:doc.page.width-200 };

    doc
      .font('Helvetica-Bold').fontSize(12).fillColor('black')
      .text('Case Number:',labelOpts).font('Helvetica').text(caseData.casenum,valueOpts)
      .font('Helvetica-Bold').text('Status:',labelOpts).font('Helvetica').text(caseData.status,valueOpts)
      .moveDown(0.2)
      .font('Helvetica-Bold').text('Reported By:',labelOpts).font('Helvetica').text(caseData.complainant,valueOpts)
      .font('Helvetica-Bold').text('Officer:',labelOpts).font('Helvetica').text(caseData.officer,valueOpts)
      .moveDown(0.2)
      .font('Helvetica-Bold').text('Date of Incident:',labelOpts)
      .font('Helvetica').text(caseData.incidentdate.toISOString().slice(0,10),valueOpts)
      .font('Helvetica-Bold').text('Assigned To:',labelOpts).font('Helvetica').text(caseData.assigned||'Unassigned',valueOpts);

    doc.moveDown(1)
      .fillColor('#CC0000').font('Helvetica-Bold').fontSize(13)
      .text('Summary',{underline:true})
      .moveDown(0.3)
      .fillColor('black').font('Helvetica').fontSize(11)
      .text(caseData.summary,{align:'justify'});

    const { rows:atts } = await pool.query('SELECT url FROM attachments WHERE casenum=$1',[cn]);
    if (atts.length) {
      doc.moveDown(0.8)
        .fillColor('#CC0000').font('Helvetica-Bold').fontSize(13)
        .text('Attachments',{underline:true})
        .moveDown(0.3)
        .fillColor('black').font('Helvetica').fontSize(11);
      atts.forEach((a,i)=>
        doc.text(`${i+1}. ${a.url}`,{link:a.url,underline:true})
      );
    }

    const { rows:coms } = await pool.query(
      'SELECT author,content,createdat FROM comments WHERE casenum=$1 ORDER BY createdat',
      [cn]
    );
    if (coms.length) {
      doc.addPage()
        .fillColor('#CC0000').font('Helvetica-Bold').fontSize(13)
        .text('Comments',{underline:true})
        .moveDown(0.3)
        .fillColor('black').font('Helvetica').fontSize(11);
      coms.forEach(c=>{
        const ts=new Date(c.createdat)
          .toLocaleString('en-US',{ timeZone:'America/New_York' });
        doc.font('Helvetica-Bold').text(`${c.author} @ ${ts}`)
           .moveDown(0.1)
           .font('Helvetica').text(c.content,{ indent:20 })
           .moveDown(0.5);
      });
    }

    doc.end();
  } catch(e){
    console.error(e);
    doc.end();
  }
});

// ─── Equipment Admin Module ────────────────────────────────────────────────

// List all equipment
app.get('/equipment', ensureAuth, async (req,res)=>{
  const { rows } = await pool.query('SELECT * FROM equipment ORDER BY created_at DESC');
  res.render('equipment',{ title:'Equipment Inventory', equipment:rows });
});

// Add new equipment
app.get('/equipment/new', ensureAuth, ensureAdmin, (req,res)=>
  res.render('new_equipment',{ title:'Add Equipment' })
);
app.post('/equipment/new', ensureAuth, ensureAdmin, async (req,res)=>{
  const { type, model, serial_number, notes } = req.body;
  await pool.query(
    `INSERT INTO equipment(type,model,serial_number,notes)
       VALUES($1,$2,$3,$4)`,
    [type,model,serial_number,notes]
  );
  res.redirect('/equipment');
});

// Equipment Admin panel (issue/return/reassign)
app.get('/equipment/manage', ensureAuth, ensureAdmin, async (req,res)=>{
  const filterOfficer = req.query.officer || null;

  // list deputies who currently have equipment
  const { rows: deputies } = await pool.query(`
    SELECT DISTINCT officer
      FROM equipment_history eh
      JOIN equipment e ON e.id = eh.equipment_id
     WHERE eh.action='Issued' AND e.status='Issued'
  `);

  let q = `
    SELECT e.id,e.type,e.model,e.serial_number,
           eh.officer,eh.timestamp AS issuedAt
      FROM equipment e
      JOIN equipment_history eh ON eh.equipment_id = e.id
     WHERE eh.action='Issued' AND e.status='Issued'
  `;
  const params = [];
  if (filterOfficer) {
    q += ' AND eh.officer=$1';
    params.push(filterOfficer);
  }
  q += ' ORDER BY eh.officer,eh.timestamp DESC';
  const { rows: items } = await pool.query(q,params);

  res.render('manage_equipment',{
    title:'Equipment Admin',
    deputies, items, filterOfficer
  });
});

// Issue / reassign equipment to a deputy
app.post('/equipment/:id/issue', ensureAuth, ensureAdmin, async (req,res)=>{
  const eqId    = req.params.id;
  const { officer, case_num, notes } = req.body;

  await pool.query('UPDATE equipment SET status=$1 WHERE id=$2',['Issued',eqId]);
  await pool.query(
    `INSERT INTO equipment_history(equipment_id,action,officer,case_num,notes)
       VALUES($1,'Issued',$2,$3,$4)`,
    [eqId, officer, case_num||null, notes||null]
  );
  res.redirect('/equipment/manage');
});

// Return equipment
app.post('/equipment/:id/return', ensureAuth, ensureAdmin, async (req,res)=>{
  const eqId = req.params.id;
  await pool.query('UPDATE equipment SET status=$1 WHERE id=$2',['In Stock',eqId]);
  await pool.query(
    `INSERT INTO equipment_history(equipment_id,action,officer,notes)
       VALUES($1,'Returned',$2,$3)`,
    [eqId, req.session.user, req.body.notes||null]
  );
  res.redirect('/equipment/manage');
});

// ─── Use‑Of‑Force Review Module ────────────────────────────────────────────

// List UOF reviews
app.get('/uof-reviews', ensureAuth, async (req,res)=>{
  const { rows } = await pool.query(`
    SELECT case_num AS "caseNum", review_date, reviewer
      FROM uof_reviews
     ORDER BY review_date DESC
  `);
  res.render('uof_list',{ title:'Use‑of‑Force Reviews', reviews:rows });
});

// New review form
app.get('/uof-reviews/new', ensureAuth, ensureAdmin, (req,res)=>
  res.render('new_uof',{ title:'New UOF Review' })
);
app.post('/uof-reviews/new', ensureAuth, ensureAdmin, async (req,res)=>{
  const { caseNum, review_date, reviewer, findings, policy_sections, recommended_actions } = req.body;
  await pool.query(`
    INSERT INTO uof_reviews(case_num,review_date,reviewer,findings,policy_sections,recommended_actions)
    VALUES($1,$2,$3,$4,$5,$6)`,
    [caseNum,review_date,reviewer,findings,policy_sections,recommended_actions]
  );
  res.redirect('/uof-reviews');
});

// View review
app.get('/uof-reviews/:caseNum', ensureAuth, async (req,res)=>{
  const { rows } = await pool.query('SELECT * FROM uof_reviews WHERE case_num=$1',[req.params.caseNum]);
  if (!rows[0]) return res.status(404).send('Not found');
  res.render('view_uof',{ title:`UOF Review ${req.params.caseNum}`, review:rows[0] });
});

// Edit review
app.get('/uof-reviews/:caseNum/edit', ensureAuth, ensureAdmin, async (req,res)=>{
  const { rows } = await pool.query('SELECT * FROM uof_reviews WHERE case_num=$1',[req.params.caseNum]);
  if (!rows[0]) return res.status(404).send('Not found');
  res.render('edit_uof',{ title:`Edit UOF ${req.params.caseNum}`, review:rows[0] });
});
app.post('/uof-reviews/:caseNum/edit', ensureAuth, ensureAdmin, async (req,res)=>{
  const cn = req.params.caseNum;
  const { review_date, reviewer, findings, policy_sections, recommended_actions } = req.body;
  await pool.query(`
    UPDATE uof_reviews
       SET review_date=$1,reviewer=$2,findings=$3,
           policy_sections=$4,recommended_actions=$5
     WHERE case_num=$6`,
    [review_date,reviewer,findings,policy_sections,recommended_actions,cn]
  );
  res.redirect(`/uof-reviews/${cn}`);
});

// Heartbeat
app.get('/heartbeat',(req,res)=>res.sendStatus(200));

// Start Server
app.listen(PORT,()=>console.log(`Server running on http://localhost:${PORT}`));
