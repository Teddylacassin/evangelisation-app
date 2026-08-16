require('dotenv').config();
const path = require('path');
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcryptjs');
const { db, VERSES } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  store: new SQLiteStore({ db: 'sessions.db', dir: path.join(__dirname, 'data') }),
  secret: process.env.SESSION_SECRET || 'change-moi-en-production-evangelisation',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 * 30 } // 30 jours
}));

const STATUSES = {
  nouvelle_ame: { label: "Nouvelle âme rencontrée", color: "#f59e0b" },
  en_suivi: { label: "En suivi", color: "#3b82f6" },
  affermie: { label: "Affermie dans la foi", color: "#8b5cf6" },
  integree: { label: "Intégrée dans une église", color: "#10b981" },
  injoignable: { label: "Injoignable", color: "#6b7280" }
};

// Liste des administrateurs : reglable sur Render (Environment > ADMIN_EMAILS),
// emails separes par des virgules, ex: "moi@exemple.com,autre@exemple.com"
const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || 'teddylacassin@hotmail.com')
  .split(',')
  .map(e => e.trim().toLowerCase())
  .filter(Boolean);

function isAdminEmail(email) {
  return !!email && ADMIN_EMAILS.includes(email.toLowerCase());
}

app.use((req, res, next) => {
  res.locals.currentUser = req.session.user || null;
  res.locals.STATUSES = STATUSES;
  res.locals.isAdmin = req.session.user ? isAdminEmail(req.session.user.email) : false;
  next();
});

function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect('/connexion');
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user) return res.redirect('/connexion');
  if (!isAdminEmail(req.session.user.email)) return res.status(403).send('Accès réservé aux administrateurs.');
  next();
}

// ---------- Accueil ----------
app.get('/', (req, res) => {
  res.redirect(req.session.user ? '/dashboard' : '/connexion');
});

// ---------- Authentification ----------
app.get('/inscription', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');
  res.render('register', { error: null });
});

app.post('/inscription', (req, res) => {
  const { name, email, password, church } = req.body;
  if (!name || !email || !password) {
    return res.render('register', { error: "Merci de remplir tous les champs obligatoires." });
  }
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase().trim());
  if (existing) {
    return res.render('register', { error: "Un compte existe déjà avec cet email." });
  }
  const hash = bcrypt.hashSync(password, 10);
  const info = db.prepare('INSERT INTO users (name, email, password_hash, church) VALUES (?, ?, ?, ?)')
    .run(name.trim(), email.toLowerCase().trim(), hash, church ? church.trim() : null);
  const user = db.prepare('SELECT id, name, email, church FROM users WHERE id = ?').get(info.lastInsertRowid);
  req.session.user = user;
  res.redirect('/dashboard');
});

app.get('/connexion', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');
  res.render('login', { error: null });
});

app.post('/connexion', (req, res) => {
  const { email, password } = req.body;
  const row = db.prepare('SELECT * FROM users WHERE email = ?').get((email || '').toLowerCase().trim());
  if (!row || !bcrypt.compareSync(password || '', row.password_hash)) {
    return res.render('login', { error: "Email ou mot de passe incorrect." });
  }
  req.session.user = { id: row.id, name: row.name, email: row.email, church: row.church };
  res.redirect('/dashboard');
});

app.post('/deconnexion', (req, res) => {
  req.session.destroy(() => res.redirect('/connexion'));
});

// ---------- Tableau de bord ----------
app.get('/dashboard', requireAuth, (req, res) => {
  const uid = req.session.user.id;

  const total = db.prepare('SELECT COUNT(*) c FROM souls WHERE created_by = ?').get(uid).c;
  const byStatus = db.prepare('SELECT status, COUNT(*) c FROM souls WHERE created_by = ? GROUP BY status').all(uid);
  const statusCounts = {};
  Object.keys(STATUSES).forEach(s => statusCounts[s] = 0);
  byStatus.forEach(r => statusCounts[r.status] = r.c);

  const thisWeek = db.prepare(`SELECT COUNT(*) c FROM souls WHERE created_by = ? AND met_date >= date('now','-7 days')`).get(uid).c;
  const thisMonth = db.prepare(`SELECT COUNT(*) c FROM souls WHERE created_by = ? AND met_date >= date('now','-30 days')`).get(uid).c;

  const aRecontacter = db.prepare(`
    SELECT * FROM souls
    WHERE created_by = ?
      AND status != 'integree'
      AND (last_contacted_at IS NULL OR last_contacted_at < datetime('now','-7 days'))
    ORDER BY met_date ASC
    LIMIT 10
  `).all(uid);

  const teamTotal = db.prepare('SELECT COUNT(*) c FROM souls').get().c;
  const teamRanking = db.prepare(`
    SELECT u.name, COUNT(s.id) c
    FROM users u LEFT JOIN souls s ON s.created_by = u.id
    GROUP BY u.id ORDER BY c DESC LIMIT 10
  `).all();

  const announcements = db.prepare(`
    SELECT a.*, u.name as author_name FROM announcements a
    JOIN users u ON u.id = a.user_id
    ORDER BY a.created_at DESC LIMIT 5
  `).all();

  res.render('dashboard', { total, statusCounts, thisWeek, thisMonth, aRecontacter, teamTotal, teamRanking, announcements });
});

// ---------- Administration (annonces a l'equipe) ----------
app.get('/admin', requireAdmin, (req, res) => {
  const announcements = db.prepare(`
    SELECT a.*, u.name as author_name FROM announcements a
    JOIN users u ON u.id = a.user_id
    ORDER BY a.created_at DESC
  `).all();
  res.render('admin', { announcements });
});

app.post('/admin/annonces', requireAdmin, (req, res) => {
  const { content } = req.body;
  if (content && content.trim()) {
    db.prepare('INSERT INTO announcements (user_id, content) VALUES (?, ?)').run(req.session.user.id, content.trim());
  }
  res.redirect('/admin');
});

app.post('/admin/annonces/:id/supprimer', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM announcements WHERE id = ?').run(req.params.id);
  res.redirect('/admin');
});

// ---------- Ames ----------
app.get('/ames', requireAuth, (req, res) => {
  const uid = req.session.user.id;
  const viewScope = req.query.scope === 'equipe' ? 'equipe' : 'moi';
  const q = (req.query.q || '').trim();
  let souls;
  if (viewScope === 'equipe') {
    if (q) {
      souls = db.prepare(`SELECT s.*, u.name as owner_name FROM souls s JOIN users u ON u.id = s.created_by WHERE s.name LIKE ? ORDER BY s.created_at DESC`).all(`%${q}%`);
    } else {
      souls = db.prepare(`SELECT s.*, u.name as owner_name FROM souls s JOIN users u ON u.id = s.created_by ORDER BY s.created_at DESC`).all();
    }
  } else {
    if (q) {
      souls = db.prepare(`SELECT * FROM souls WHERE created_by = ? AND name LIKE ? ORDER BY created_at DESC`).all(uid, `%${q}%`);
    } else {
      souls = db.prepare(`SELECT * FROM souls WHERE created_by = ? ORDER BY created_at DESC`).all(uid);
    }
  }
  res.render('souls_list', { souls, viewScope, q });
});

app.get('/ames/nouvelle', requireAuth, (req, res) => {
  res.render('soul_form', { soul: null, error: null });
});

app.post('/ames', requireAuth, (req, res) => {
  const { name, phone, city, location, status, notes, met_date } = req.body;
  if (!name) return res.render('soul_form', { soul: req.body, error: "Le nom est obligatoire." });
  db.prepare(`INSERT INTO souls (name, phone, city, location, status, notes, met_date, created_by)
    VALUES (?, ?, ?, ?, ?, ?, COALESCE(NULLIF(?, ''), date('now')), ?)`)
    .run(name.trim(), phone || null, city || null, location || null, status || 'nouvelle_ame', notes || null, met_date, req.session.user.id);
  res.redirect('/ames');
});

app.get('/ames/:id', requireAuth, (req, res) => {
  const soul = db.prepare('SELECT * FROM souls WHERE id = ?').get(req.params.id);
  if (!soul) return res.status(404).send('Âme introuvable.');
  const messages = db.prepare(`SELECT m.*, u.name as user_name FROM message_log m JOIN users u ON u.id = m.user_id WHERE soul_id = ? ORDER BY sent_at DESC`).all(soul.id);
  res.render('soul_detail', { soul, messages });
});

app.get('/ames/:id/editer', requireAuth, (req, res) => {
  const soul = db.prepare('SELECT * FROM souls WHERE id = ?').get(req.params.id);
  if (!soul) return res.status(404).send('Âme introuvable.');
  res.render('soul_form', { soul, error: null });
});

app.post('/ames/:id', requireAuth, (req, res) => {
  const { name, phone, city, location, status, notes, met_date } = req.body;
  db.prepare(`UPDATE souls SET name=?, phone=?, city=?, location=?, status=?, notes=?, met_date=? WHERE id=?`)
    .run(name.trim(), phone || null, city || null, location || null, status, notes || null, met_date, req.params.id);
  res.redirect('/ames/' + req.params.id);
});

app.post('/ames/:id/supprimer', requireAuth, (req, res) => {
  db.prepare('DELETE FROM souls WHERE id = ?').run(req.params.id);
  res.redirect('/ames');
});

// ---------- Messagerie (versets / encouragement) ----------
app.get('/ames/:id/message', requireAuth, (req, res) => {
  const soul = db.prepare('SELECT * FROM souls WHERE id = ?').get(req.params.id);
  if (!soul) return res.status(404).send('Âme introuvable.');
  res.render('message_compose', { soul, VERSES });
});

app.post('/ames/:id/message', requireAuth, (req, res) => {
  const soul = db.prepare('SELECT * FROM souls WHERE id = ?').get(req.params.id);
  if (!soul) return res.status(404).send('Âme introuvable.');
  const { content } = req.body;
  if (!content || !content.trim()) return res.redirect('/ames/' + soul.id + '/message');

  db.prepare('INSERT INTO message_log (soul_id, user_id, content) VALUES (?, ?, ?)')
    .run(soul.id, req.session.user.id, content.trim());
  db.prepare(`UPDATE souls SET last_contacted_at = datetime('now') WHERE id = ?`).run(soul.id);

  const digitsPhone = (soul.phone || '').replace(/[^\d+]/g, '');
  res.render('message_preview', { soul, content: content.trim(), digitsPhone });
});

// ---------- Espace prière ----------
app.get('/priere', requireAuth, (req, res) => {
  const uid = req.session.user.id;
  const requests = db.prepare(`
    SELECT p.*, u.name as user_name,
      (SELECT COUNT(*) FROM prayer_supports ps WHERE ps.prayer_id = p.id) as support_count,
      (SELECT COUNT(*) FROM prayer_supports ps WHERE ps.prayer_id = p.id AND ps.user_id = ?) as i_support
    FROM prayer_requests p JOIN users u ON u.id = p.user_id
    ORDER BY p.answered ASC, p.created_at DESC
  `).all(uid);
  res.render('prayer', { requests });
});

app.post('/priere', requireAuth, (req, res) => {
  const { content } = req.body;
  if (content && content.trim()) {
    db.prepare('INSERT INTO prayer_requests (user_id, content) VALUES (?, ?)').run(req.session.user.id, content.trim());
  }
  res.redirect('/priere');
});

app.post('/priere/:id/soutenir', requireAuth, (req, res) => {
  const uid = req.session.user.id;
  const pid = req.params.id;
  const existing = db.prepare('SELECT id FROM prayer_supports WHERE prayer_id = ? AND user_id = ?').get(pid, uid);
  if (existing) {
    db.prepare('DELETE FROM prayer_supports WHERE id = ?').run(existing.id);
  } else {
    db.prepare('INSERT INTO prayer_supports (prayer_id, user_id) VALUES (?, ?)').run(pid, uid);
  }
  res.redirect('/priere');
});

app.post('/priere/:id/repondu', requireAuth, (req, res) => {
  const p = db.prepare('SELECT * FROM prayer_requests WHERE id = ?').get(req.params.id);
  if (p && p.user_id === req.session.user.id) {
    db.prepare('UPDATE prayer_requests SET answered = NOT answered WHERE id = ?').run(p.id);
  }
  res.redirect('/priere');
});

app.listen(PORT, () => {
  console.log(`Application d'évangélisation lancée sur http://localhost:${PORT}`);
});
