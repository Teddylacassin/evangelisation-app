require('dotenv').config();
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcryptjs');
const cron = require('node-cron');
const { initDb, get, all, run, VERSES } = require('./db');
const { sendEmail } = require('./mail');

const app = express();
const PORT = process.env.PORT || 3000;

// Le dossier "data" sert uniquement a stocker les sessions de connexion
// (les donnees de l'app, elles, vivent sur Turso). On le cree s'il n'existe pas.
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  store: new SQLiteStore({ db: 'sessions.db', dir: dataDir }),
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

// Petit wrapper pour eviter d'ecrire try/catch dans chaque route asynchrone
const h = (fn) => (req, res, next) => fn(req, res, next).catch(next);

// Normalise un numero de telephone pour la comparaison : on garde les 9 derniers
// chiffres, ce qui permet de reconnaitre le meme numero ecrit "0470123456" ou
// "+32470123456" ou "0032470123456" (l'indicatif pays et le 0 initial varient,
// mais les derniers chiffres du numero local restent les memes).
function phoneKey(phone) {
  const digits = (phone || '').replace(/[^\d]/g, '');
  if (digits.length < 6) return null;
  return digits.slice(-9);
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

app.post('/inscription', h(async (req, res) => {
  const { name, email, password, church } = req.body;
  if (!name || !email || !password) {
    return res.render('register', { error: "Merci de remplir tous les champs obligatoires." });
  }
  const existing = await get('SELECT id FROM users WHERE email = ?', [email.toLowerCase().trim()]);
  if (existing) {
    return res.render('register', { error: "Un compte existe déjà avec cet email." });
  }
  const hash = bcrypt.hashSync(password, 10);
  const info = await run(
    'INSERT INTO users (name, email, password_hash, church) VALUES (?, ?, ?, ?)',
    [name.trim(), email.toLowerCase().trim(), hash, church ? church.trim() : null]
  );
  const user = await get('SELECT id, name, email, church FROM users WHERE id = ?', [info.lastInsertRowid]);
  req.session.user = user;
  res.redirect('/dashboard');
}));

app.get('/connexion', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');
  res.render('login', { error: null });
});

app.post('/connexion', h(async (req, res) => {
  const { email, password } = req.body;
  const row = await get('SELECT * FROM users WHERE email = ?', [(email || '').toLowerCase().trim()]);
  if (!row || !bcrypt.compareSync(password || '', row.password_hash)) {
    return res.render('login', { error: "Email ou mot de passe incorrect." });
  }
  req.session.user = { id: row.id, name: row.name, email: row.email, church: row.church };
  res.redirect('/dashboard');
}));

app.post('/deconnexion', (req, res) => {
  req.session.destroy(() => res.redirect('/connexion'));
});

// ---------- Mot de passe oublié ----------
app.get('/mot-de-passe-oublie', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');
  res.render('forgot_password', { sent: false });
});

app.post('/mot-de-passe-oublie', h(async (req, res) => {
  const email = (req.body.email || '').toLowerCase().trim();
  const user = await get('SELECT * FROM users WHERE email = ?', [email]);
  if (user) {
    const token = crypto.randomBytes(32).toString('hex');
    await run(
      "UPDATE users SET reset_token = ?, reset_token_expires = datetime('now', '+1 hour') WHERE id = ?",
      [token, user.id]
    );
    const resetUrl = `${req.protocol}://${req.get('host')}/reinitialiser/${token}`;
    await sendEmail({
      to: user.email,
      subject: 'Réinitialisation de ton mot de passe — Semeurs',
      html: `<p>Bonjour ${user.name},</p>
             <p>Tu as demandé à réinitialiser ton mot de passe sur l'application Semeurs.</p>
             <p><a href="${resetUrl}">Clique ici pour choisir un nouveau mot de passe</a> (lien valable 1 heure).</p>
             <p>Si tu n'es pas à l'origine de cette demande, tu peux ignorer cet email.</p>`
    });
  }
  // On affiche toujours le même message, qu'un compte existe avec cet email ou non,
  // pour ne pas révéler quels emails sont inscrits.
  res.render('forgot_password', { sent: true });
}));

app.get('/reinitialiser/:token', h(async (req, res) => {
  const user = await get(
    "SELECT * FROM users WHERE reset_token = ? AND reset_token_expires > datetime('now')",
    [req.params.token]
  );
  res.render('reset_password', { valid: !!user, token: req.params.token, error: null, done: false });
}));

app.post('/reinitialiser/:token', h(async (req, res) => {
  const user = await get(
    "SELECT * FROM users WHERE reset_token = ? AND reset_token_expires > datetime('now')",
    [req.params.token]
  );
  if (!user) {
    return res.render('reset_password', { valid: false, token: req.params.token, error: null, done: false });
  }
  const { password } = req.body;
  if (!password || password.length < 4) {
    return res.render('reset_password', {
      valid: true,
      token: req.params.token,
      error: 'Le mot de passe doit contenir au moins 4 caractères.',
      done: false
    });
  }
  const hash = bcrypt.hashSync(password, 10);
  await run('UPDATE users SET password_hash = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?', [hash, user.id]);
  res.render('reset_password', { valid: true, token: req.params.token, error: null, done: true });
}));

// ---------- Tableau de bord ----------
app.get('/dashboard', requireAuth, h(async (req, res) => {
  const uid = req.session.user.id;

  const total = (await get('SELECT COUNT(*) c FROM souls WHERE created_by = ?', [uid])).c;
  const byStatus = await all('SELECT status, COUNT(*) c FROM souls WHERE created_by = ? GROUP BY status', [uid]);
  const statusCounts = {};
  Object.keys(STATUSES).forEach(s => statusCounts[s] = 0);
  byStatus.forEach(r => statusCounts[r.status] = r.c);

  const thisWeek = (await get(`SELECT COUNT(*) c FROM souls WHERE created_by = ? AND met_date >= date('now','-7 days')`, [uid])).c;
  const thisMonth = (await get(`SELECT COUNT(*) c FROM souls WHERE created_by = ? AND met_date >= date('now','-30 days')`, [uid])).c;

  const aRecontacter = await all(`
    SELECT * FROM souls
    WHERE created_by = ?
      AND status != 'integree'
      AND (last_contacted_at IS NULL OR last_contacted_at < datetime('now','-7 days'))
    ORDER BY met_date ASC
    LIMIT 10
  `, [uid]);

  const teamTotal = (await get('SELECT COUNT(*) c FROM souls', [])).c;
  const teamRanking = await all(`
    SELECT u.name, COUNT(s.id) c
    FROM users u LEFT JOIN souls s ON s.created_by = u.id
    GROUP BY u.id ORDER BY c DESC LIMIT 10
  `, []);

  const announcements = await all(`
    SELECT a.*, u.name as author_name FROM announcements a
    JOIN users u ON u.id = a.user_id
    ORDER BY a.created_at DESC LIMIT 5
  `, []);

  const prayerSupportCount = (await get(`
    SELECT COUNT(*) c FROM prayer_supports ps
    JOIN prayer_requests p ON p.id = ps.prayer_id
    WHERE p.user_id = ?
  `, [uid])).c;

  const goals = await all('SELECT * FROM goals WHERE user_id = ? ORDER BY id ASC', [uid]);
  for (const g of goals) {
    g.achieved = await computeGoalProgress(uid, g.metric, g.period_type);
    g.percent = g.target > 0 ? Math.min(100, Math.round((g.achieved / g.target) * 100)) : 0;
  }

  const recentSouls = await all('SELECT * FROM souls WHERE created_by = ? ORDER BY created_at DESC LIMIT 5', [uid]);

  res.render('dashboard', {
    total, statusCounts, thisWeek, thisMonth, aRecontacter, teamTotal, teamRanking,
    announcements, prayerSupportCount, goals, GOAL_METRICS, GOAL_PERIODS, recentSouls
  });
}));

// ---------- Administration (annonces a l'equipe) ----------
app.get('/admin', requireAdmin, h(async (req, res) => {
  const announcements = await all(`
    SELECT a.*, u.name as author_name FROM announcements a
    JOIN users u ON u.id = a.user_id
    ORDER BY a.created_at DESC
  `, []);
  res.render('admin', { announcements });
}));

app.post('/admin/annonces', requireAdmin, h(async (req, res) => {
  const { content } = req.body;
  if (content && content.trim()) {
    await run('INSERT INTO announcements (user_id, content) VALUES (?, ?)', [req.session.user.id, content.trim()]);
  }
  res.redirect('/admin');
}));

app.post('/admin/annonces/:id/supprimer', requireAdmin, h(async (req, res) => {
  await run('DELETE FROM announcements WHERE id = ?', [req.params.id]);
  res.redirect('/admin');
}));

// ---------- Ames ----------
app.get('/ames', requireAuth, h(async (req, res) => {
  const uid = req.session.user.id;
  const viewScope = req.query.scope === 'equipe' ? 'equipe' : 'moi';
  const q = (req.query.q || '').trim();
  let souls;
  if (viewScope === 'equipe') {
    if (q) {
      souls = await all(`SELECT s.*, u.name as owner_name FROM souls s JOIN users u ON u.id = s.created_by WHERE s.name LIKE ? ORDER BY s.created_at DESC`, [`%${q}%`]);
    } else {
      souls = await all(`SELECT s.*, u.name as owner_name FROM souls s JOIN users u ON u.id = s.created_by ORDER BY s.created_at DESC`, []);
    }
  } else {
    if (q) {
      souls = await all(`SELECT * FROM souls WHERE created_by = ? AND name LIKE ? ORDER BY created_at DESC`, [uid, `%${q}%`]);
    } else {
      souls = await all(`SELECT * FROM souls WHERE created_by = ? ORDER BY created_at DESC`, [uid]);
    }
  }
  res.render('souls_list', { souls, viewScope, q });
}));

app.get('/ames/export.csv', requireAuth, h(async (req, res) => {
  const uid = req.session.user.id;
  const viewScope = req.query.scope === 'equipe' ? 'equipe' : 'moi';
  let souls;
  if (viewScope === 'equipe') {
    souls = await all(`SELECT s.*, u.name as owner_name FROM souls s JOIN users u ON u.id = s.created_by ORDER BY s.created_at DESC`, []);
  } else {
    souls = await all(`SELECT * FROM souls WHERE created_by = ? ORDER BY created_at DESC`, [uid]);
  }
  const esc = (v) => `"${String(v == null ? '' : v).replace(/"/g, '""')}"`;
  const headers = ['Nom', 'Téléphone', 'Ville', 'Lieu', 'Statut', 'Date de rencontre', 'Dernier contact', 'Notes'];
  if (viewScope === 'equipe') headers.push('Gagnée par');
  const lines = [headers.map(esc).join(',')];
  souls.forEach((s) => {
    const row = [
      s.name,
      s.phone,
      s.city,
      s.location,
      STATUSES[s.status] ? STATUSES[s.status].label : s.status,
      s.met_date,
      s.last_contacted_at,
      s.notes
    ];
    if (viewScope === 'equipe') row.push(s.owner_name);
    lines.push(row.map(esc).join(','));
  });
  const csv = '﻿' + lines.join('\r\n');
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="ames-${viewScope}.csv"`);
  res.send(csv);
}));

app.get('/ames/nouvelle', requireAuth, (req, res) => {
  res.render('soul_form', { soul: null, error: null, duplicate: null });
});

app.post('/ames', requireAuth, h(async (req, res) => {
  const { name, phone, city, location, status, notes, met_date, confirm_duplicate } = req.body;
  if (!name) return res.render('soul_form', { soul: req.body, error: "Le nom est obligatoire.", duplicate: null });

  if (phone && !confirm_duplicate) {
    const key = phoneKey(phone);
    if (key) {
      const candidates = await all(`
        SELECT s.*, u.name as owner_name FROM souls s JOIN users u ON u.id = s.created_by WHERE s.phone IS NOT NULL
      `, []);
      const existing = candidates.find((c) => phoneKey(c.phone) === key);
      if (existing) {
        return res.render('soul_form', { soul: req.body, error: null, duplicate: existing });
      }
    }
  }

  await run(
    `INSERT INTO souls (name, phone, city, location, status, notes, met_date, created_by)
    VALUES (?, ?, ?, ?, ?, ?, COALESCE(NULLIF(?, ''), date('now')), ?)`,
    [name.trim(), phone || null, city || null, location || null, status || 'nouvelle_ame', notes || null, met_date, req.session.user.id]
  );
  res.redirect('/ames');
}));

app.get('/ames/:id', requireAuth, h(async (req, res) => {
  const soul = await get('SELECT * FROM souls WHERE id = ?', [req.params.id]);
  if (!soul) return res.status(404).send('Âme introuvable.');
  const messages = await all(`SELECT m.*, u.name as user_name FROM message_log m JOIN users u ON u.id = m.user_id WHERE soul_id = ? ORDER BY sent_at DESC`, [soul.id]);
  const history = await all(`SELECT h.*, u.name as user_name FROM soul_status_history h JOIN users u ON u.id = h.changed_by WHERE soul_id = ? ORDER BY changed_at DESC`, [soul.id]);
  res.render('soul_detail', { soul, messages, history });
}));

app.get('/ames/:id/editer', requireAuth, h(async (req, res) => {
  const soul = await get('SELECT * FROM souls WHERE id = ?', [req.params.id]);
  if (!soul) return res.status(404).send('Âme introuvable.');
  res.render('soul_form', { soul, error: null, duplicate: null });
}));

app.post('/ames/:id', requireAuth, h(async (req, res) => {
  const { name, phone, city, location, status, notes, met_date } = req.body;
  const before = await get('SELECT status FROM souls WHERE id = ?', [req.params.id]);
  await run(
    `UPDATE souls SET name=?, phone=?, city=?, location=?, status=?, notes=?, met_date=? WHERE id=?`,
    [name.trim(), phone || null, city || null, location || null, status, notes || null, met_date, req.params.id]
  );
  if (before && before.status !== status) {
    await run(
      'INSERT INTO soul_status_history (soul_id, old_status, new_status, changed_by) VALUES (?, ?, ?, ?)',
      [req.params.id, before.status, status, req.session.user.id]
    );
  }
  res.redirect('/ames/' + req.params.id);
}));

app.post('/ames/:id/supprimer', requireAuth, h(async (req, res) => {
  await run('DELETE FROM souls WHERE id = ?', [req.params.id]);
  res.redirect('/ames');
}));

// ---------- Messagerie (versets / encouragement) ----------
app.get('/ames/:id/message', requireAuth, h(async (req, res) => {
  const soul = await get('SELECT * FROM souls WHERE id = ?', [req.params.id]);
  if (!soul) return res.status(404).send('Âme introuvable.');
  res.render('message_compose', { soul, VERSES });
}));

app.post('/ames/:id/message', requireAuth, h(async (req, res) => {
  const soul = await get('SELECT * FROM souls WHERE id = ?', [req.params.id]);
  if (!soul) return res.status(404).send('Âme introuvable.');
  const { content } = req.body;
  if (!content || !content.trim()) return res.redirect('/ames/' + soul.id + '/message');

  await run('INSERT INTO message_log (soul_id, user_id, content) VALUES (?, ?, ?)', [soul.id, req.session.user.id, content.trim()]);
  await run(`UPDATE souls SET last_contacted_at = datetime('now') WHERE id = ?`, [soul.id]);

  const digitsPhone = (soul.phone || '').replace(/[^\d+]/g, '');
  res.render('message_preview', { soul, content: content.trim(), digitsPhone });
}));

// ---------- Espace prière ----------
app.get('/priere', requireAuth, h(async (req, res) => {
  const uid = req.session.user.id;
  const requests = await all(`
    SELECT p.*, u.name as user_name,
      (SELECT COUNT(*) FROM prayer_supports ps WHERE ps.prayer_id = p.id) as support_count,
      (SELECT COUNT(*) FROM prayer_supports ps WHERE ps.prayer_id = p.id AND ps.user_id = ?) as i_support
    FROM prayer_requests p JOIN users u ON u.id = p.user_id
    ORDER BY p.answered ASC, p.created_at DESC
  `, [uid]);
  res.render('prayer', { requests });
}));

app.post('/priere', requireAuth, h(async (req, res) => {
  const { content } = req.body;
  if (content && content.trim()) {
    await run('INSERT INTO prayer_requests (user_id, content) VALUES (?, ?)', [req.session.user.id, content.trim()]);
  }
  res.redirect('/priere');
}));

app.post('/priere/:id/soutenir', requireAuth, h(async (req, res) => {
  const uid = req.session.user.id;
  const pid = req.params.id;
  const existing = await get('SELECT id FROM prayer_supports WHERE prayer_id = ? AND user_id = ?', [pid, uid]);
  if (existing) {
    await run('DELETE FROM prayer_supports WHERE id = ?', [existing.id]);
  } else {
    await run('INSERT INTO prayer_supports (prayer_id, user_id) VALUES (?, ?)', [pid, uid]);
  }
  res.redirect('/priere');
}));

app.post('/priere/:id/repondu', requireAuth, h(async (req, res) => {
  const p = await get('SELECT * FROM prayer_requests WHERE id = ?', [req.params.id]);
  if (p && p.user_id === req.session.user.id) {
    await run('UPDATE prayer_requests SET answered = NOT answered WHERE id = ?', [p.id]);
  }
  res.redirect('/priere');
}));

// ---------- Rapports de sortie ----------
app.get('/rapports', requireAuth, h(async (req, res) => {
  const reports = await all(`
    SELECT r.*, u.name as user_name FROM reports r
    JOIN users u ON u.id = r.user_id
    ORDER BY r.report_date DESC, r.created_at DESC
    LIMIT 50
  `, []);
  for (const r of reports) {
    r.people = await all('SELECT * FROM report_people WHERE report_id = ? ORDER BY id ASC', [r.id]);
  }
  res.render('reports', { reports });
}));

app.post('/rapports', requireAuth, h(async (req, res) => {
  const { report_date, location, presence } = req.body;
  const info = await run(
    `INSERT INTO reports (user_id, report_date, location, presence)
     VALUES (?, COALESCE(NULLIF(?, ''), date('now')), ?, ?)`,
    [req.session.user.id, report_date || '', location || null, presence || null]
  );
  const reportId = info.lastInsertRowid;

  // Les personnes rencontrees arrivent sous la forme person[0][name], person[0][phone], etc.
  // (grace a express.urlencoded({extended:true}) qui comprend cette notation).
  const peopleInput = req.body.person ? Object.values(req.body.person) : [];
  for (const p of peopleInput) {
    const name = (p.name || '').trim();
    if (!name) continue;
    const notes = (p.notes || '').trim() || null;
    const phone = (p.phone || '').trim() || null;
    const evangelized = p.evangelized ? 1 : 0;
    const saved = p.saved ? 1 : 0;
    const invited = p.invited ? 1 : 0;

    // Toute personne marquee "sauvee" est automatiquement ajoutee au suivi des ames,
    // pour ne pas avoir a la re-saisir a la main. On evite les doublons par telephone.
    let soulId = null;
    if (saved) {
      let existing = null;
      const key = phoneKey(phone);
      if (key) {
        const candidates = await all('SELECT * FROM souls WHERE phone IS NOT NULL', []);
        existing = candidates.find((c) => phoneKey(c.phone) === key) || null;
      }
      if (existing) {
        soulId = existing.id;
      } else {
        const soulInfo = await run(
          `INSERT INTO souls (name, phone, city, location, status, notes, met_date, created_by)
           VALUES (?, ?, NULL, ?, 'nouvelle_ame', ?, COALESCE(NULLIF(?, ''), date('now')), ?)`,
          [name, phone, location || null, notes, report_date || '', req.session.user.id]
        );
        soulId = soulInfo.lastInsertRowid;
      }
    }

    await run(
      `INSERT INTO report_people (report_id, name, notes, evangelized, saved, phone, invited_church, soul_id)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [reportId, name, notes, evangelized, saved, phone, invited, soulId]
    );
  }

  res.redirect('/rapports');
}));

app.post('/rapports/:id/supprimer', requireAuth, h(async (req, res) => {
  const r = await get('SELECT * FROM reports WHERE id = ?', [req.params.id]);
  if (r && r.user_id === req.session.user.id) {
    await run('DELETE FROM reports WHERE id = ?', [r.id]);
  }
  res.redirect('/rapports');
}));

// ---------- Statistiques (issues des rapports de sortie) ----------
app.get('/statistiques', requireAuth, h(async (req, res) => {
  const period = ['semaine', 'mois', 'tout'].includes(req.query.period) ? req.query.period : 'mois';
  let dateFilter = '';
  if (period === 'semaine') dateFilter = "AND r.report_date >= date('now','-7 days')";
  else if (period === 'mois') dateFilter = "AND r.report_date >= date('now','-30 days')";

  const totals = await get(`
    SELECT
      COUNT(DISTINCT r.id) as total_sorties,
      COUNT(rp.id) as total_personnes,
      COALESCE(SUM(rp.evangelized),0) as total_evangelized,
      COALESCE(SUM(rp.saved),0) as total_saved,
      COALESCE(SUM(rp.invited_church),0) as total_invited
    FROM reports r
    LEFT JOIN report_people rp ON rp.report_id = r.id
    WHERE 1=1 ${dateFilter}
  `, []);

  const ranking = await all(`
    SELECT u.name,
      COUNT(DISTINCT r.id) as sorties,
      COALESCE(SUM(rp.evangelized),0) as evangelized,
      COALESCE(SUM(rp.saved),0) as saved,
      COALESCE(SUM(rp.invited_church),0) as invited
    FROM users u
    LEFT JOIN reports r ON r.user_id = u.id ${dateFilter}
    LEFT JOIN report_people rp ON rp.report_id = r.id
    GROUP BY u.id
    ORDER BY saved DESC, evangelized DESC, sorties DESC
  `, []);

  res.render('statistics', { period, totals, ranking });
}));

// ---------- Mes objectifs ----------
const GOAL_METRICS = {
  saved: 'Âmes sauvées',
  evangelized: 'Âmes évangélisées',
  invited: "Invitations à l'église",
  sorties: 'Sorties effectuées'
};
const GOAL_PERIODS = {
  semaine: { label: 'Cette semaine', days: 7 },
  mois: { label: 'Ce mois-ci', days: 30 },
  annee: { label: 'Cette année', days: 365 }
};

async function computeGoalProgress(userId, metric, periodType) {
  const days = GOAL_PERIODS[periodType] ? GOAL_PERIODS[periodType].days : 30;
  if (metric === 'sorties') {
    const row = await get(
      `SELECT COUNT(*) c FROM reports WHERE user_id = ? AND report_date >= date('now', ?)`,
      [userId, `-${days} days`]
    );
    return row.c;
  }
  const column = metric === 'saved' ? 'rp.saved' : metric === 'evangelized' ? 'rp.evangelized' : 'rp.invited_church';
  const row = await get(
    `SELECT COALESCE(SUM(${column}),0) c
     FROM reports r JOIN report_people rp ON rp.report_id = r.id
     WHERE r.user_id = ? AND r.report_date >= date('now', ?)`,
    [userId, `-${days} days`]
  );
  return row.c;
}

app.get('/objectifs', requireAuth, h(async (req, res) => {
  const uid = req.session.user.id;
  const goals = await all('SELECT * FROM goals WHERE user_id = ? ORDER BY id ASC', [uid]);
  for (const g of goals) {
    g.achieved = await computeGoalProgress(uid, g.metric, g.period_type);
    g.percent = g.target > 0 ? Math.min(100, Math.round((g.achieved / g.target) * 100)) : 0;
  }
  res.render('goals', { goals, GOAL_METRICS, GOAL_PERIODS });
}));

app.post('/objectifs', requireAuth, h(async (req, res) => {
  const uid = req.session.user.id;
  const { metric, period_type, target } = req.body;
  if (!GOAL_METRICS[metric] || !GOAL_PERIODS[period_type]) return res.redirect('/objectifs');
  const targetNum = parseInt(target, 10);
  if (!targetNum || targetNum <= 0) return res.redirect('/objectifs');

  const existing = await get('SELECT id FROM goals WHERE user_id = ? AND metric = ?', [uid, metric]);
  if (existing) {
    await run('UPDATE goals SET period_type = ?, target = ? WHERE id = ?', [period_type, targetNum, existing.id]);
  } else {
    await run('INSERT INTO goals (user_id, metric, period_type, target) VALUES (?, ?, ?, ?)', [uid, metric, period_type, targetNum]);
  }
  res.redirect('/objectifs');
}));

app.post('/objectifs/:id/supprimer', requireAuth, h(async (req, res) => {
  const g = await get('SELECT * FROM goals WHERE id = ?', [req.params.id]);
  if (g && g.user_id === req.session.user.id) {
    await run('DELETE FROM goals WHERE id = ?', [g.id]);
  }
  res.redirect('/objectifs');
}));

// ---------- Rappel hebdomadaire par email ----------
// Chaque lundi a 8h (heure de Bruxelles), on envoie a chaque gagneur d'ame la liste
// des personnes qu'il n'a pas recontactees depuis plus de 7 jours. Si RESEND_API_KEY
// n'est pas configure sur Render, sendEmail() se contente de logger sans planter.
cron.schedule('0 8 * * 1', async () => {
  try {
    const users = await all('SELECT * FROM users', []);
    for (const u of users) {
      const pending = await all(`
        SELECT * FROM souls
        WHERE created_by = ?
          AND status != 'integree'
          AND (last_contacted_at IS NULL OR last_contacted_at < datetime('now','-7 days'))
        ORDER BY met_date ASC
      `, [u.id]);
      if (pending.length === 0) continue;
      const list = pending.map((s) => `<li>${s.name}${s.city ? ' — ' + s.city : ''}</li>`).join('');
      await sendEmail({
        to: u.email,
        subject: `${pending.length} âme(s) à recontacter cette semaine`,
        html: `<p>Bonjour ${u.name},</p>
               <p>Voici les âmes que tu n'as pas recontactées depuis plus de 7 jours :</p>
               <ul>${list}</ul>
               <p>Rendez-vous sur ton tableau de bord pour leur envoyer un mot d'encouragement 🙏</p>`
      });
    }
    console.log('Rappels hebdomadaires envoyés.');
  } catch (err) {
    console.error('Erreur envoi des rappels hebdomadaires :', err);
  }
}, { timezone: 'Europe/Brussels' });

// ---------- Demarrage ----------
initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Application d'évangélisation lancée sur http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    console.error('Erreur au demarrage (initialisation base de donnees) :', err);
    process.exit(1);
  });
