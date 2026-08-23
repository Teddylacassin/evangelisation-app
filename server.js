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
app.use(express.json());
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
async function getSetting(key) {
  const row = await get('SELECT value FROM settings WHERE key = ?', [key]);
  return row ? row.value : null;
}

async function setSetting(key, value) {
  await run(
    `INSERT INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now'))
     ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')`,
    [key, value]
  );
}

app.get('/admin', requireAdmin, h(async (req, res) => {
  const announcements = await all(`
    SELECT a.*, u.name as author_name FROM announcements a
    JOIN users u ON u.id = a.user_id
    ORDER BY a.created_at DESC
  `, []);
  const zoomLink = await getSetting('zoom_link');
  const zoomLabel = await getSetting('zoom_label');
  const teamMembers = await all('SELECT id, name FROM users ORDER BY name ASC', []);
  const prayerMeetings = await all(`
    SELECT pm.*, l.name as lead_name, c.name as colead_name
    FROM prayer_meetings pm
    LEFT JOIN users l ON l.id = pm.lead_id
    LEFT JOIN users c ON c.id = pm.colead_id
    ORDER BY pm.meeting_date ASC
  `, []);
  const houseCells = await all('SELECT * FROM house_cells ORDER BY active DESC, neighborhood ASC, name ASC', []);
  res.render('admin', { announcements, zoomLink, zoomLabel, teamMembers, prayerMeetings, houseCells });
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

app.post('/admin/zoom', requireAdmin, h(async (req, res) => {
  const { zoom_link, zoom_label } = req.body;
  await setSetting('zoom_link', (zoom_link || '').trim());
  await setSetting('zoom_label', (zoom_label || '').trim());
  res.redirect('/admin');
}));

app.post('/admin/reunions-priere', requireAdmin, h(async (req, res) => {
  const { meeting_date, topic, lead_id, colead_id } = req.body;
  if (meeting_date && meeting_date.trim()) {
    await run(
      'INSERT INTO prayer_meetings (meeting_date, topic, lead_id, colead_id, created_by) VALUES (?, ?, ?, ?, ?)',
      [meeting_date.trim(), (topic || '').trim() || null, lead_id || null, colead_id || null, req.session.user.id]
    );
  }
  res.redirect('/admin');
}));

app.post('/admin/reunions-priere/:id/supprimer', requireAdmin, h(async (req, res) => {
  await run('DELETE FROM prayer_meetings WHERE id = ?', [req.params.id]);
  res.redirect('/admin');
}));

// ---------- Cellules de maison ----------
app.post('/admin/cellules', requireAdmin, h(async (req, res) => {
  const { name, neighborhood, meeting_day, meeting_time, description, pilot_name, pilot_phone, copilot_name, copilot_phone } = req.body;
  if (name && name.trim() && neighborhood && neighborhood.trim() && pilot_name && pilot_name.trim() && pilot_phone && pilot_phone.trim()) {
    await run(
      `INSERT INTO house_cells (name, neighborhood, meeting_day, meeting_time, description, pilot_name, pilot_phone, copilot_name, copilot_phone, created_by)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [name.trim(), neighborhood.trim(), (meeting_day || '').trim() || null, (meeting_time || '').trim() || null,
       (description || '').trim() || null, pilot_name.trim(), pilot_phone.trim(),
       (copilot_name || '').trim() || null, (copilot_phone || '').trim() || null, req.session.user.id]
    );
  }
  res.redirect('/admin');
}));

app.post('/admin/cellules/:id/toggle', requireAdmin, h(async (req, res) => {
  await run('UPDATE house_cells SET active = 1 - active WHERE id = ?', [req.params.id]);
  res.redirect('/admin');
}));

app.post('/admin/cellules/:id/supprimer', requireAdmin, h(async (req, res) => {
  await run('DELETE FROM house_cells WHERE id = ?', [req.params.id]);
  res.redirect('/admin');
}));

// Page publique (pas de connexion requise) : accessible via le QR code des cartes
// d'invitation. On n'affiche jamais d'adresse, seulement le quartier et un moyen
// de contacter le pilote / co-pilote par WhatsApp, pour preserver l'intimite des
// familles qui accueillent une cellule chez elles.
app.get('/cellules', h(async (req, res) => {
  const neighborhoods = await all(
    `SELECT DISTINCT neighborhood FROM house_cells WHERE active = 1 ORDER BY neighborhood ASC`, []
  );
  const selected = (req.query.quartier || '').trim();
  const cells = selected
    ? await all(`SELECT * FROM house_cells WHERE active = 1 AND neighborhood = ? ORDER BY name ASC`, [selected])
    : await all(`SELECT * FROM house_cells WHERE active = 1 ORDER BY neighborhood ASC, name ASC`, []);
  res.render('cellules', { cells, neighborhoods, selected });
}));

// Page interne (connexion requise) qui affiche le QR code des cartes d'invitation
// directement dans l'appli : chaque gagneur d'ame peut l'ouvrir sur son telephone
// et le faire scanner par la personne qu'il rencontre, sans avoir besoin d'une
// carte imprimee sur lui.
app.get('/invitation', requireAuth, (req, res) => {
  res.render('invitation');
});

// ---------- Carte des missions ----------
// Outil de coordination interne pour l'equipe (connexion requise) : qui est sur
// le terrain en ce moment, quelles cellules se reunissent aujourd'hui, et quelles
// sorties sont planifiees a l'avance avec inscription.
const JOURS_FR = ['Dimanche', 'Lundi', 'Mardi', 'Mercredi', 'Jeudi', 'Vendredi', 'Samedi'];

// Liste fermee de quartiers de Liege, chacun associe a un point approximatif sur
// la carte. Sert de repli quand une personne n'a pas partage sa position GPS en
// direct (ou l'a refusee) : elle apparait alors approximativement dans son quartier
// declare plutot qu'a une adresse exacte.
const LIEGE_QUARTIERS = [
  { label: 'Centre-ville', lat: 50.6326, lng: 5.5797 },
  { label: 'Outremeuse', lat: 50.6423, lng: 5.5847 },
  { label: 'Guillemins', lat: 50.6247, lng: 5.5664 },
  { label: 'Angleur', lat: 50.6106, lng: 5.6059 },
  { label: 'Sainte-Marguerite', lat: 50.6469, lng: 5.5717 },
  { label: 'Sainte-Walburge', lat: 50.6516, lng: 5.5588 },
  { label: 'Jupille', lat: 50.6465, lng: 5.6349 },
  { label: 'Chênée', lat: 50.6089, lng: 5.6216 },
  { label: 'Grivegnée', lat: 50.6280, lng: 5.6188 },
  { label: 'Bressoux', lat: 50.6435, lng: 5.6106 },
  { label: 'Rocourt', lat: 50.6737, lng: 5.5525 },
  { label: 'Glain', lat: 50.6544, lng: 5.5341 },
  { label: 'Droixhe', lat: 50.6499, lng: 5.6033 },
  { label: 'Longdoz', lat: 50.6367, lng: 5.5875 },
  { label: 'Fétinne', lat: 50.6321, lng: 5.5977 }
];

function findQuartier(label) {
  return LIEGE_QUARTIERS.find((q) => q.label === (label || '').trim()) || null;
}

// Ajoute un leger decalage aleatoire (quelques centaines de metres) autour du point
// central du quartier, pour que plusieurs personnes dans le meme quartier n'apparaissent
// jamais exactement au meme endroit ni au centre exact du quartier.
function jitter(quartier) {
  return {
    lat: quartier.lat + (Math.random() - 0.5) * 0.008,
    lng: quartier.lng + (Math.random() - 0.5) * 0.012
  };
}

// Distance a vol d'oiseau (en metres) entre deux points GPS, via la formule de
// Haversine. Utilise uniquement entre deux positions GPS en direct (jamais avec
// un point approximatif de quartier, ce qui donnerait une distance trompeuse).
function distanceMeters(lat1, lng1, lat2, lng2) {
  const R = 6371000;
  const toRad = (deg) => (deg * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLng = toRad(lng2 - lng1);
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLng / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

// Ajoute une distance approximative (en metres) entre "moi" et chaque autre
// missionnaire actif, uniquement quand les deux partagent une position GPS en
// direct fraiche. Sinon la distance reste inconnue (null) : on ne calcule jamais
// de distance a partir d'un point de quartier approximatif.
function addDistances(activeCheckins, myActiveCheckin) {
  const canCompute = myActiveCheckin && myActiveCheckin.has_live_position && myActiveCheckin.lat != null && myActiveCheckin.lng != null;
  activeCheckins.forEach((c) => {
    if (canCompute && c.user_id !== myActiveCheckin.user_id && c.has_live_position && c.lat != null && c.lng != null) {
      c.distance_m = Math.round(distanceMeters(myActiveCheckin.lat, myActiveCheckin.lng, c.lat, c.lng));
    } else {
      c.distance_m = null;
    }
  });
}

// Construit les points affiches sur la carte : si un missionnaire a partage sa
// position GPS en direct (recue il y a moins de 2 minutes), on affiche cette
// position exacte ; sinon on retombe sur le quartier declare (avec leger decalage
// aleatoire). Les sorties prevues restent toujours au niveau du quartier.
function buildMapPoints(activeCheckins, outings) {
  const mapPoints = [];
  activeCheckins.forEach((c) => {
    if (c.has_live_position && c.lat != null && c.lng != null) {
      mapPoints.push({
        type: 'terrain',
        live: true,
        lat: c.lat,
        lng: c.lng,
        label: `🔥 ${c.user_name} — position en direct`
      });
      return;
    }
    const q = findQuartier(c.neighborhood);
    if (!q) return;
    const pos = jitter(q);
    mapPoints.push({ type: 'terrain', live: false, lat: pos.lat, lng: pos.lng, label: `🔥 ${c.user_name} — ${c.neighborhood}` });
  });
  outings.forEach((o) => {
    const q = findQuartier(o.neighborhood);
    if (!q) return;
    const pos = jitter(q);
    mapPoints.push({
      type: 'sortie',
      live: false,
      lat: pos.lat,
      lng: pos.lng,
      label: `📅 ${o.outing_date} — ${o.location} (${o.participants.length} participant${o.participants.length !== 1 ? 's' : ''})`
    });
  });
  return mapPoints;
}

app.get('/missions', requireAuth, h(async (req, res) => {
  const uid = req.session.user.id;

  const activeCheckins = await all(`
    SELECT c.*, u.name as user_name,
      CASE WHEN c.position_updated_at > datetime('now', '-2 minutes') THEN 1 ELSE 0 END as has_live_position
    FROM field_checkins c
    JOIN users u ON u.id = c.user_id
    WHERE c.ended_at IS NULL AND c.started_at > datetime('now', '-6 hours')
    ORDER BY c.started_at DESC
  `, []);
  const myActiveCheckin = activeCheckins.find((c) => c.user_id === uid) || null;
  addDistances(activeCheckins, myActiveCheckin);

  const todayName = JOURS_FR[new Date().getDay()];
  const allCells = await all('SELECT * FROM house_cells WHERE active = 1 ORDER BY neighborhood ASC, name ASC', []);
  const cellsToday = allCells.filter((c) => (c.meeting_day || '').trim().toLowerCase() === todayName.toLowerCase());

  const outings = await all(`
    SELECT o.*, u.name as creator_name FROM planned_outings o
    JOIN users u ON u.id = o.created_by
    WHERE o.outing_date >= date('now')
    ORDER BY o.outing_date ASC
  `, []);
  for (const o of outings) {
    o.participants = await all(`
      SELECT op.*, u.name as user_name FROM outing_participants op
      JOIN users u ON u.id = op.user_id
      WHERE op.outing_id = ?
      ORDER BY u.name ASC
    `, [o.id]);
    o.iParticipate = o.participants.some((p) => p.user_id === uid);
  }

  // On prepare les points de la carte cote serveur : position en direct quand elle est
  // fraiche, sinon un point approximatif (jitte) par personne sur le terrain, et un
  // point par sortie a venir dont le quartier est connu.
  const mapPoints = buildMapPoints(activeCheckins, outings);

  res.render('missions', { activeCheckins, myActiveCheckin, todayName, cellsToday, outings, LIEGE_QUARTIERS, mapPoints });
}));

app.post('/missions/position', requireAuth, h(async (req, res) => {
  const uid = req.session.user.id;
  const lat = Number(req.body.lat);
  const lng = Number(req.body.lng);
  if (!Number.isFinite(lat) || !Number.isFinite(lng) || lat < -90 || lat > 90 || lng < -180 || lng > 180) {
    return res.status(400).json({ ok: false });
  }
  const active = await get(
    `SELECT * FROM field_checkins WHERE user_id = ? AND ended_at IS NULL AND started_at > datetime('now', '-6 hours')`,
    [uid]
  );
  if (!active) {
    return res.status(409).json({ ok: false });
  }
  await run(
    `UPDATE field_checkins SET lat = ?, lng = ?, position_updated_at = datetime('now') WHERE id = ?`,
    [lat, lng, active.id]
  );
  res.json({ ok: true });
}));

app.get('/missions/live.json', requireAuth, h(async (req, res) => {
  const uid = req.session.user.id;
  const activeCheckins = await all(`
    SELECT c.*, u.name as user_name,
      CASE WHEN c.position_updated_at > datetime('now', '-2 minutes') THEN 1 ELSE 0 END as has_live_position
    FROM field_checkins c
    JOIN users u ON u.id = c.user_id
    WHERE c.ended_at IS NULL AND c.started_at > datetime('now', '-6 hours')
    ORDER BY c.started_at DESC
  `, []);
  const myActiveCheckin = activeCheckins.find((c) => c.user_id === uid) || null;
  addDistances(activeCheckins, myActiveCheckin);

  const outings = await all(`
    SELECT o.*, u.name as creator_name FROM planned_outings o
    JOIN users u ON u.id = o.created_by
    WHERE o.outing_date >= date('now')
    ORDER BY o.outing_date ASC
  `, []);
  for (const o of outings) {
    o.participants = await all(`
      SELECT op.*, u.name as user_name FROM outing_participants op
      JOIN users u ON u.id = op.user_id
      WHERE op.outing_id = ?
      ORDER BY u.name ASC
    `, [o.id]);
  }
  const mapPoints = buildMapPoints(activeCheckins, outings);
  const checkins = activeCheckins.map((c) => ({
    user_name: c.user_name,
    neighborhood: c.neighborhood,
    distance_m: c.distance_m
  }));
  res.json({ activeCount: activeCheckins.length, mapPoints, checkins });
}));

app.post('/missions/terrain', requireAuth, h(async (req, res) => {
  const uid = req.session.user.id;
  const active = await get(
    `SELECT * FROM field_checkins WHERE user_id = ? AND ended_at IS NULL AND started_at > datetime('now', '-6 hours')`,
    [uid]
  );
  if (active) {
    await run(`UPDATE field_checkins SET ended_at = datetime('now') WHERE id = ?`, [active.id]);
  } else {
    const neighborhood = (req.body.neighborhood || '').trim();
    if (neighborhood && findQuartier(neighborhood)) {
      await run('INSERT INTO field_checkins (user_id, neighborhood) VALUES (?, ?)', [uid, neighborhood]);
    }
  }
  res.redirect('/missions');
}));

app.post('/missions/sorties', requireAuth, h(async (req, res) => {
  const { outing_date, location, neighborhood, notes } = req.body;
  if (outing_date && outing_date.trim() && location && location.trim()) {
    const validNeighborhood = neighborhood && findQuartier(neighborhood) ? neighborhood.trim() : null;
    await run(
      'INSERT INTO planned_outings (outing_date, location, neighborhood, notes, created_by) VALUES (?, ?, ?, ?, ?)',
      [outing_date.trim(), location.trim(), validNeighborhood, (notes || '').trim() || null, req.session.user.id]
    );
  }
  res.redirect('/missions');
}));

app.post('/missions/sorties/:id/participer', requireAuth, h(async (req, res) => {
  const uid = req.session.user.id;
  const oid = req.params.id;
  const existing = await get('SELECT id FROM outing_participants WHERE outing_id = ? AND user_id = ?', [oid, uid]);
  if (existing) {
    await run('DELETE FROM outing_participants WHERE id = ?', [existing.id]);
  } else {
    await run('INSERT INTO outing_participants (outing_id, user_id) VALUES (?, ?)', [oid, uid]);
  }
  res.redirect('/missions');
}));

app.post('/missions/sorties/:id/supprimer', requireAuth, h(async (req, res) => {
  const o = await get('SELECT * FROM planned_outings WHERE id = ?', [req.params.id]);
  if (o && o.created_by === req.session.user.id) {
    await run('DELETE FROM planned_outings WHERE id = ?', [o.id]);
  }
  res.redirect('/missions');
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
  const zoomLink = await getSetting('zoom_link');
  const zoomLabel = await getSetting('zoom_label');
  const nextMeeting = await get(`
    SELECT pm.*, l.name as lead_name, c.name as colead_name
    FROM prayer_meetings pm
    LEFT JOIN users l ON l.id = pm.lead_id
    LEFT JOIN users c ON c.id = pm.colead_id
    WHERE pm.meeting_date >= date('now')
    ORDER BY pm.meeting_date ASC
    LIMIT 1
  `, []);
  res.render('prayer', { requests, zoomLink, zoomLabel, nextMeeting });
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
