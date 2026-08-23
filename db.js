const { createClient } = require('@libsql/client');
const path = require('path');
const fs = require('fs');

// En production (Render) : TURSO_DATABASE_URL et TURSO_AUTH_TOKEN sont definis
// dans les variables d'environnement (base de donnees Turso, gratuite et persistante).
// En local (developpement) : si ces variables sont absentes, on utilise un fichier
// SQLite local pour pouvoir tester sans compte Turso.
if (!process.env.TURSO_DATABASE_URL) {
  const dataDir = path.join(__dirname, 'data');
  if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
}

const db = createClient(
  process.env.TURSO_DATABASE_URL
    ? { url: process.env.TURSO_DATABASE_URL, authToken: process.env.TURSO_AUTH_TOKEN }
    : { url: 'file:./data/evangelisation.db' }
);

async function initDb() {
  await db.batch([
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      church TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`,
    `CREATE TABLE IF NOT EXISTS souls (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      phone TEXT,
      city TEXT,
      location TEXT,
      status TEXT NOT NULL DEFAULT 'nouvelle_ame',
      notes TEXT,
      met_date TEXT NOT NULL DEFAULT (date('now')),
      created_by INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      last_contacted_at TEXT,
      FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE
    )`,
    `CREATE TABLE IF NOT EXISTS message_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      soul_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      content TEXT NOT NULL,
      channel TEXT NOT NULL DEFAULT 'sms',
      sent_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (soul_id) REFERENCES souls(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )`,
    `CREATE TABLE IF NOT EXISTS prayer_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      content TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      answered INTEGER NOT NULL DEFAULT 0,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )`,
    `CREATE TABLE IF NOT EXISTS prayer_supports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      prayer_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE(prayer_id, user_id),
      FOREIGN KEY (prayer_id) REFERENCES prayer_requests(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )`,
    `CREATE TABLE IF NOT EXISTS announcements (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      content TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )`,
    `CREATE TABLE IF NOT EXISTS soul_status_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      soul_id INTEGER NOT NULL,
      old_status TEXT,
      new_status TEXT NOT NULL,
      changed_by INTEGER NOT NULL,
      changed_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (soul_id) REFERENCES souls(id) ON DELETE CASCADE,
      FOREIGN KEY (changed_by) REFERENCES users(id) ON DELETE CASCADE
    )`,
    `CREATE TABLE IF NOT EXISTS reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      report_date TEXT NOT NULL DEFAULT (date('now')),
      location TEXT,
      presence TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )`,
    `CREATE TABLE IF NOT EXISTS report_people (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      report_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      notes TEXT,
      evangelized INTEGER NOT NULL DEFAULT 0,
      saved INTEGER NOT NULL DEFAULT 0,
      phone TEXT,
      invited_church INTEGER NOT NULL DEFAULT 0,
      soul_id INTEGER,
      FOREIGN KEY (report_id) REFERENCES reports(id) ON DELETE CASCADE,
      FOREIGN KEY (soul_id) REFERENCES souls(id) ON DELETE SET NULL
    )`,
    `CREATE TABLE IF NOT EXISTS goals (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      metric TEXT NOT NULL,
      period_type TEXT NOT NULL,
      target INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE(user_id, metric),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )`,
    `CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT,
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`,
    `CREATE TABLE IF NOT EXISTS prayer_meetings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      meeting_date TEXT NOT NULL,
      topic TEXT,
      lead_id INTEGER,
      colead_id INTEGER,
      created_by INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (lead_id) REFERENCES users(id) ON DELETE SET NULL,
      FOREIGN KEY (colead_id) REFERENCES users(id) ON DELETE SET NULL,
      FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE
    )`,
    `CREATE TABLE IF NOT EXISTS house_cells (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      neighborhood TEXT NOT NULL,
      meeting_day TEXT,
      meeting_time TEXT,
      description TEXT,
      pilot_name TEXT NOT NULL,
      pilot_phone TEXT NOT NULL,
      copilot_name TEXT,
      copilot_phone TEXT,
      active INTEGER NOT NULL DEFAULT 1,
      created_by INTEGER,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
    )`,
    `CREATE TABLE IF NOT EXISTS field_checkins (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      neighborhood TEXT NOT NULL,
      started_at TEXT NOT NULL DEFAULT (datetime('now')),
      ended_at TEXT,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )`,
    `CREATE TABLE IF NOT EXISTS planned_outings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      outing_date TEXT NOT NULL,
      location TEXT NOT NULL,
      notes TEXT,
      created_by INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE
    )`,
    `CREATE TABLE IF NOT EXISTS outing_participants (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      outing_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE(outing_id, user_id),
      FOREIGN KEY (outing_id) REFERENCES planned_outings(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )`,
    `CREATE TABLE IF NOT EXISTS cell_participants (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      cell_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE(cell_id, user_id),
      FOREIGN KEY (cell_id) REFERENCES house_cells(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )`,
    `CREATE TABLE IF NOT EXISTS cell_reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      cell_id INTEGER NOT NULL,
      reported_by INTEGER NOT NULL,
      meeting_date TEXT NOT NULL DEFAULT (date('now')),
      attendance_count INTEGER,
      note TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (cell_id) REFERENCES house_cells(id) ON DELETE CASCADE,
      FOREIGN KEY (reported_by) REFERENCES users(id) ON DELETE CASCADE
    )`
  ], 'write');

  // Ajout des colonnes necessaires a la reinitialisation de mot de passe par email.
  // Comme la table "users" existe deja en production (Turso), on ne peut pas
  // simplement la recreer : on ajoute les colonnes une par une, et on ignore
  // l'erreur si elles existent deja (c'est le cas apres le tout premier deploiement
  // de cette fonctionnalite).
  const alterations = [
    "ALTER TABLE users ADD COLUMN reset_token TEXT",
    "ALTER TABLE users ADD COLUMN reset_token_expires TEXT",
    "ALTER TABLE planned_outings ADD COLUMN neighborhood TEXT",
    "ALTER TABLE field_checkins ADD COLUMN lat REAL",
    "ALTER TABLE field_checkins ADD COLUMN lng REAL",
    "ALTER TABLE field_checkins ADD COLUMN position_updated_at TEXT",
    "ALTER TABLE users ADD COLUMN last_seen_outings_at TEXT",
    "ALTER TABLE users ADD COLUMN last_seen_prayer_at TEXT",
    "ALTER TABLE souls ADD COLUMN cell_id INTEGER"
  ];
  for (const sql of alterations) {
    try {
      await db.execute(sql);
    } catch (e) {
      // colonne deja existante : rien a faire
    }
  }
}

// Petits helpers pour ecrire des requetes proches du style precedent (better-sqlite3)
// mais version asynchrone (Turso/libsql fonctionne par promesses).
async function get(sql, args = []) {
  const rs = await db.execute({ sql, args });
  return rs.rows[0] || null;
}
async function all(sql, args = []) {
  const rs = await db.execute({ sql, args });
  return rs.rows;
}
async function run(sql, args = []) {
  const rs = await db.execute({ sql, args });
  return { lastInsertRowid: rs.lastInsertRowid, changes: rs.rowsAffected };
}

// --- Bibliotheque de versets / messages, integree en dur (pas besoin de table) ---
const VERSES = {
  encouragement: [
    { ref: "Jérémie 29:11", text: "Car je connais les projets que j'ai formés sur vous, dit l'Éternel, projets de paix et non de malheur, afin de vous donner un avenir et de l'espérance." },
    { ref: "Ésaïe 41:10", text: "Ne crains rien, car je suis avec toi ; ne prends pas d'inquiétude, car je suis ton Dieu ; je te fortifie, je viens à ton secours." },
    { ref: "Philippiens 4:13", text: "Je puis tout par celui qui me fortifie." },
    { ref: "Psaume 34:19", text: "L'Éternel est près de ceux qui ont le coeur brisé, et il sauve ceux qui ont l'esprit dans l'abattement." },
    { ref: "Romains 8:28", text: "Toutes choses concourent au bien de ceux qui aiment Dieu." }
  ],
  salut: [
    { ref: "Jean 3:16", text: "Car Dieu a tant aimé le monde qu'il a donné son Fils unique, afin que quiconque croit en lui ne périsse point, mais qu'il ait la vie éternelle." },
    { ref: "Romains 10:9", text: "Si tu confesses de ta bouche le Seigneur Jésus, et si tu crois dans ton coeur que Dieu l'a ressuscité des morts, tu seras sauvé." },
    { ref: "Actes 16:31", text: "Crois au Seigneur Jésus, et tu seras sauvé, toi et ta famille." },
    { ref: "Éphésiens 2:8-9", text: "C'est par la grâce que vous êtes sauvés, par le moyen de la foi. Et cela ne vient pas de vous, c'est le don de Dieu." }
  ],
  reconfort: [
    { ref: "Psaume 23:1-4", text: "L'Éternel est mon berger : je ne manquerai de rien. Quand je marche dans la vallée de l'ombre de la mort, je ne crains aucun mal, car tu es avec moi." },
    { ref: "Matthieu 11:28", text: "Venez à moi, vous tous qui êtes fatigués et chargés, et je vous donnerai du repos." },
    { ref: "2 Corinthiens 1:3-4", text: "Le Dieu de toute consolation, qui nous console dans toutes nos afflictions." }
  ],
  force_et_foi: [
    { ref: "Josué 1:9", text: "Fortifie-toi et prends courage, ne t'effraie point et ne t'épouvante point, car l'Éternel, ton Dieu, est avec toi partout où tu iras." },
    { ref: "Hébreux 11:1", text: "La foi est une ferme assurance des choses qu'on espère, une démonstration de celles qu'on ne voit pas." },
    { ref: "Marc 9:23", text: "Tout est possible à celui qui croit." }
  ]
};

module.exports = { db, initDb, get, all, run, VERSES };
