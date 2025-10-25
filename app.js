// app.js (ESM)
// ระบบยืม–คืนอุปกรณ์กีฬา + ฟิตเนส
// โครงนี้ใช้ Express + PostgreSQL + EJS + Session + Nodemailer

// ===== 1) imports =====
import express from 'express';
import path from 'path';
import pkg from 'pg';
import { fileURLToPath } from 'url';
import QRCode from 'qrcode';
import { randomUUID, createHash } from 'crypto';
import session from 'express-session';
import nodemailer from 'nodemailer';
import 'dotenv/config';
import cron from 'node-cron';


const { Pool } = pkg;

// ===== 2) PATH/APP BASICS =====
const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

const app  = express();
const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;

// ===== 3) STATIC FILES (serve /public ที่ root) =====
// ให้ไฟล์ /manifest.json, /sw.js, /icons/* ใช้พาธตรงจาก root
app.use(express.static(path.join(__dirname, 'public')));

// กำหนด MIME ของ manifest ให้ถูกต้อง (Chrome คาดหวัง application/manifest+json)
app.get('/manifest.json', (req, res) => {
  res.type('application/manifest+json');
  res.sendFile(path.join(__dirname, 'public', 'manifest.json'));
});

app.use((req, res, next) => {
  const role = (req.session?.user?.role || '').toLowerCase();
  const type = (req.session?.user?.type || '').toLowerCase();

  if (role === 'admin') {
    res.locals.manifestHref = '/manifest-admin.json';
    res.locals.themeColor   = '#dc3545';
  } else if (role === 'staff') {
    res.locals.manifestHref = '/manifest-staff.json';
    res.locals.themeColor   = '#198754';
  } else if (type === 'student' || type === 'external') {
    res.locals.manifestHref = '/manifest-user.json';
    res.locals.themeColor   = '#0d6efd';
  } else {
    res.locals.manifestHref = '/manifest.json'; // ก่อนล็อกอิน
    res.locals.themeColor   = '#0d6efd';
  }
  next();
});

// ===== 3) DB: create pool FIRST =====
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || undefined,
  user: process.env.PGUSER || 'postgres',
  host: process.env.PGHOST || 'localhost',
  database: process.env.PGDATABASE || 'projectdb',
  password: process.env.PGPASSWORD || '1234',
  port: Number(process.env.PGPORT || 5432),
  ssl: process.env.PGSSL === 'true' ? { rejectUnauthorized: false } : undefined
});

const sha256Hex = (s) => createHash('sha256').update(String(s)).digest('hex');

// ===== DEBUG WRAPPER: log SQL เมื่อ error =====
const _pgQuery = pool.query.bind(pool);
pool.query = async (text, params=[]) => {
  try { return await _pgQuery(text, params); }
  catch (e) {
    console.error('\n[PG ERROR]', e.code, e.message);
    console.error('SQL  :\n' + text);
    console.error('PARAM:', params);
    throw e;
  }
};

// === DB bootstrap: created_date + triggers + unique indexes + views ===
async function initDb() {
  await pool.query(`CREATE EXTENSION IF NOT EXISTS pgcrypto`);

await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS student_id_hash TEXT`);
await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS uq_users_sid_hash ON users(student_id_hash)`);

  // 1) created_date + trigger ให้ notifications
  await pool.query(`ALTER TABLE notifications ADD COLUMN IF NOT EXISTS created_date date`);
  await pool.query(`
    CREATE OR REPLACE FUNCTION set_created_date()
    RETURNS trigger AS $$
    BEGIN
      NEW.created_date := COALESCE(NEW.created_at::date, CURRENT_DATE);
      RETURN NEW;
    END;
    $$ LANGUAGE plpgsql;
  `);
  await pool.query(`DROP TRIGGER IF EXISTS trg_set_created_date ON notifications`);
  await pool.query(`
    CREATE TRIGGER trg_set_created_date
    BEFORE INSERT ON notifications
    FOR EACH ROW
    EXECUTE FUNCTION set_created_date()
  `);
  await pool.query(`UPDATE notifications SET created_date = created_at::date WHERE created_date IS NULL`);

  // 2) unique กันซ้ำรายวัน (ref/type/date)
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS uq_notif_daily
      ON notifications ((meta->>'ref'), type, created_date)
      WHERE type IN ('overdue_student','overdue_faculty','overdue_staff_2_6')
  `);

  // 3) unique กันแจ้งซ้ำต่อรายการฝั่ง staff
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS uq_notif_once_idx
      ON notifications (user_id, type, (meta->>'ref'))
      WHERE (meta->>'ref') IS NOT NULL
  `);

  // 3.1) บังคับ overdue_student ได้เพียง "ครั้งเดียว" ต่อ tx (meta.ref)
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS uq_notif_overdue_student_once
      ON notifications ((meta->>'ref'))
      WHERE type = 'overdue_student'
  `);

  // 4) ธง escalated_at ใน transactions
  await pool.query(`ALTER TABLE transactions ADD COLUMN IF NOT EXISTS escalated_at timestamptz`);

  // 4.1) วันที่ "นัดคืน" ที่บันทึกไว้ (optional)
  await pool.query(`ALTER TABLE transactions ADD COLUMN IF NOT EXISTS promised_return_date date`);

  // 5) ตาราง hold
  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_holds (
      id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      reason      text NOT NULL,
      created_at  timestamptz NOT NULL DEFAULT now(),
      cleared_at  timestamptz
    )
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS ix_user_holds_active
      ON user_holds(user_id)
      WHERE cleared_at IS NULL
  `);
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS uq_user_holds_one_active
      ON user_holds(user_id)
      WHERE cleared_at IS NULL
  `);

  // 6) ตารางคืนบางส่วน (ถ้ายังไม่มี)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS transaction_returns (
      id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      transaction_id uuid NOT NULL REFERENCES transactions(id) ON DELETE CASCADE,
      return_qty     int  NOT NULL CHECK (return_qty > 0),
      note           text,
      created_at     timestamptz NOT NULL DEFAULT now()
    )
  `);

  // 7) Views: overdue 2–6 และ 7+
  await pool.query(`
    DROP VIEW IF EXISTS overdue_2_6_days CASCADE;
    CREATE VIEW overdue_2_6_days AS
    SELECT
      t.id AS tx_id,
      t.user_id,
      t.inventory_id,
      t.qty,
      i.item_name,
      (CURRENT_DATE - t.borrow_date::date) AS days_overdue
    FROM transactions t
    JOIN inventory i ON i.id = t.inventory_id
    WHERE t.return_date IS NULL
      AND (CURRENT_DATE - t.borrow_date::date) BETWEEN 2 AND 6;
  `);

  await pool.query(`
    DROP VIEW IF EXISTS overdue_7_plus CASCADE;
    CREATE VIEW overdue_7_plus AS
    SELECT
      t.id AS tx_id,
      t.user_id,
      t.inventory_id,
      t.qty,
      i.item_name,
      (CURRENT_DATE - t.borrow_date::date) AS days_overdue
    FROM transactions t
    JOIN inventory i ON i.id = t.inventory_id
    WHERE t.return_date IS NULL
      AND (CURRENT_DATE - t.borrow_date::date) >= 7;
  `);

  // 8) View: รายการคงค้างรายธุรกรรม (เหลือคืนเท่าไร) + นัดคืน
  await pool.query(`
    DROP VIEW IF EXISTS v_tx_outstanding CASCADE;
    CREATE VIEW v_tx_outstanding AS
    SELECT
      t.id                AS tx_id,
      t.user_id,
      t.inventory_id,
      i.item_name,
      t.borrow_date,
      t.promised_return_date,
      t.qty               AS borrowed_qty,
      COALESCE((
        SELECT SUM(tr.return_qty) FROM transaction_returns tr
        WHERE tr.transaction_id = t.id
      ),0)                AS returned_qty,
      GREATEST(t.qty - COALESCE((
        SELECT SUM(tr.return_qty) FROM transaction_returns tr
        WHERE tr.transaction_id = t.id
      ),0), 0)            AS outstanding_qty
    FROM transactions t
    JOIN inventory i ON i.id = t.inventory_id
    WHERE t.return_date IS NULL
      AND (t.qty - COALESCE((
        SELECT SUM(tr.return_qty) FROM transaction_returns tr
        WHERE tr.transaction_id = t.id
      ),0)) > 0
    ORDER BY t.borrow_date ASC;
  `);

  // 9) View: คงเหลือที่ยืมใหม่ได้จริงของแต่ละอุปกรณ์
  await pool.query(`
    DROP VIEW IF EXISTS v_inventory_available CASCADE;
    CREATE VIEW v_inventory_available AS
    SELECT
      i.id,
      i.item_name,
      i.stock AS physical_stock,
      COALESCE(SUM(v.outstanding_qty),0) AS outstanding_in_use,
      GREATEST(i.stock - COALESCE(SUM(v.outstanding_qty),0), 0) AS available_for_new_borrow
    FROM inventory i
    LEFT JOIN v_tx_outstanding v ON v.inventory_id = i.id
    GROUP BY i.id, i.item_name, i.stock
  `);
}

/* =========================
 * 3) EMAIL
 * ========================= */
const MAIL_FROM = process.env.MAIL_FROM || 'noreply@example.com';
const STAFF_ALERT_EMAIL = process.env.STAFF_ALERT_EMAIL || 'staff@example.com';

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: Number(process.env.SMTP_PORT || 465),
  secure: true,
  auth: {
    user: process.env.SMTP_USER || 'your@gmail.com',
    pass: process.env.SMTP_PASS || 'app-password-here'
  }
});

async function sendMail(to, subject, html) {
  try { await transporter.sendMail({ from: MAIL_FROM, to, subject, html }); }
  catch (e) { console.warn('sendMail error:', e?.message || e); }
}

// STAFF notification policy
const STAFF_ALLOWED_TYPES = new Set(
  (process.env.STAFF_ALLOWED_TYPES || 'overdue_staff,overdue_staff_2_6')
    .split(',').map(s => s.trim()).filter(Boolean)
);
/* =========================
 * 4) HELPERS
 * ========================= */

// ตรวจว่าเป็น UUID มาตรฐานหรือไม่
const isUUID = (s) =>
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    .test(String(s));

// normalizeCode: รับโค้ดจาก QR/URL/student_id/citizen_id/uuid ให้กลายเป็นค่าเดียวกัน
// ❗ แก้ให้ "ถ้าเป็น UUID" จะไม่ลบขีดกลาง (แก้ปัญหาลิงก์ /return?member=<uuid> หา member ไม่เจอ)
function normalizeCode(raw) {
  if (!raw) return '';
  let s = String(raw).trim();
  try { s = decodeURIComponent(s); } catch {}

  // ถ้าเป็น URL → ดึงค่าจาก ?member= หรือ segment สุดท้าย
  if (/^https?:\/\//i.test(s)) {
    try {
      const u = new URL(s);
      const m = (u.searchParams.get('member') || '').trim();
      if (m) return isUUID(m) ? m : m.replace(/\s+/g,'').replace(/-/g,''); // ถ้าเป็น UUID คืนเลย
      const last = (u.pathname.split('/').filter(Boolean).pop() || '').trim();
      if (last) return isUUID(last) ? last : last.replace(/\s+/g,'').replace(/-/g,'');
    } catch {}
  }
  // ถ้าเป็น UUID อยู่แล้ว → คืนเลย (อย่าลบขีด)
  if (isUUID(s)) return s;

  // ไม่ใช่ UUID: ลบช่องว่าง/ขีดกลาง สำหรับเลขบัตร/รหัสนักศึกษา
  s = s.replace(/\s+/g,'').replace(/-/g,'');

  // รองรับเลข 13/12 หลัก (บัตร/รหัส)
  const m13 = s.match(/\b\d{13}\b/); if (m13) return m13[0];
  const m12 = s.match(/\b\d{12}\b/); if (m12) return m12[0];

  return s;
}

async function findMemberByAny(raw) {
  if (!raw) return null;
  let code = normalizeCode(raw);
  const sql = `
  SELECT id, full_name, member_type, email, student_id, citizen_id, qr_code_value, faculty
    FROM users
   WHERE $1::text = id::text
      OR $1::text = COALESCE(qr_code_value,'')
      OR $1::text = COALESCE(student_id,'')
      OR $1::text = COALESCE(citizen_id,'')
   LIMIT 1
`;
  const r = await pool.query(sql, [code]);
  if (r.rowCount) return r.rows[0];

  // 🔁 Fallback: ลองเทียบ hash (ไม่แตะ SQL เดิม)
  try {
    const codeHash = sha256Hex(code);
    const r2 = await pool.query(
      `SELECT id, full_name, member_type, email, student_id, citizen_id, qr_code_value, faculty
         FROM users
        WHERE $1::text = COALESCE(student_id_hash,'')
        LIMIT 1`,
      [codeHash]
    );
    if (r2.rowCount) return r2.rows[0];
  } catch (_e) {}

  return null;
}

async function getUserById(idOrCode) {
  const r = await pool.query(
    `SELECT id, email, full_name, faculty, member_type, student_id, citizen_id, qr_code_value
       FROM users
      WHERE id::text = $1::text
   OR $1::text = COALESCE(student_id,'')
   OR  $1::text = COALESCE(citizen_id,'')
   OR  $1::text = COALESCE(qr_code_value,'')
      LIMIT 1`,
    [String(idOrCode)]
  );
  if (r.rowCount) return r.rows[0];

  // 🔁 Fallback: hash
  try {
    const codeHash = sha256Hex(String(idOrCode));
    const r2 = await pool.query(
      `SELECT id, email, full_name, faculty, member_type, student_id, citizen_id, qr_code_value
         FROM users
        WHERE $1::text = COALESCE(student_id_hash,'')
        LIMIT 1`,
      [codeHash]
    );
    if (r2.rowCount) return r2.rows[0];
  } catch (_e) {}

  return null;
}


async function pushNotif(userIdOrCode, type, title, message, meta = null) {
  let uid = null;
  if (isUUID(userIdOrCode)) uid = userIdOrCode;
  else {
    const u = await getUserById(userIdOrCode);
    uid = u?.id || null;
  }
  if (!uid) { console.warn('pushNotif: cannot resolve', userIdOrCode); return; }

  await pool.query(
    `INSERT INTO notifications (user_id, type, title, message, meta)
     VALUES ($1::uuid, $2, $3, $4, $5::jsonb)
     ON CONFLICT DO NOTHING`,
    [uid, type, title, message, meta ? JSON.stringify(meta) : null]
  );
}

async function notifyUser({ userIdOrCode, type, title, message, meta, emailSubject, emailHtml }) {
  const u = await getUserById(userIdOrCode);
  if (!u) return;
  try { await pushNotif(u.id, type, title, message, meta); }
  catch (e) { console.warn('notifyUser in-app error', e?.message || e); }
  if (u.email && emailSubject) {
    await sendMail(u.email, emailSubject, emailHtml || `<p>${message}</p>`);
  }
}

async function hasActiveHold(userId) {
  const r = await pool.query(
    `SELECT 1 FROM user_holds WHERE user_id = $1::uuid AND cleared_at IS NULL LIMIT 1`,
    [userId]
  );
  return r.rowCount > 0;
}

async function clearActiveHolds(userId, note='') {
  const r = await pool.query(
    `UPDATE user_holds
        SET cleared_at = now(),
            reason = COALESCE(reason,'') ||
                     CASE WHEN $2::text <> '' THEN ' | cleared: '||$2 ELSE '' END
      WHERE user_id = $1::uuid
        AND cleared_at IS NULL
      RETURNING id`,
    [userId, note]
  );
  return r.rowCount > 0;
}

async function hasOpenTransactions(userId) {
  const r = await pool.query(
    `SELECT 1
       FROM transactions
      WHERE user_id = $1::uuid
        AND return_date IS NULL
      LIMIT 1`,
    [userId]
  );
  return r.rowCount > 0;
}

async function pushNotifOnce(userId, type, title, message, meta = null) {
  if (!userId) return;
  const metaJson = meta ? JSON.stringify(meta) : null;

  try {
    await pool.query(
      `INSERT INTO notifications (user_id, type, title, message, meta)
       VALUES ($1::uuid, $2, $3, $4, $5::jsonb)`,
      [userId, type, title, message, metaJson]
    );
  } catch (e) {
    if (e?.code === '23505') return;
    throw e;
  }
}

async function notifyStaff({ type, title, message, meta, emailSubject, emailHtml }) {
  try {
    if (!STAFF_ALLOWED_TYPES.has(type)) return;

    const staffRows = (await pool.query(
      `SELECT u.id, u.email
         FROM users u
         JOIN roles r ON r.id = u.role_id
        WHERE r.name IN ('staff','admin')`
    )).rows;

    for (const s of staffRows) {
      await pushNotifOnce(s.id, type, title, message, meta);
      if (s.email && emailSubject) {
        await sendMail(s.email, emailSubject, emailHtml || `<p>${message}</p>`);
      }
    }

    if (STAFF_ALERT_EMAIL && emailSubject) {
      await sendMail(STAFF_ALERT_EMAIL, emailSubject, emailHtml || `<p>${message}</p>`);
    }
  } catch (e) {
    console.warn('notifyStaff error', e?.message || e);
  }
}

// ===== ปรับฟังก์ชัน getHistoryData =====
// รวมข้อมูลประวัติ Borrow/Return + Fitness โดยกรองตาม user / ช่วงวัน
async function getHistoryData({ userId = null, from = null, to = null }) {
  const wT = [], pT = [];
  if (userId) { pT.push(userId); wT.push(`t.user_id = $${pT.length}::uuid`); }
  if (from)   { pT.push(from);   wT.push(`t.borrow_date >= $${pT.length}::date`); }
  if (to)     { pT.push(to);     wT.push(`t.borrow_date <= $${pT.length}::date`); }

  const sqlBorrow = `
    SELECT
      t.id,
      t.user_id,                             -- ใช้เช็ค hold/flag อื่นๆ
      u.full_name, u.member_type, u.student_id, u.citizen_id,
      i.item_name,
      t.qty,
      -- ✅ รวมคืนแล้วต่อรายการ
      COALESCE((
        SELECT SUM(tr.return_qty) FROM transaction_returns tr
        WHERE tr.transaction_id = t.id
      ),0) AS returned_qty,
      -- ✅ เหลือคืนต่อรายการ
      GREATEST(
        t.qty - COALESCE((
          SELECT SUM(tr.return_qty) FROM transaction_returns tr
          WHERE tr.transaction_id = t.id
        ),0),
      0) AS remaining_qty,
      t.borrow_date, t.return_date,
      t.escalated_at,
      t.promised_return_date,
      (CURRENT_DATE - t.borrow_date::date) AS days_overdue
    FROM transactions t
    LEFT JOIN users u     ON u.id = t.user_id
    LEFT JOIN inventory i ON i.id = t.inventory_id
    ${wT.length ? 'WHERE ' + wT.join(' AND ') : ''}
    ORDER BY t.borrow_date DESC, t.created_at DESC NULLS LAST
  `;
  const borrowRows = (await pool.query(sqlBorrow, pT)).rows;

  // === เติม flags ===
  const txIds = borrowRows.map(r => r.id);
  const userIds = [...new Set(borrowRows.map(r => r.user_id))];

  // 1) เคยแจ้งนักศึกษามาก่อนหรือยัง (type: overdue_student, meta.ref = tx_id)
  let notifiedEver = new Set();
  if (txIds.length) {
    const q1 = await pool.query(
      `SELECT (meta->>'ref') AS ref
         FROM notifications
        WHERE type='overdue_student'
          AND (meta->>'ref') = ANY($1::text[])`,
      [txIds]
    );
    notifiedEver = new Set(q1.rows.map(r => r.ref));
  }

  // 2) ใครมี hold ค้างอยู่ตอนนี้
  let holdSet = new Set();
  if (userIds.length) {
    const q2 = await pool.query(
      `SELECT user_id
         FROM user_holds
        WHERE cleared_at IS NULL
          AND user_id = ANY($1::uuid[])`,
      [userIds]
    );
    holdSet = new Set(q2.rows.map(r => r.user_id));
  }

  // แนบ flag ลงแถว
  for (const r of borrowRows) {
    r.notified_ever   = notifiedEver.has(r.id);
    r.has_active_hold = holdSet.has(r.user_id);
  }

  // === Fitness ===
  const wF = [], pF = [];
  if (userId) { pF.push(userId); wF.push(`f.user_id = $${pF.length}::uuid`); }
  if (from)   { pF.push(from);   wF.push(`f.visit_date >= $${pF.length}::date`); }
  if (to)     { pF.push(to);     wF.push(`f.visit_date <= $${pF.length}::date`); }

  const sqlFit = `
    SELECT
      f.id, u.full_name, u.member_type, u.student_id, u.citizen_id,
      f.visit_date, f.amount, f.pay_method
    FROM fitness_visits f
    LEFT JOIN users u ON u.id = f.user_id
    ${wF.length ? 'WHERE ' + wF.join(' AND ') : ''}
    ORDER BY f.visit_date DESC, f.created_at DESC
  `;
  const fitnessRows = (await pool.query(sqlFit, pF)).rows;

  return { borrowRows, fitnessRows };
}

// ===== 4) VIEW ENGINE =====
app.set('view engine', 'ejs');
app.set('views', [
  path.join(__dirname, 'views'),
  path.join(__dirname, 'views/member'),
  path.join(__dirname, 'views/staff'),
  path.join(__dirname, 'views/admin'),
]);
app.locals.basedir = path.join(__dirname, 'views');

// ===== 5) BODY & SESSION =====
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: process.env.SESS_SECRET || 'CHANGE_ME_SECRET',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000*60*60*24*7 }
}));
app.set('trust proxy', 1);

app.use((req, res, next) => {
  res.locals.user = req.session?.user || null;
  next();
});

/* =========================
 * 6) AUTH MIDDLEWARES
 * ========================= */
function isStaff(req, res, next) {
  const role = (req.session?.user?.role || '').toLowerCase();
  if (role === 'staff' || role === 'admin') return next();
  return res.redirect('/staff-login');
}

function requireMember(req, res, next) {
  const t = (req.session?.user?.type || '').toLowerCase();
  if (t === 'student' || t === 'external') return next();
  return res.redirect('/login');
}

function redirectIfLoggedIn(req, res, next) {
  const u = req.session?.user;
  if (!u) return next();
  const role = (u.role || '').toLowerCase();
  const t    = (u.type || '').toLowerCase();
  if (role === 'staff' || role === 'admin') return res.redirect('/staff-home');
  return res.redirect(t === 'student' ? '/student-home' : '/external-home');
}

// ===== เพิ่มกลาง AUTH MIDDLEWARES =====
function isAdmin(req, res, next) {
  const role = (req.session?.user?.role || '').toLowerCase();
  if (role === 'admin') return next();
  return res.redirect('/admin-login'); // ถ้าไม่ใช่ admin ให้ไปหน้า login แอดมิน
}

// (ออปชัน) ถ้าใช้ในหน้า /admin-login เพื่อกันคนที่ล็อกอินแอดมินแล้วไม่ให้เห็นฟอร์มซ้ำ
function redirectIfAdminLoggedIn(req, res, next) {
  const role = (req.session?.user?.role || '').toLowerCase();
  if (role === 'admin') return res.redirect('/admin-home');
  return next();
}

/* =========================
 * 7) STAFF LOGIN (DEMO)
 * ========================= */
app.get('/staff-login', (req, res) => res.render('staff-login', { error: null }));

app.post('/staff-login', async (req, res) => {
  const { email } = req.body || {};
  const sql = `
    SELECT u.id, u.full_name, r.name AS role
    FROM users u
    JOIN roles r ON r.id = u.role_id
    WHERE LOWER(u.email) = LOWER($1) AND r.name IN ('staff','admin')
    LIMIT 1
  `;
  const r = await pool.query(sql, [email]);
  if (!r.rowCount) return res.render('staff-login', { error: 'ไม่มีสิทธิ์หรืออีเมลไม่ถูกต้อง' });

  const row = r.rows[0];
  req.session.regenerate((err) => {
    if (err) return res.render('staff-login', { error: 'เกิดข้อผิดพลาดของเซสชัน' });
    req.session.user   = { id: row.id, name: row.full_name, role: row.role };
    req.session.userId = row.id;
    return res.redirect('/staff-home');
  });
});

/* =========================
 * ADMIN LOGIN
 * ========================= */
app.get('/admin-login', redirectIfAdminLoggedIn, (req, res) => {
  res.render('admin-login', { error: null });
});

app.post('/admin-login', async (req, res) => {
  try {
    const email = (req.body.email || '').trim();
    if (!email) return res.render('admin-login', { error: 'กรอกอีเมลให้ครบ' });

    const r = await pool.query(`
      SELECT u.id, u.full_name, r.name AS role
      FROM users u
      JOIN roles r ON r.id = u.role_id
      WHERE LOWER(u.email) = LOWER($1) AND r.name = 'admin'
      LIMIT 1
    `, [email]);

    if (!r.rowCount) {
      return res.render('admin-login', { error: 'ไม่มีสิทธิ์แอดมินหรืออีเมลไม่ถูกต้อง' });
    }

    const row = r.rows[0];
    req.session.regenerate((err) => {
      if (err) return res.render('admin-login', { error: 'เกิดข้อผิดพลาดของเซสชัน' });
      req.session.user   = { id: row.id, name: row.full_name, role: row.role };
      req.session.userId = row.id;
      return res.redirect('/admin-home');
    });
  } catch (e) {
    console.error('POST /admin-login error:', e);
    return res.render('admin-login', { error: 'เกิดข้อผิดพลาด กรุณาลองใหม่' });
  }
});

/* =========================
 * ADMIN HOME (Dashboard)
 * ========================= */
app.get('/admin-home', isAdmin, async (req, res) => {
  try {
    // ตัวเลขสรุป (เบาๆ พอใช้งาน)
    const [{ rows: uAll }, { rows: uStu }, { rows: uStaff }, { rows: uAdmin }] = await Promise.all([
      pool.query(`SELECT COUNT(*)::int AS c FROM users`),
      pool.query(`SELECT COUNT(*)::int AS c FROM users WHERE member_type='student'`),
      pool.query(`SELECT COUNT(*)::int AS c FROM users u JOIN roles r ON r.id=u.role_id WHERE r.name='staff'`),
      pool.query(`SELECT COUNT(*)::int AS c FROM users u JOIN roles r ON r.id=u.role_id WHERE r.name='admin'`)
    ]);

    const [{ rows: invAct }, { rows: outAll }, { rows: over2_6 }, { rows: over7plus }, { rows: holds }] = await Promise.all([
      pool.query(`SELECT COUNT(*)::int AS c FROM inventory WHERE active=true`),
      pool.query(`SELECT COUNT(*)::int AS c FROM v_tx_outstanding`),
      pool.query(`SELECT COUNT(*)::int AS c FROM overdue_2_6_days`),
      pool.query(`SELECT COUNT(*)::int AS c FROM overdue_7_plus`),
      pool.query(`SELECT COUNT(*)::int AS c FROM user_holds WHERE cleared_at IS NULL`)
    ]);

    // ดึง top 10 งานเร่งด่วน (7+ วัน)
    const urgent = (await pool.query(`
      SELECT o.tx_id, o.user_id, i.item_name, t.qty,
             (CURRENT_DATE - t.borrow_date::date) AS days_overdue
      FROM overdue_7_plus o
      JOIN transactions t ON t.id = o.tx_id
      JOIN inventory i    ON i.id = o.inventory_id
      ORDER BY days_overdue DESC
      LIMIT 10
    `)).rows;

    // ดึงรายการ “นัดคืนวันนี้” (promised_return_date = วันนี้)
    const promisedToday = (await pool.query(`
      SELECT t.id AS tx_id, u.full_name, i.item_name, t.qty, t.borrow_date
      FROM transactions t
      JOIN users u ON u.id=t.user_id
      JOIN inventory i ON i.id=t.inventory_id
      WHERE t.return_date IS NULL
        AND t.promised_return_date = CURRENT_DATE
      ORDER BY t.borrow_date ASC
      LIMIT 20
    `)).rows;

    res.render('admin-home', {
      stats: {
        usersTotal: uAll[0].c,
        usersStudent: uStu[0].c,
        usersStaff: uStaff[0].c,
        usersAdmin: uAdmin[0].c,
        invActive: invAct[0].c,
        outstanding: outAll[0].c,
        overdue2_6: over2_6[0].c,
        overdue7plus: over7plus[0].c,
        holds: holds[0].c
      },
      urgent, promisedToday,
      me: req.session.user
    });
  } catch (e) {
    console.error('GET /admin-home error:', e);
    res.status(500).send('โหลด Dashboard ไม่สำเร็จ');
  }
});

// === Admin: User management ===
app.get('/admin/users', isAdmin, async (req, res) => {
  const q = await pool.query(`
    SELECT u.id, u.full_name, u.email, u.member_type, u.created_at,
           r.name AS role
    FROM users u
    LEFT JOIN roles r ON r.id = u.role_id
    ORDER BY u.created_at DESC
    LIMIT 200
  `);
  const roles = (await pool.query(`SELECT id, name FROM roles ORDER BY id`)).rows;
  res.render('admin-users', { users: q.rows, roles, ok: req.query.ok || null, err: req.query.err || null });
});

// สร้างผู้ใช้ Staff/Admin เร็วๆ (ไม่ใช้รหัสผ่าน)
app.post('/admin/users/create', isAdmin, async (req, res) => {
  const { email='', full_name='', role='staff' } = req.body || {};
  const roleName = (role || '').toLowerCase(); // 'staff' | 'admin'
  try {
    const rRole = await pool.query(`SELECT id FROM roles WHERE name = $1 LIMIT 1`, [roleName]);
    if (!rRole.rowCount) return res.redirect('/admin/users?err=role_not_found');

    await pool.query(`
      INSERT INTO users (id, role_id, member_type, email, full_name)
      VALUES (gen_random_uuid(), $1, $2, $3, $4)
    `, [rRole.rows[0].id, roleName, email.trim(), full_name.trim()]);
    return res.redirect('/admin/users?ok=created');
  } catch (e) {
    console.error('admin create user error:', e);
    return res.redirect('/admin/users?err=dup_or_invalid');
  }
});

// เปลี่ยนสิทธิ์ (promote/demote)
app.post('/admin/users/:id/role', isAdmin, async (req, res) => {
  const id = (req.params.id||'').trim();
  const roleName = (req.body.role||'').toLowerCase(); // 'student'|'external'|'staff'|'admin'
  try {
    const rRole = await pool.query(`SELECT id FROM roles WHERE name=$1 LIMIT 1`, [roleName]);
    if (!rRole.rowCount) return res.redirect('/admin/users?err=role_not_found');
    await pool.query(`UPDATE users SET role_id=$2, member_type=$3 WHERE id=$1::uuid`, [id, rRole.rows[0].id, roleName]);
    return res.redirect('/admin/users?ok=role_updated');
  } catch (e) {
    console.error('admin change role error:', e);
    return res.redirect('/admin/users?err=update_failed');
  }
});

// (ตัวเลือก) ลบผู้ใช้
app.post('/admin/users/:id/delete', isAdmin, async (req, res) => {
  const id = (req.params.id||'').trim();
  try {
    await pool.query(`DELETE FROM users WHERE id=$1::uuid`, [id]);
    return res.redirect('/admin/users?ok=deleted');
  } catch (e) {
    console.error('admin delete user error:', e);
    return res.redirect('/admin/users?err=delete_failed');
  }
});

/* =========================
 * 8) BASIC PAGES
 * ========================= */
app.get('/', redirectIfLoggedIn, (req, res) => res.render('index'));
app.get('/register/student',  redirectIfLoggedIn, (req, res) => res.render('register-student'));
app.get('/register/external', redirectIfLoggedIn, (req, res) => res.render('register-external'));
app.get('/inventory', isStaff, (req, res) => res.redirect('/staff/inventory'));

app.get('/staff-home', isStaff, async (req, res) => {
  // ดึงอีเมลของผู้ใช้ปัจจุบัน
  let userEmail = '';
  try {
    const meId = req.session?.user?.id;
    if (meId) {
      const r = await pool.query(
        'SELECT email FROM users WHERE id = $1::uuid LIMIT 1',
        [meId]
      );
      userEmail = r.rows[0]?.email || '';
    }
  } catch (e) {
    console.warn('get email failed:', e.message);
  }

  const inv = (await pool.query(
    'SELECT id, item_name, stock, active FROM inventory ORDER BY item_name'
  )).rows;

  res.render('staff-home', {
    user: req.session.user,
    userEmail,           // << ส่งไปให้ EJS
    inventory: inv
  });
});


/* =========================
 * 9) Notifications API
 * ========================= */
app.get('/api/notifications', async (req, res) => {
  const userId = req.session?.userId || req.session?.user?.id;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });

  const limit = Math.min(parseInt(req.query.limit || '20', 10), 100);
  const since = req.query.since ? new Date(req.query.since) : null;

  const roleLike = (req.session?.user?.role || req.session?.user?.type || req.session?.user?.member_type || '').toLowerCase();
  const viewerIsStaff = roleLike === 'staff' || roleLike === 'admin';
  const allowedTypes = Array.from(STAFF_ALLOWED_TYPES);

  try {
    let rows;
    if (viewerIsStaff) {
      if (since && !isNaN(since)) {
        const r = await pool.query(
          `SELECT id, type, title, message, meta, created_at, read_at
             FROM notifications
            WHERE user_id = $1::uuid
              AND created_at >= ($2::timestamptz - interval '5 seconds')
              AND type = ANY($3::text[])
            ORDER BY created_at DESC
            LIMIT $4::int`,
          [userId, since.toISOString(), allowedTypes, limit]
        );
        rows = r.rows;
      } else {
        const r = await pool.query(
          `SELECT id, type, title, message, meta, created_at, read_at
             FROM notifications
            WHERE user_id = $1::uuid
              AND type = ANY($2::text[])
            ORDER BY created_at DESC
            LIMIT $3::int`,
          [userId, allowedTypes, limit]
        );
        rows = r.rows;
      }
    } else {
      if (since && !isNaN(since)) {
        const r = await pool.query(
          `SELECT id, type, title, message, meta, created_at, read_at
             FROM notifications
            WHERE user_id = $1::uuid
              AND created_at >= ($2::timestamptz - interval '5 seconds')
            ORDER BY created_at DESC
            LIMIT $3::int`,
          [userId, since.toISOString(), limit]
        );
        rows = r.rows;
      } else {
        const r = await pool.query(
          `SELECT id, type, title, message, meta, created_at, read_at
             FROM notifications
            WHERE user_id = $1::uuid
            ORDER BY created_at DESC
            LIMIT $2::int`,
          [userId, limit]
        );
        rows = r.rows;
      }
    }

    res.json({ items: rows, now: new Date().toISOString() });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/notifications/mark-read', async (req, res) => {
  const userId = req.session?.userId || req.session?.user?.id;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });
  const ids = Array.isArray(req.body?.ids) ? req.body.ids : [];
  if (ids.length === 0) return res.json({ ok: true });

  try {
    await pool.query(
      `UPDATE notifications
          SET read_at = now()
        WHERE user_id = $1::uuid
          AND id = ANY($2::uuid[])
          AND read_at IS NULL`,
      [userId, ids]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

// =========================
// Notifications API: แจ้งเตือนค้างคืน (นักศึกษา)
// =========================
async function handleOverdueStudent(req, res) {
  try {
    const { tx_id } = req.body;

    const q = await pool.query(`
      SELECT t.id, t.user_id, t.borrow_date, t.return_date, t.qty,
             i.item_name,
             (CURRENT_DATE - t.borrow_date::date) AS days_overdue
      FROM transactions t
      JOIN inventory i ON i.id = t.inventory_id
      WHERE t.id::text = $1::text
      LIMIT 1
    `, [tx_id]);

    if (!q.rowCount)   return res.status(404).json({ error: 'not found' });
    const r = q.rows[0];
    if (r.return_date) return res.status(400).json({ error: 'already returned' });

    const d = Number(r.days_overdue || 0);
    if (d < 2)         return res.status(400).json({ error: 'not overdue enough' });

    const msg = `รายการยืม ${r.item_name} เกินกำหนดมาแล้ว ${d} วัน กรุณานำมาคืน`;

    try {
      await pool.query(`
        INSERT INTO notifications (user_id, type, title, message, meta)
        VALUES (
          $1::uuid,
          'overdue_student',
          'เกินกำหนดต้องคืนอุปกรณ์',
          $2::text,
          jsonb_build_object(
            'ref', $3::text,
            'days_overdue', $4::int,
            'item', $5::text,
            'qty', $6::int
          )
        )
      `, [r.user_id, msg, r.id, d, r.item_name, r.qty]);
      return res.json({ ok: true, status: 'inserted' });
    } catch (e) {
      if (e?.code === '23505') {
        return res.status(409).json({ ok: false, status: 'already' });
      }
      throw e;
    }
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
}

app.post('/api/notifications/overdue/student', isStaff, handleOverdueStudent);
app.post('/notifications/overdue/student',    isStaff, handleOverdueStudent);

/* =========================
 * 10) BORROW FLOW
 * ========================= */
app.get('/borrow', isStaff, async (req, res) => {
  try {
    const success = (req.query.success || '').trim();
    const tx      = (req.query.tx || '').trim();
    const raw     = (req.query.member || '').trim();
    if (!raw) return res.redirect('/staff-home');

    const m = await findMemberByAny(raw);
    if (!m) {
      return res.render('borrow', {
        member: null, loans: [], inventory: [], message: 'ไม่พบข้อมูลสมาชิก',
        success, tx, blockBorrow: false
      });
    }

    const loans = (await pool.query(
      `SELECT i.item_name AS name, t.qty, t.borrow_date
         FROM transactions t
         JOIN inventory i ON i.id = t.inventory_id
        WHERE t.user_id = $1::uuid
          AND t.return_date IS NULL
        ORDER BY t.borrow_date DESC`,
      [m.id]
    )).rows;

    let blockBorrow = false;
    if (m.member_type === 'student') {
      const chk = await pool.query(
        `SELECT 1 FROM v_tx_outstanding 
          WHERE user_id = $1::uuid AND outstanding_qty > 0 LIMIT 1`,
        [m.id]
      );
      blockBorrow = chk.rowCount > 0;
    }

    const inventory = blockBorrow ? [] : (await pool.query(
      `SELECT id, item_name AS name, stock
         FROM inventory
        WHERE active = TRUE AND stock > 0
        ORDER BY item_name ASC`
    )).rows;

    return res.render('borrow', {
      member: m, loans, inventory,
      message: blockBorrow ? 'นโยบาย: นักศึกษาต้องคืนของเดิมก่อน จึงจะยืมรายการใหม่ได้' : null,
      success, tx, blockBorrow
    });
  } catch (e) {
    console.error('GET /borrow error:', e);
    return res.render('borrow', {
      member: null, loans: [], inventory: [], message: 'เกิดข้อผิดพลาดในการโหลดหน้า',
      success: '', tx: '', blockBorrow: false
    });
  }
});

// ยืมอุปกรณ์ — stock คงที่, เช็คจาก v_inventory_available
app.post('/borrow/submit', isStaff, async (req, res) => {
  try {
    const user_id      = (req.body.member_id || '').trim();
    const inventory_id = (req.body.inventory_id || '').trim();
    const qty          = parseInt(req.body.qty, 10);
    const borrow_date  = (req.body.borrow_date || '').trim();

    if (!user_id || !inventory_id || !Number.isInteger(qty) || qty <= 0 || !borrow_date) {
      return res.status(400).send('ข้อมูลไม่ครบหรือไม่ถูกต้อง');
    }

    // ถ้ามี hold อยู่และยังมีรายการค้าง → ห้ามยืม
    if (await hasActiveHold(user_id)) {
      const stillOpen = await hasOpenTransactions(user_id);
      if (!stillOpen) {
        await clearActiveHolds(user_id, 'auto-clear on borrow: no open loans');
      } else {
        return res.status(403).send('บัญชีนี้ถูกระงับการยืมชั่วคราว (ส่งเรื่องถึงคณะ/ค้างคืนเกินกำหนด)');
      }
    }

    // ดึงสต็อกจริง + คงเหลือให้ยืมจากวิว
    const q = await pool.query(`
      SELECT v.item_name, v.physical_stock, v.available_for_new_borrow
      FROM v_inventory_available v
      WHERE v.id = $1::uuid
      LIMIT 1
    `, [inventory_id]);
    if (!q.rowCount) return res.status(404).send('ไม่พบอุปกรณ์');

    const { item_name, physical_stock, available_for_new_borrow } = q.rows[0];
    if (available_for_new_borrow < qty) {
      return res.status(400).send(
        `คงเหลือให้ยืมไม่พอ (สต็อกจริง ${physical_stock}, กำลังถูกยืมไปแล้ว ${
          physical_stock - available_for_new_borrow
        }, คงเหลือให้ยืม ${available_for_new_borrow})`
      );
    }

    const client = await pool.connect();
    const txId = randomUUID();

    try {
      await client.query('BEGIN');
      await client.query(
  `INSERT INTO transactions (id, user_id, inventory_id, qty, borrow_date)
   VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5::date)`,
  [txId, user_id, inventory_id, qty, borrow_date]
);
      await client.query('COMMIT');
    } catch (e) {
      try { await client.query('ROLLBACK'); } catch {}
      client.release();
      console.error('TX borrow error:', e);
      return res.status(500).send('บันทึกไม่สำเร็จ');
    }
    client.release();

    const msg = `คุณได้ยืม ${item_name} จำนวน ${qty} ชิ้น วันที่ ${borrow_date}`;
    await notifyUser({
      userIdOrCode: user_id,
      type: 'borrow_created',
      title: 'ยืนยันการยืมอุปกรณ์',
      message: msg,
      meta: { ref: txId, goto: `/history#tx=${txId}` },
      emailSubject: 'ยืนยันการยืมอุปกรณ์',
      emailHtml: `<p>${msg}</p><p>รหัสรายการ: ${txId}</p>`
    });

    return res.redirect('/staff-home');
  } catch (e) {
    console.error('POST /borrow/submit error:', e);
    return res.status(500).send('server error');
  }
});

/* =========================
 * 11) RETURN / FITNESS
 * ========================= */
app.get('/return', isStaff, async (req, res) => {
  const code = (req.query.member || '').trim();
  if (!code) return res.render('return', { step:'scan', member:'', borrows:[] });

  const member = await findMemberByAny(code);
  if (!member) return res.render('return', { step:'scan', member:'', borrows:[], error:'ไม่พบสมาชิก' });

  const r = await pool.query(
  `SELECT v.tx_id, v.item_name, v.borrow_date, v.outstanding_qty
      FROM v_tx_outstanding v
     WHERE v.user_id = $1::uuid
       AND v.outstanding_qty > 0
     ORDER BY v.borrow_date DESC`,
   [member.id]
 );

  res.render('return', { step:'list', member, borrows:r.rows });
});

app.post('/return/submit', isStaff, async (req, res) => {
  try {
    const { tx_id, return_qty, note } = req.body;
    if (!tx_id) return res.status(400).send('tx_id required');

    // 1) ดึงธุรกรรม
    const txRes = await pool.query(
      `SELECT id, user_id, inventory_id, qty, return_date
         FROM transactions
        WHERE id = $1::uuid
        LIMIT 1`,
      [tx_id]
    );
    if (!txRes.rowCount)  return res.status(404).send('transaction not found');
    const tx = txRes.rows[0];
    if (tx.return_date)   return res.status(400).send('already closed');

    // 2) คำนวณคงค้าง
    const agg = await pool.query(
      `SELECT COALESCE(SUM(return_qty),0) AS returned_qty
         FROM transaction_returns
        WHERE transaction_id = $1::uuid`,
      [tx.id]
    );
    const alreadyReturned = Number(agg.rows[0].returned_qty || 0);
    const remaining = Number(tx.qty) - alreadyReturned;
    if (remaining <= 0) return res.status(400).send('transaction already fully returned');

    const qtyToReturn = Number(return_qty) > 0 ? Number(return_qty) : remaining;
    if (qtyToReturn > remaining) {
      return res.status(400).send(`เกินจำนวนคงค้าง (คงค้าง ${remaining})`);
    }

    // 3) บันทึกการคืน (ไม่ยุ่งกับ inventory.stock)
    await pool.query('BEGIN');

    // บันทึกคืนบางส่วน/ทั้งหมด
    await pool.query(
  `INSERT INTO transaction_returns (transaction_id, return_qty, note)
   VALUES ($1::uuid, $2::int, $3::text)`,
  [tx.id, qtyToReturn, note || null]
);

    // ถ้าคืนครบ → ปิดรายการ
    const still = remaining - qtyToReturn;
    if (still === 0) {
      await pool.query(
        `UPDATE transactions SET return_date = now() WHERE id = $1::uuid`,
        [tx.id]
      );
    }

    await pool.query('COMMIT');

    // 4) แจ้งผู้ใช้
    const title = still === 0 ? 'คืนอุปกรณ์ครบแล้ว' : 'คืนอุปกรณ์ (บางส่วน)';
    const msg   = still === 0
      ? `คุณได้คืนอุปกรณ์ครบตามจำนวน (รหัสรายการ: ${tx.id})`
      : `คุณได้คืนอุปกรณ์จำนวน ${qtyToReturn} ชิ้น (ยังคงค้าง ${still})`;

    await notifyUser({
      userIdOrCode: tx.user_id,
      type: still === 0 ? 'return_completed' : 'return_partial',
      title,
      message: msg,
      meta: { ref: `ret-${tx.id}`, tx_id: tx.id, remaining: still, goto: '/history' },
      emailSubject: title,
      emailHtml: `<p>${msg}</p><p>รหัสรายการ: ${tx.id}</p>`
    });

    // 5) ถ้าไม่มีค้างอื่นแล้ว → auto-clear hold (เหมือนเดิม)
    try {
      const r2 = await pool.query(
        `SELECT 1 FROM v_tx_outstanding
          WHERE user_id = $1::uuid AND outstanding_qty > 0
          LIMIT 1`,
        [tx.user_id]
      );
      if (r2.rowCount === 0) {
        const cleared = await clearActiveHolds(tx.user_id, `auto-clear: returned tx ${tx.id}`);
        if (cleared) {
          await notifyUser({
            userIdOrCode: tx.user_id,
            type: 'hold_cleared',
            title: 'ปลดระงับสิทธิ์แล้ว',
            message: 'ไม่มีรายการค้างคืนในระบบ ระบบจึงปลดการระงับสิทธิ์ยืมให้แล้ว',
            meta: { ref: `clear-${tx.id}`, goto: '/history' }
          });
          await notifyStaff({
            type: 'hold_cleared',
            title: 'ปลด Hold อัตโนมัติ',
            message: `ปลดการระงับสิทธิ์ของผู้ใช้หลังคืนครบ (tx ${tx.id})`,
            meta: { ref: `clear-${tx.id}`, user_id: tx.user_id }
          });
        }
      }
    } catch (e) {
      console.warn('auto-clear hold failed:', e?.message || e);
    }

    // 6) กลับหน้าที่เหมาะสม
    return res.redirect(still > 0 ? '/staff/outstanding' : '/staff-home');

  } catch (err) {
    await pool.query('ROLLBACK').catch(()=>{});
    console.error('POST /return/submit error:', err);
    return res.status(500).send('server error');
  }
});

app.get('/fitness', isStaff, async (req, res) => {
  try {
    const raw = (req.query.member || '').trim();
    if (!raw) return res.render('fitness', { member: null });

    const m = await findMemberByAny(raw);
    return res.render('fitness', { member: m || null });
  } catch (e) {
    console.error('GET /fitness error:', e);
    return res.render('fitness', { member: null });
  }
});

app.post('/fitness/submit', isStaff, async (req, res) => {
  try {
    const user_id     = (req.body.member_id || '').trim();
    const member_type = (req.body.member_type || '').trim();
    const visit_date  = (req.body.visit_date || '').trim();
    const pay_method  = (req.body.pay_method || 'cash').trim();

    if (!user_id || !visit_date || !member_type) return res.status(400).send('ข้อมูลไม่ครบ');
    if (!['student','external'].includes(member_type)) return res.status(400).send('member_type ไม่ถูกต้อง');
    if (!['cash','qr'].includes(pay_method)) return res.status(400).send('วิธีชำระเงินไม่ถูกต้อง');

    const amount = (member_type === 'student') ? 5 : 30;

    const check = await pool.query(
      'SELECT id, full_name, member_type FROM users WHERE id = $1::uuid LIMIT 1',
      [user_id]
    );
    if (!check.rowCount) return res.status(404).send('ไม่พบบัญชีสมาชิก');

    await pool.query(
      `INSERT INTO fitness_visits (user_id, visit_date, amount, pay_method)
       VALUES ($1::uuid, $2::date, $3::int, $4)`,
      [user_id, visit_date, amount, pay_method]
    );

    try {
      await pushNotif(
        user_id,
        'fitness_visit',
        'เข้าใช้ฟิตเน็ตสำเร็จ',
        `คุณได้เข้าใช้ฟิตเน็ตวันที่ ${visit_date} ชำระ ${amount} บาท (${pay_method === 'qr' ? 'สแกน QR' : 'เงินสด'})`,
        { goto: '/history?tab=fitness', amount, visit_date, pay_method }
      );
    } catch (e) { console.warn('pushNotif (fitness) failed:', e?.message || e); }

    return res.redirect('/staff-home?ok=fitness');
  } catch (e) {
    console.error('POST /fitness/submit error:', e);
    return res.status(500).send('server error');
  }
});

/* =========================
 * 12) MEMBER AREA
 * ========================= */
app.get('/login', (req, res) => {
  if (req.session?.user) {
    const t = req.session.user.type;
    return res.redirect(t === 'student' ? '/student-home' : '/external-home');
  }
  res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
  const email = (req.body.email || '').trim();
  const code  = (req.body.code  || '').trim();
  if (!email || !code) return res.render('login', { error: 'กรอกอีเมลและรหัสให้ครบ' });
  try {
    const { rows } = await pool.query(
  `SELECT id, member_type, email, student_id, citizen_id, qr_code_value
     FROM users
    WHERE LOWER(email) = LOWER($1::text)
      AND ($2::text = COALESCE(student_id,'')
       OR  $2::text = COALESCE(citizen_id,'')
       OR  $2::text = COALESCE(qr_code_value,''))  
    LIMIT 1`,
  [email, code]
);
    let u = rows[0];
    if (!u) {
    try {
    const codeHash = sha256Hex(code);
    const r2 = await pool.query(
      `SELECT id, member_type, email, student_id, citizen_id, qr_code_value
         FROM users
        WHERE LOWER(email) = LOWER($1::text)
          AND $2::text = COALESCE(student_id_hash,'')
        LIMIT 1`,
      [email, codeHash]
    );
    u = r2.rows[0];
  } catch (_e) {}
}
if (!u) return res.render('login', { error: 'ไม่พบบัญชีหรือรหัสไม่ถูกต้อง' });
    req.session.regenerate((err) => {
      if (err) return res.render('login', { error: 'เกิดข้อผิดพลาดของเซสชัน' });
      req.session.user   = { id: u.id, type: u.member_type };
      req.session.userId = u.id;
      return res.redirect(u.member_type === 'student' ? '/student-home' : '/external-home');
    });
  } catch (e) {
    console.error(e);
    return res.render('login', { error: 'เกิดข้อผิดพลาด กรุณาลองใหม่' });
  }
});

app.post('/logout', (req, res) => { req.session.destroy(() => res.redirect('/login')); });

app.get('/student-home', requireMember, async (req, res) => {
  if (req.session.user.type !== 'student') return res.redirect('/external-home');

  const id = req.session.user.id;
  const { rows } = await pool.query(
    `SELECT id, full_name, email, student_id, faculty, qr_code_value
       FROM users
      WHERE id = $1::uuid AND member_type = 'student'
      LIMIT 1`,
    [id]
  );

  if (!rows.length) return res.status(404).send('ไม่พบนักศึกษา');
  return res.render('student-home', { user: rows[0] });
});

app.get('/external-home', requireMember, async (req, res) => {
  if (req.session.user.type !== 'external') return res.redirect('/student-home');
  const id = req.session.user.id;
  const { rows } = await pool.query(
    `SELECT full_name,email,citizen_id,qr_code_value
       FROM users WHERE id = $1::uuid AND member_type='external'`, [id]
  );
  if (!rows.length) return res.status(404).send('ไม่พบบุคคลภายนอก');
  res.render('external-home', { 
    user: { full_name: rows[0].full_name, email: rows[0].email, external_id: rows[0].citizen_id, qr_code_value: rows[0].qr_code_value }
  });
});

/* =========================
 * 13) REGISTER
 * ========================= */
app.post('/register/student', redirectIfLoggedIn, async (req, res) => {
  const { email, student_id, full_name, faculty, phone } = req.body;

  if (!email?.endsWith('@mail.rmutk.ac.th')) return res.status(400).send('อีเมลต้องเป็น @mail.rmutk.ac.th');
  if (!/^[0-9]{12}$/.test(student_id || '')) return res.status(400).send('รหัสนักศึกษาต้องเป็นตัวเลข 12 หลัก');

  const uid = randomUUID();
  const check = await pool.query(`SELECT id FROM users WHERE LOWER(email)=LOWER($1) OR student_id=$2`, [email, student_id]);
  if (check.rows.length) return res.status(400).send('อีเมลหรือรหัสนักศึกษานี้ถูกใช้สมัครแล้ว');

  try {
    await pool.query(
      `INSERT INTO users
        (id, role_id, member_type, email, student_id, full_name, faculty, phone, qr_code_value)
       VALUES
        ($1, (SELECT id FROM roles WHERE name = 'student'), 'student',
         $2, $3, $4, $5, $6, $7)`,
      [uid, email, student_id, full_name, faculty, phone, student_id]
    );

    // ⬇️⬇️ เพิ่ม 2 บรรทัดนี้ไว้ “ใน” try หลัง INSERT สำเร็จ ⬇️⬇️
    await pool.query(
      `UPDATE users SET student_id_hash = $2 WHERE id = $1::uuid`,
      [uid, sha256Hex(student_id)]
    );
    // ⬆️⬆️ อยู่นี่จะเห็นตัวแปร uid/ student_id ได้ ⬆️⬆️

    req.session.user   = { id: uid, type: 'student' };
    req.session.userId = uid;
    res.redirect('/student-home');
  } catch (err) {
    console.error(err);
    if (err.code === '23505') return res.status(400).send('รหัสนักศึกษาหรืออีเมลนี้ถูกใช้สมัครแล้ว');
    res.status(500).send('สมัครสมาชิกนักศึกษาไม่สำเร็จ');
  }
});

app.post('/register/external', redirectIfLoggedIn, async (req, res) => {
  const { email, citizen_id, full_name, phone } = req.body;
  if (!/^[0-9]{13}$/.test(citizen_id || '')) return res.status(400).send('เลขบัตรประชาชนต้องเป็นตัวเลข 13 หลัก');

  const uid = randomUUID();
  const check = await pool.query(`SELECT id FROM users WHERE LOWER(email)=LOWER($1) OR citizen_id=$2`, [email, citizen_id]);
  if (check.rows.length) return res.status(400).send('อีเมลหรือเลขบัตรประชาชนนี้ถูกใช้สมัครแล้ว');

  try {
    await pool.query(
      `INSERT INTO users
        (id, role_id, member_type, email, citizen_id, full_name, phone, qr_code_value)
       VALUES
        ($1, (SELECT id FROM roles WHERE name = 'external'), 'external',
         $2, $3, $4, $5, $6)`,
      [uid, email, citizen_id, full_name, phone, citizen_id]
    );
    req.session.user   = { id: uid, type: 'external' };
    req.session.userId = uid;
    res.redirect('/external-home');
  } catch (err) {
    console.error(err);
    if (err.code === '23505') return res.status(400).send('เลขบัตรประชาชนหรืออีเมลนี้ถูกใช้สมัครแล้ว');
    res.status(500).send('สมัครสมาชิกบุคคลภายนอกไม่สำเร็จ');
  }
});

// =========================
// 14) INVENTORY (STAFF)
// =========================
app.get('/staff/inventory', isStaff, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT 
        v.id,
        v.item_name,
        v.physical_stock,
        v.outstanding_in_use,
        v.available_for_new_borrow,
        i.active
      FROM v_inventory_available v
      JOIN inventory i ON i.id = v.id
      ORDER BY i.active DESC, v.item_name ASC
    `);
    res.render('inventory', { items: rows, success: req.query.ok || null, error: null });
  } catch (e) {
    console.error('inventory error:', e);
    res.render('inventory', { items: [], success: null, error: 'โหลดรายการไม่สำเร็จ' });
  }
});

app.get('/staff/inventory/new', isStaff, (req, res) => {
  res.render('inventory-new', { error: null, success: null, form: { name: '', stock: '' } });
});

app.post('/staff/inventory/new', isStaff, async (req, res) => {
  const name  = (req.body.name || '').trim();
  const stock = parseInt(req.body.stock, 10);

  if (!name || Number.isNaN(stock) || stock < 0) {
    return res.render('inventory-new', {
      error: 'กรุณากรอกข้อมูลให้ถูกต้อง',
      success: null,
      form: { name, stock: req.body.stock }
    });
  }
  try {
    const dup = await pool.query(
      'SELECT 1 FROM inventory WHERE LOWER(item_name)=LOWER($1) LIMIT 1',[name]
    );
    if (dup.rowCount) {
      return res.render('inventory-new', {
        error: 'มีชื่ออุปกรณ์นี้อยู่แล้ว',
        success: null,
        form: { name, stock: req.body.stock }
      });
    }
    await pool.query(
      'INSERT INTO inventory (id, item_name, stock, active) VALUES ($1::uuid, $2, $3, TRUE)',
      [randomUUID(), name, stock]
    );
    return res.redirect('/staff/inventory?ok=created');
  } catch (e) {
    console.error('insert inventory error:', e);
    return res.render('inventory-new', {
      error: e.detail || 'เพิ่มอุปกรณ์ไม่สำเร็จ',
      success: null,
      form: { name, stock: req.body.stock }
    });
  }
});

app.post('/staff/inventory/toggle/:id', isStaff, async (req, res) => {
  const id = (req.params.id || '').trim();
  try {
    await pool.query(`UPDATE inventory SET active = NOT active WHERE id=$1::uuid`, [id]);
    return res.redirect('/staff/inventory?ok=toggled');
  } catch (e) {
    console.error('TOGGLE error', e);
    return res.redirect('/staff/inventory?ok=error');
  }
});

app.post('/staff/inventory/:id/edit', isStaff, async (req, res) => {
  const id     = (req.params.id || '').trim();
  const name   = (req.body.name || '').trim();
  const stock  = Number(req.body.stock || 0);
  const active = !!req.body.active;

  if (!name || !Number.isInteger(stock) || stock < 0) {
    return res.redirect('/staff/inventory?ok=error');
  }

  try {
    const { rows: out } = await pool.query(`
      SELECT COALESCE(SUM(outstanding_qty),0) AS out_using
      FROM v_tx_outstanding WHERE inventory_id = $1::uuid
    `, [id]);
    const outUsing = Number(out[0]?.out_using || 0);
    if (stock < outUsing) {
      return res.redirect('/staff/inventory?ok=stock_underflow');
    }

    const dup = await pool.query(
      `SELECT 1 FROM inventory WHERE LOWER(item_name)=LOWER($1) AND id<>$2::uuid LIMIT 1`,
      [name, id]
    );
    if (dup.rowCount) return res.redirect('/staff/inventory?ok=dup');

    await pool.query(
      `UPDATE inventory SET item_name=$1, stock=$2, active=$3 WHERE id=$4::uuid`,
      [name, stock, active, id]
    );
    return res.redirect('/staff/inventory?ok=updated');
  } catch (e) {
    console.error('EDIT error', e);
    return res.redirect('/staff/inventory?ok=error');
  }
});

app.post('/staff/inventory/:id/delete', isStaff, async (req, res) => {
  const id = (req.params.id || '').trim();
  try {
    await pool.query(`DELETE FROM inventory WHERE id=$1::uuid`, [id]);
    return res.redirect('/staff/inventory?ok=deleted');
  } catch (e) {
    console.error('DELETE error', e);
    if (e.code === '23503') {
      try {
        await pool.query(`
          ALTER TABLE inventory
          ADD COLUMN IF NOT EXISTS deleted_at timestamptz
        `);
        await pool.query(`
          UPDATE inventory
             SET active = FALSE,
                 deleted_at = COALESCE(deleted_at, now())
           WHERE id = $1::uuid
        `, [id]);
        return res.redirect('/staff/inventory?ok=archived');
      } catch (e2) {
        console.error('SOFT-DELETE fallback error:', e2);
        return res.redirect('/staff/inventory?ok=fk');
      }
    }
    return res.redirect('/staff/inventory?ok=error');
  }
});

// /staff/outstanding — ดูรายการค้างทุกคน
app.get('/staff/outstanding', isStaff, async (req, res) => {
  // ดึงค้างจากธุรกรรมที่ยังไม่ปิด + คำนวณคืนแล้วจาก transaction_returns
  const rows = (await pool.query(`
    SELECT
      t.id                              AS tx_id,
      t.user_id,
      u.full_name,
      i.item_name,
      t.qty                             AS borrowed_qty,
      COALESCE((
        SELECT SUM(tr.return_qty) FROM transaction_returns tr
        WHERE tr.transaction_id = t.id
      ), 0)                             AS returned_qty,
      (t.qty - COALESCE((
        SELECT SUM(tr.return_qty) FROM transaction_returns tr
        WHERE tr.transaction_id = t.id
      ), 0))                            AS outstanding_qty,
      t.borrow_date,
      t.promised_return_date
    FROM transactions t
    JOIN users    u ON u.id = t.user_id
    JOIN inventory i ON i.id = t.inventory_id
    WHERE t.return_date IS NULL
      AND (t.qty - COALESCE((
        SELECT SUM(tr.return_qty) FROM transaction_returns tr
        WHERE tr.transaction_id = t.id
      ), 0)) > 0
    ORDER BY t.borrow_date ASC
  `)).rows;

  res.render('outstanding', { rows });
});

// บันทึก/ลบ "วันนัดคืน" (เฉพาะ staff)
app.post('/staff/outstanding/promise', isStaff, async (req, res) => {
  try {
    const txId = (req.body?.tx_id || '').trim();
    // date อาจเป็นค่าว่าง = ลบวันนัดคืน
    const dateVal = (req.body?.date || '').trim();

    if (!txId) return res.status(400).json({ error: 'missing tx_id' });

    if (dateVal) {
      // validate รูปแบบ YYYY-MM-DD แบบง่าย ๆ
      if (!/^\d{4}-\d{2}-\d{2}$/.test(dateVal)) {
        return res.status(400).json({ error: 'invalid date format (YYYY-MM-DD)' });
      }
      await pool.query(
        `UPDATE transactions SET promised_return_date = $2::date
         WHERE id = $1::uuid AND return_date IS NULL`,
        [txId, dateVal]
      );
    } else {
      // ลบวันนัดคืน
      await pool.query(
        `UPDATE transactions SET promised_return_date = NULL
         WHERE id = $1::uuid AND return_date IS NULL`,
        [txId]
      );
    }

    return res.json({ ok: true });
  } catch (e) {
    console.error('promise date save error:', e);
    return res.status(500).json({ error: 'server error' });
  }
});

app.post('/holds/:userId/clear', isStaff, async (req, res) => {
  try {
    const userId = (req.params.userId || '').trim();
    if (!userId) return res.status(400).json({ error: 'missing userId' });

    const r = await pool.query(
      `UPDATE user_holds
          SET cleared_at = now(), reason = COALESCE(reason,'') || ' | cleared: manual'
        WHERE user_id = $1::uuid AND cleared_at IS NULL
        RETURNING id`,
      [userId]
    );
    if (!r.rowCount) return res.status(200).json({ ok: true, status: 'no_active_hold' });

    await notifyUser({
      userIdOrCode: userId,
      type: 'hold_cleared',
      title: 'ปลดระงับสิทธิ์แล้ว',
      message: 'เจ้าหน้าที่ได้ปลดการระงับสิทธิ์ยืมให้แล้ว',
      meta: { ref: `hold-clear-${userId}`, goto: '/history' }
    });
    await notifyStaff({
      type: 'hold_cleared',
      title: 'ปลด Hold โดยเจ้าหน้าที่',
      message: `ปลดการระงับสิทธิ์ของผู้ใช้ ${userId} (manual)`,
      meta: { ref: `hold-clear-${userId}`, user_id: userId }
    });

    res.json({ ok: true, status: 'cleared' });
  } catch (e) {
    console.error('clear hold error:', e);
    res.status(500).json({ error: 'server_error' });
  }
});

/* =========================
 * 15) QR IMAGE
 * ========================= */
app.get('/qrcode/:value', async (req, res) => {
  res.type('png');
  QRCode.toFileStream(res, req.params.value, { width: 600, margin: 1 });
});

/* =========================
 * 16) CRON: เตือนค้างคืน
 * ========================= */
async function runOverdueJob() {
  console.log('[CRON] overdue check start', new Date().toISOString());

  // 2–6 วัน: แจ้งนักศึกษา + staff
  const dueSoon = (await pool.query(`SELECT * FROM overdue_2_6_days`)).rows;
  console.log(`[CRON] dueSoon rows = ${dueSoon.length}`);

  for (const r of dueSoon) {
    try {
      const msgUser = `รายการยืม ${r.item_name} × ${r.qty} ค้างคืนมาแล้ว ${r.days_overdue} วัน กรุณานำมาคืนโดยเร็ว`;
      await notifyUser({
        userIdOrCode: r.user_id,
        type: 'overdue_student',
        title: 'แจ้งเตือนค้างคืนอุปกรณ์',
        message: msgUser,
        meta: { ref: r.tx_id, tx_id: r.tx_id, goto: `/history#tx=${r.tx_id}` },
        emailSubject: 'แจ้งเตือนค้างคืนอุปกรณ์',
        emailHtml: `<p>${msgUser}</p><p>รหัสรายการ: ${r.tx_id}</p>`
      });

      await notifyStaff({
        type: 'overdue_staff_2_6',
        title: 'รายการค้างคืน 2–6 วัน',
        message: `มีนักศึกษาค้างคืน ${r.item_name} × ${r.qty} ${r.days_overdue} วัน`,
        meta: {
          ref: r.tx_id,
          tx_id: r.tx_id,
          user_id: r.user_id,
          item: r.item_name,
          qty: r.qty,
          days_overdue: r.days_overdue,
          history_url: `/staff/history?member=${encodeURIComponent(r.user_id)}`
        },
        emailSubject: '[แจ้งเตือน] ค้างคืน 2–6 วัน',
        emailHtml: `<p>มีนักศึกษาค้างคืน ${r.item_name} × ${r.qty} ${r.days_overdue} วัน</p>
                    <p><a href="/staff/history?member=${encodeURIComponent(r.user_id)}">เปิดประวัติสมาชิก</a></p>`
      });
    } catch (e) {
      console.error(`[CRON] dueSoon FAIL tx=${r.tx_id}`, e);
    }
  }

  // ≥7 วัน: แจ้ง staff + ลิงก์พิมพ์เอกสาร
  const over7 = (await pool.query(`SELECT * FROM overdue_7_plus`)).rows;
  console.log(`[CRON] over7 rows = ${over7.length}`);

  for (const r of over7) {
    try {
      const u = await getUserById(r.user_id);
      const msg = `นักศึกษา ${u?.full_name || r.user_id} ค้างคืน ${r.item_name} × ${r.qty} เป็นเวลา ${r.days_overdue} วัน`;
      const printUrl = `/reports/overdue/print?tx=${encodeURIComponent(r.tx_id)}`;

      await notifyStaff({
        type: 'overdue_staff', // หมายถึง ≥7 วัน
        title: 'รายการค้างคืนเกิน 7 วัน',
        message: `${msg}. เอกสารสำหรับส่งคณะ: ${printUrl}`,
        meta: {
          ref: r.tx_id,
          tx_id: r.tx_id,
          user_id: u?.id || r.user_id,
          item: r.item_name,
          qty: r.qty,
          days_overdue: r.days_overdue,
          print_url: printUrl,
          history_url: `/staff/history?member=${encodeURIComponent(r.user_id)}`
        },
        emailSubject: '[แจ้งเตือน] ค้างคืนเกิน 7 วัน',
        emailHtml: `<p>${msg}</p>
        <p><a href="${printUrl}">เปิดเอกสารสำหรับพิมพ์</a> |
        <a href="/staff/history?member=${encodeURIComponent(r.user_id)}">เปิดประวัติสมาชิก</a></p>`
      });
    } catch (e) {
      console.error(`[CRON] over7 FAIL tx=${r.tx_id}`, e);
    }
  }
}

/* =========================
 * 17) Report print (7+ days)
 * ========================= */
app.get('/reports/overdue/print', isStaff, async (req, res) => {
  try {
    const tx = (req.query.tx || '').trim();
    if (!tx) return res.status(400).send('missing tx');

    const r = await pool.query(
      `SELECT t.id, t.user_id, t.inventory_id, t.qty, t.borrow_date,
              i.item_name, (CURRENT_DATE - t.borrow_date::date) AS days_overdue,
              t.escalated_at
         FROM transactions t
         JOIN inventory i ON i.id = t.inventory_id
        WHERE t.id = $1::uuid AND t.return_date IS NULL
        LIMIT 1`,
      [tx]
    );
    if (!r.rowCount) return res.status(404).send('not found');

    const row = r.rows[0];
    const u = await getUserById(row.user_id);

    const html = `
<!doctype html>
<html lang="th"><head>
<meta charset="utf-8">
<title>หนังสือแจ้งค้างคืน – ${u?.full_name || '-'}</title>
<style>
  body{font-family:Tahoma, sans-serif; line-height:1.6; margin:36px}
  .title{font-size:20px; font-weight:700; text-align:center; margin-bottom:8px}
  .sub{color:#555; text-align:center; margin-bottom:24px}
  .box{border:1px solid #ccc; padding:16px; border-radius:8px}
  .muted{color:#666}
  .sign{margin-top:32px}
  .noprint .btn{margin-left:8px}
  @media print {.noprint{display:none}}
</style>
</head><body>
  <div class="noprint" style="text-align:right;margin-bottom:8px;">
    <button onclick="window.print()">🖨️ พิมพ์เอกสาร</button>
    <button id="btnMarkSent" data-tx="${row.id}" class="btn" style="background:#ffc107;border:none;padding:8px 12px;border-radius:6px;">
      ✔️ ทำเครื่องหมายส่งถึงคณะแล้ว
    </button>
    <span id="markMsg" style="color:#198754;display:${row.escalated_at ? 'inline' : 'none'};margin-left:6px;">
      (บันทึกแล้ว)
    </span>
  </div>

  <div class="title">หนังสือแจ้งค้างคืนอุปกรณ์กีฬา</div>
  <div class="sub">รหัสรายการ: ${row.id}</div>

  <div class="box">
    <p>เรียน คณะ${u?.faculty || '(ไม่ระบุ)'}</p>
    <p>ตามที่นักศึกษา <strong>${u?.full_name || '-'}</strong> (อีเมล: ${u?.email || '-'}) ได้ทำการยืมอุปกรณ์
      <strong>${row.item_name}</strong> จำนวน <strong>${row.qty}</strong> ชิ้น เมื่อวันที่ <strong>${new Date(row.borrow_date).toLocaleDateString('th-TH')}</strong>
      บัดนี้ครบกำหนดและเกินกำหนดมาแล้ว <strong>${row.days_overdue}</strong> วัน แต่ยังไม่ได้ทำการคืนอุปกรณ์แต่อย่างใด</p>
    <p>จึงใคร่ขอความอนุเคราะห์ให้แจ้งเตือนนักศึกษา เพื่อดำเนินการคืนอุปกรณ์โดยเร็ว</p>
    <p class="muted">เอกสารนี้จัดทำโดยระบบยืม–คืนอุปกรณ์กีฬาและฟิตเนส</p>
  </div>

  <div class="sign">
    <p>ลงชื่อ................................................. เจ้าหน้าที่ผู้รับผิดชอบ</p>
    <p>วันที่........../........../............</p>
  </div>

  <script>
    const btn = document.getElementById('btnMarkSent');
    if (btn) {
      btn.addEventListener('click', async () => {
        const tx = btn.dataset.tx;
        const old = btn.innerHTML;
        btn.disabled = true; btn.innerHTML = 'กำลังบันทึก...';
        try{
          const resp = await fetch('/reports/overdue/mark-sent', {
            method: 'POST',
            headers: {'Content-Type':'application/json'},
            body: JSON.stringify({ tx })
          });
          const data = await resp.json().catch(()=>({}));
          if(!resp.ok) throw new Error(data?.error || ('HTTP '+resp.status));
          btn.style.background = '#198754'; btn.style.color='#fff';
          btn.innerHTML = 'บันทึกว่า: ส่งถึงคณะแล้ว';
          const msg = document.getElementById('markMsg'); if (msg) msg.style.display='inline';
          setTimeout(() => { window.location.href = '/staff/history'; }, 600);
        }catch(e){
          alert('บันทึกล้มเหลว: ' + (e.message || e));
          btn.disabled = false; btn.innerHTML = old;
        }
      });
    }
  </script>
</body></html>`;
    res.send(html);
  } catch (e) {
    console.error('print report error:', e);
    res.status(500).send('server error');
  }
});

app.post('/reports/overdue/mark-sent', isStaff, async (req, res) => {
  try {
    const tx = (req.body?.tx || '').trim();
    if (!tx) return res.status(400).json({ error: 'missing tx' });

    const r = await pool.query(
      `SELECT t.id, t.user_id, t.inventory_id, t.qty, t.borrow_date, t.return_date, t.escalated_at,
              i.item_name, (CURRENT_DATE - t.borrow_date::date) AS days_overdue
         FROM transactions t
         JOIN inventory i ON i.id = t.inventory_id
        WHERE t.id = $1::uuid
        LIMIT 1`, [tx]
    );
    if (!r.rowCount)   return res.status(404).json({ error: 'not found' });
    const row = r.rows[0];
    if (row.return_date) return res.status(400).json({ error: 'already returned' });

    if (!row.escalated_at) {
      await pool.query(`UPDATE transactions SET escalated_at = now() WHERE id = $1::uuid`, [tx]);
    }

    await notifyUser({
      userIdOrCode: row.user_id,
      type: 'overdue_faculty',
      title: 'ส่งเรื่องถึงคณะแล้ว',
      message: `รายการยืม ${row.item_name} × ${row.qty} เกินกำหนด ${row.days_overdue} วัน ระบบบันทึกว่าได้ส่งเอกสารถึงคณะแล้ว`,
      meta: { ref: row.id, goto: '/history' }
    });

    await notifyStaff({
      type: 'overdue_staff',
      title: 'ทำเครื่องหมาย “ส่งถึงคณะแล้ว”',
      message: `TX ${row.id} (${row.item_name} × ${row.qty}) ถูกทำเครื่องหมายส่งถึงคณะแล้ว`,
      meta: { ref: row.id, user_id: row.user_id }
    });

    return res.json({ ok: true });
  } catch (e) {
    console.error('mark-sent error:', e);
    return res.status(500).json({ error: 'server error' });
  }
});

/* =========================
 * 18) HISTORY (staff + member)
 * ========================= */
app.get('/history', requireMember, async (req, res) => {
  const userId = req.session.user.id;
  const type = req.session.user.type;

  const { borrowRows, fitnessRows } = await getHistoryData({ userId });

  const outRows = (await pool.query(`
    SELECT item_name, borrowed_qty, returned_qty, outstanding_qty, borrow_date
    FROM v_tx_outstanding
    WHERE user_id = $1::uuid AND outstanding_qty > 0
    ORDER BY borrow_date ASC
  `, [userId])).rows;

  if (type === 'student') {
    return res.render('history/student', { borrowRows, fitnessRows, outRows });
  }
  return res.render('history/external', { borrowRows, fitnessRows, outRows });
});

app.get('/staff/history', isStaff, async (req, res) => {
  const filters = {
    member: (req.query.member || '').trim(),
    from:   (req.query.from   || '').trim(),
    to:     (req.query.to     || '').trim(),
  };

  let member = null; let userId = null;
  if (filters.member) {
    member = await findMemberByAny(filters.member);
    userId = member?.id || null;

    if (userId) {
      const hold = await pool.query(
        `SELECT 1 FROM user_holds WHERE user_id=$1::uuid AND cleared_at IS NULL LIMIT 1`,
        [userId]
      );
      if (member) member.hold_active = hold.rowCount > 0;
    }
  }

  const { borrowRows, fitnessRows } = await getHistoryData({ userId, from: filters.from, to: filters.to });
  return res.render('history/staff', { filters, member, borrowRows, fitnessRows });
});

app.get('/members', async (req, res) => {
  try {
    const rows = (await pool.query(
      `SELECT id, full_name, member_type, student_id, citizen_id, email, created_at
         FROM users
        ORDER BY created_at DESC
        LIMIT 100`
    )).rows;
    res.render('members', { members: rows });
  } catch (e) {
    console.error('GET /members error:', e);
    res.render('members', { members: [], info: 'เกิดข้อผิดพลาดในการโหลดรายชื่อ' });
  }
});

app.get("/equipment", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        v.id,
        v.item_name,
        v.physical_stock,
        v.outstanding_in_use,
        v.available_for_new_borrow,
        i.active
      FROM v_inventory_available v
      JOIN inventory i ON i.id = v.id
      ORDER BY v.item_name ASC
    `);
    res.render("equipment", { inventory: result.rows });
  } catch (err) {
    console.error(err);
    res.render("equipment", { inventory: [] });
  }
});

/* =========================
 * 19) START
 * ========================= */
cron.schedule('0 8 * * *', () => runOverdueJob().catch(console.error), {
  timezone: 'Asia/Bangkok'
});

initDb()
  .then(() => {
    app.listen(PORT, '0.0.0.0', () => console.log(`Server running at http://localhost:${PORT}`));
    return runOverdueJob().catch(console.error); // run once after boot
  })
  .catch(err => {
    console.error('DB init failed:', err.code, err.message);
    process.exit(1);
  });
