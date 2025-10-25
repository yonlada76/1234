-- =========================
--  ALL-IN-ONE SETUP SQL
--  (Safe to rerun)
-- =========================

-- ---------- EXTENSIONS ----------
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ---------- ROLES ----------
CREATE TABLE IF NOT EXISTS roles (
  id   SERIAL PRIMARY KEY,
  name VARCHAR(20) UNIQUE NOT NULL
);

INSERT INTO roles(name) VALUES
('student'), ('external'), ('staff'), ('admin')
ON CONFLICT (name) DO NOTHING;

-- ---------- USERS ----------
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  role_id INT REFERENCES roles(id),
  member_type VARCHAR(20) CHECK (member_type IN ('student','external','staff','admin')),
  email VARCHAR(255) UNIQUE NOT NULL,
  student_id VARCHAR(12) UNIQUE,
  citizen_id VARCHAR(13) UNIQUE,
  full_name VARCHAR(200) NOT NULL,
  faculty VARCHAR(100),
  phone VARCHAR(30),
  qr_code_value TEXT UNIQUE,
  created_at TIMESTAMPTZ DEFAULT now(),
  student_id_hash TEXT
);

-- (เผื่อฐานเก่าที่ยังไม่มีคอลัมน์) เพิ่มแบบกันซ้ำ
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS student_id VARCHAR(12) UNIQUE,
  ADD COLUMN IF NOT EXISTS student_id_hash TEXT;

-- บังคับรูปแบบเลข 12 หลักแบบ idempotent
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'chk_student_id_len'
          AND conrelid = 'users'::regclass
  ) THEN
    ALTER TABLE users
      ADD CONSTRAINT chk_student_id_len CHECK (
        student_id IS NULL OR student_id ~ ''
      );
  END IF;
END $$;

-- ดัชนี (unique) สำหรับ student_id_hash
CREATE UNIQUE INDEX IF NOT EXISTS uq_users_student_id_hash ON users(student_id_hash);

-- seed staff (ตัวอย่าง)
INSERT INTO users (role_id, member_type, email, full_name)
SELECT id, 'staff', 'staff@example.com', 'Staff User'
FROM roles WHERE name='staff'
ON CONFLICT DO NOTHING;

-- ---------- INVENTORY ----------
CREATE TABLE IF NOT EXISTS inventory (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  item_name VARCHAR(150) UNIQUE NOT NULL,
  stock INT NOT NULL DEFAULT 0 CHECK (stock >= 0),
  active BOOLEAN NOT NULL DEFAULT TRUE,
  deleted_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_inventory_active_name ON inventory(active, item_name);
CREATE INDEX IF NOT EXISTS idx_inventory_stock ON inventory(stock);

-- ---------- TRANSACTIONS ----------
CREATE TABLE IF NOT EXISTS transactions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id),
  inventory_id UUID NOT NULL REFERENCES inventory(id),
  qty INT NOT NULL CHECK (qty > 0),
  borrow_date DATE DEFAULT CURRENT_DATE,
  return_date TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT now(),
  escalated_at TIMESTAMPTZ,
  promised_return_date DATE   -- ใช้ในหน้า "คงค้าง" เพื่อนัดวันคืน
);

CREATE INDEX IF NOT EXISTS idx_tx_user_open ON transactions(user_id) WHERE return_date IS NULL;

-- ---------- TRANSACTION RETURNS (คืนบางส่วน) ----------
CREATE TABLE IF NOT EXISTS transaction_returns (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  transaction_id UUID NOT NULL REFERENCES transactions(id) ON DELETE CASCADE,
  return_qty INT NOT NULL CHECK (return_qty > 0),
  returned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  note TEXT
);
CREATE INDEX IF NOT EXISTS idx_tr_txid ON transaction_returns(transaction_id);

-- ---------- FITNESS VISITS ----------
CREATE TABLE IF NOT EXISTS fitness_visits (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id),
  visit_date DATE NOT NULL,
  amount INT NOT NULL,
  pay_method TEXT CHECK (pay_method IN ('cash','qr')),
  created_at TIMESTAMPTZ DEFAULT now()
);

-- ---------- NOTIFICATIONS ----------
CREATE TABLE IF NOT EXISTS notifications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  title TEXT,
  message TEXT,
  meta JSONB,
  created_at TIMESTAMPTZ DEFAULT now(),
  read_at TIMESTAMPTZ,
  created_date DATE
);

-- trigger: set created_date
CREATE OR REPLACE FUNCTION set_created_date()
RETURNS trigger AS $$
BEGIN
  NEW.created_date := COALESCE(NEW.created_at::date, CURRENT_DATE);
  RETURN NEW;
END; $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_set_created_date ON notifications;
CREATE TRIGGER trg_set_created_date
BEFORE INSERT ON notifications
FOR EACH ROW
EXECUTE FUNCTION set_created_date();

-- เติมย้อนหลัง (ครั้งแรกเท่านั้นจะมีผล)
UPDATE notifications
   SET created_date = created_at::date
 WHERE created_date IS NULL;

-- unique กันส่งซ้ำรายวัน (อิง ref/type/date)
CREATE UNIQUE INDEX IF NOT EXISTS uq_notif_daily
  ON notifications ((meta->>'ref'), type, created_date)
  WHERE type IN ('overdue_student','overdue_faculty','overdue_staff_2_6');

-- unique กันแจ้งซ้ำต่อรายการฝั่ง staff (meta.ref)
CREATE UNIQUE INDEX IF NOT EXISTS uq_notif_once_idx
  ON notifications (user_id, type, (meta->>'ref'))
  WHERE (meta->>'ref') IS NOT NULL;

-- บังคับ "แจ้งนักศึกษาค้างคืน" ได้ครั้งเดียว/รายการ
CREATE UNIQUE INDEX IF NOT EXISTS uq_notif_overdue_student_once
  ON notifications ( (meta->>'ref') )
  WHERE type = 'overdue_student';

-- ---------- USER HOLDS ----------
CREATE TABLE IF NOT EXISTS user_holds (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  reason TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  cleared_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS ix_user_holds_active
  ON user_holds(user_id)
  WHERE cleared_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_user_holds_one_active
  ON user_holds(user_id)
  WHERE cleared_at IS NULL;

-- ---------- OVERDUE VIEWS (2–6 วัน, 7+ วัน) ----------
CREATE OR REPLACE VIEW overdue_2_6_days AS
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

CREATE OR REPLACE VIEW overdue_7_plus AS
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

-- ---------- VIEW: ค้างคืนต่อรายการ (ใช้ในหลายหน้า + ปุ่ม “รับคืน”) ----------
CREATE OR REPLACE VIEW v_tx_outstanding AS
SELECT
  t.id                AS tx_id,                 -- << โค้ดฝั่ง EJS อ้างชื่อนี้
  t.user_id,
  t.inventory_id,
  i.item_name,
  t.borrow_date,
  t.promised_return_date,                       -- << ใช้แสดง “นัดคืน”
  t.qty               AS borrowed_qty,
  COALESCE((
    SELECT SUM(tr.return_qty)
    FROM transaction_returns tr
    WHERE tr.transaction_id = t.id
  ), 0)                AS returned_qty,
  GREATEST(
    t.qty - COALESCE((
      SELECT SUM(tr.return_qty)
      FROM transaction_returns tr
      WHERE tr.transaction_id = t.id
    ), 0),
    0
  )                    AS outstanding_qty
FROM transactions t
JOIN inventory i ON i.id = t.inventory_id
WHERE t.return_date IS NULL
  AND (t.qty - COALESCE((
         SELECT SUM(tr.return_qty) FROM transaction_returns tr
         WHERE tr.transaction_id = t.id
       ), 0)) > 0
ORDER BY t.borrow_date ASC;

-- ---------- VIEW: คงเหลือสต็อกหลังหักของค้าง ----------
CREATE OR REPLACE VIEW v_inventory_available AS
WITH out_by_item AS (
  SELECT inventory_id, SUM(outstanding_qty) AS out_using
  FROM v_tx_outstanding
  WHERE outstanding_qty > 0
  GROUP BY inventory_id
)
SELECT
  i.id,
  i.item_name,
  i.stock AS physical_stock,
  COALESCE(o.out_using,0) AS outstanding_in_use,
  GREATEST(i.stock - COALESCE(o.out_using,0), 0) AS available_for_new_borrow
FROM inventory i
LEFT JOIN out_by_item o ON o.inventory_id = i.id;

-- ---------- BACKFILL: student_id_hash (ครั้งแรก/เฉพาะที่ยังว่าง) ----------
UPDATE users
   SET student_id_hash = encode(digest(student_id, 'sha256'), 'hex')
 WHERE member_type = 'student'
   AND student_id IS NOT NULL
   AND student_id_hash IS NULL;

-- ---------- CLEANUP (รองรับฐานเก่าที่เคยมี UNIQUE CONSTRAINT เดิม) ----------
-- ถ้าเคยสร้าง constraint ชื่อ users_student_id_hash_key ไว้ ให้ลบทิ้ง
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_student_id_hash_key;

INSERT INTO users (role_id, member_type, email, full_name)
SELECT id, 'admin', 'admin@example.com', 'Admin User'
FROM roles WHERE name='admin'
ON CONFLICT DO NOTHING;


-- วิวสรุปสถานะอุปกรณ์ต่อชิ้น
CREATE OR REPLACE VIEW public.v_item_status AS
WITH
o AS (  -- กำลังค้างยืมอยู่ ( outstanding ทั้งหมด )
  SELECT inventory_id, SUM(outstanding_qty)::int AS in_use
  FROM public.v_tx_outstanding
  GROUP BY inventory_id
),
od2 AS ( -- ค้าง 2–6 วัน
  SELECT inventory_id, SUM(qty)::int AS overdue_2_6
  FROM public.overdue_2_6_days
  GROUP BY inventory_id
),
od7 AS ( -- ค้าง 7 วันขึ้นไป
  SELECT inventory_id, SUM(qty)::int AS overdue_7_plus
  FROM public.overdue_7_plus
  GROUP BY inventory_id
)
SELECT
  i.id,
  i.item_name,
  i.stock                                   AS stock_total,   -- ค่าคงที่จาก inventory
  COALESCE(o.in_use, 0)                     AS in_use,        -- จำนวนที่ยังค้างจริง
  COALESCE(od2.overdue_2_6, 0)              AS overdue_2_6,
  COALESCE(od7.overdue_7_plus, 0)           AS overdue_7_plus,
  GREATEST(i.stock - COALESCE(o.in_use,0),0) AS available      -- คงเหลือให้ยืม
FROM public.inventory i
LEFT JOIN o   ON o.inventory_id   = i.id
LEFT JOIN od2 ON od2.inventory_id = i.id
LEFT JOIN od7 ON od7.inventory_id = i.id
WHERE i.deleted_at IS NULL AND i.active = TRUE
ORDER BY i.item_name;
