require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
const q = (text, params) => pool.query(text, params).then((r) => r.rows);
const PRICE = Number(process.env.PRICE_PER_STUDENT || 50); // ₹ per student
const TRIAL_DAYS = 7;
const SECRET = process.env.JWT_SECRET;

const wrap = (fn) => (req, res) =>
  fn(req, res).catch((e) => {
    console.error(e);
    if (e.code === "23505") return res.status(409).json({ error: "Already exists (duplicate login ID / roll)" });
    res.status(500).json({ error: "Server error" });
  });

const today = () => new Date().toISOString().slice(0, 10);
const sign = (u) => jwt.sign({ id: u.id, role: u.role, school_id: u.school_id, class_name: u.class_name }, SECRET, { expiresIn: "7d" });

// ---------- middleware ----------
const auth = (...roles) => (req, res, next) => {
  try {
    req.user = jwt.verify((req.headers.authorization || "").replace("Bearer ", ""), SECRET);
    if (roles.length && !roles.includes(req.user.role)) return res.status(403).json({ error: "Not allowed" });
    next();
  } catch {
    res.status(401).json({ error: "Login required" });
  }
};

// blocks a school once trial is over and it has not paid
const active = wrap(async (req, res, next) => {
  const [s] = await q("select trial_ends_at, paid_until from schools where id=$1", [req.user.school_id]);
  const now = new Date();
  const ok = (s.paid_until && new Date(s.paid_until) > now) || new Date(s.trial_ends_at) > now;
  if (!ok) return res.status(402).json({ error: "Free trial ended. Please subscribe.", code: "SUBSCRIPTION_EXPIRED" });
  next();
});

async function createSchoolWithAdmin({ schoolName, name, loginId, password }) {
  const [school] = await q(
    "insert into schools(name, trial_ends_at) values($1, now() + ($2 || ' days')::interval) returning *",
    [schoolName, TRIAL_DAYS]
  );
  const hash = await bcrypt.hash(password, 10);
  const [admin] = await q(
    "insert into users(school_id, role, login_id, password_hash, name) values($1,'admin',$2,$3,$4) returning *",
    [school.id, loginId.trim(), hash, name]
  );
  return { school, admin };
}

// ---------- AUTH ----------
// "Get Started" screen: principal creates school -> 7-day free trial starts
app.post("/api/auth/register-school", wrap(async (req, res) => {
  const { schoolName, name, loginId, password } = req.body;
  if (!schoolName || !loginId || !password) return res.status(400).json({ error: "schoolName, loginId, password required" });
  const { school, admin } = await createSchoolWithAdmin({ schoolName, name, loginId, password });
  res.json({ token: sign(admin), role: "admin", trialEndsAt: school.trial_ends_at });
}));

// One login for everyone (student/teacher/parent/admin/superadmin)
app.post("/api/auth/login", wrap(async (req, res) => {
  const { loginId, password, role } = req.body;
  const [u] = await q("select * from users where login_id=$1", [String(loginId || "").trim()]);
  if (!u || !(await bcrypt.compare(password || "", u.password_hash))) return res.status(401).json({ error: "Wrong ID or password" });
  if (role && role !== u.role && !(role === "admin" && u.role === "superadmin"))
    return res.status(403).json({ error: `This ID is a ${u.role} account` });
  res.json({ token: sign(u), role: u.role, name: u.name, class_name: u.class_name });
}));

app.get("/api/me", auth(), wrap(async (req, res) => {
  const [u] = await q("select id, role, name, login_id, class_name, subject, school_id from users where id=$1", [req.user.id]);
  res.json(u);
}));

// ---------- SUPER ADMIN (you) ----------
app.get("/api/superadmin/schools", auth("superadmin"), wrap(async (req, res) => {
  res.json(await q(`
    select s.*, (select count(*) from students st where st.school_id = s.id)::int as students
    from schools s order by created_at desc`));
}));

// create school + admin (principal) yourself
app.post("/api/superadmin/admins", auth("superadmin"), wrap(async (req, res) => {
  const { school, admin } = await createSchoolWithAdmin(req.body);
  res.json({ school, admin: { id: admin.id, loginId: admin.login_id } });
}));

// mark a school as paid (after you receive payment)
app.post("/api/superadmin/schools/:id/mark-paid", auth("superadmin"), wrap(async (req, res) => {
  const months = Number(req.body.months || 1);
  const [{ count }] = await q("select count(*)::int from students where school_id=$1", [req.params.id]);
  await q("insert into payments(school_id, students_count, amount_inr, months) values($1,$2,$3,$4)", [req.params.id, count, count * PRICE * months, months]);
  const [s] = await q(`
    update schools set paid_until = greatest(coalesce(paid_until, now()), now()) + ($2 || ' months')::interval
    where id=$1 returning *`, [req.params.id, months]);
  res.json(s);
}));

// ---------- BILLING (admin) ----------
app.get("/api/billing/summary", auth("admin"), wrap(async (req, res) => {
  const [s] = await q("select * from schools where id=$1", [req.user.school_id]);
  const [{ count }] = await q("select count(*)::int from students where school_id=$1", [req.user.school_id]);
  const now = new Date();
  const paid = s.paid_until && new Date(s.paid_until) > now;
  res.json({
    status: paid ? "premium" : new Date(s.trial_ends_at) > now ? "trial" : "expired",
    trialEndsAt: s.trial_ends_at,
    paidUntil: s.paid_until,
    students: count,
    pricePerStudent: PRICE,
    amountDue: count * PRICE, // per month
  });
}));

// ---------- ADMIN / PRINCIPAL ----------
app.post("/api/admin/teachers", auth("admin"), active, wrap(async (req, res) => {
  const { name, loginId, password, subject, class_name } = req.body;
  const hash = await bcrypt.hash(password, 10);
  const [t] = await q(
    "insert into users(school_id, role, login_id, password_hash, name, subject, class_name) values($1,'teacher',$2,$3,$4,$5,$6) returning id, name, login_id, subject, class_name",
    [req.user.school_id, loginId.trim(), hash, name, subject, class_name]
  );
  res.json(t);
}));

app.get("/api/admin/teachers", auth("admin"), active, wrap(async (req, res) => {
  res.json(await q("select id, name, login_id, subject, class_name from users where school_id=$1 and role='teacher'", [req.user.school_id]));
}));

// attendance graph + today's class data
app.get("/api/admin/attendance/today", auth("admin"), active, wrap(async (req, res) => {
  res.json(await q(`
    select st.class_name as class,
           count(*)::int as total,
           count(*) filter (where a.status in ('present','late'))::int as present,
           count(*) filter (where a.status = 'absent')::int as absent
    from students st
    left join attendance a on a.student_id = st.user_id and a.day = $2
    where st.school_id = $1
    group by st.class_name order by st.class_name`, [req.user.school_id, today()]));
}));

app.post("/api/admin/notices", auth("admin"), active, wrap(async (req, res) => {
  const { audience, class_name, text } = req.body; // audience: students | teachers | parents
  const [n] = await q("insert into notices(school_id, audience, class_name, text, from_role) values($1,$2,$3,$4,'Principal') returning *",
    [req.user.school_id, audience, class_name || null, text]);
  res.json(n);
}));

// ---------- TEACHER ----------
app.post("/api/teacher/students", auth("teacher"), active, wrap(async (req, res) => {
  const { name, phone, email, password } = req.body;
  const cls = req.user.class_name;
  const [{ next }] = await q("select coalesce(max(roll),0)+1 as next from students where school_id=$1 and class_name=$2", [req.user.school_id, cls]);
  const hash = await bcrypt.hash(password, 10);
  const [u] = await q("insert into users(school_id, role, login_id, password_hash, name, class_name) values($1,'student',$2,$3,$4,$5) returning id",
    [req.user.school_id, phone.trim(), hash, name, cls]);
  await q("insert into students(user_id, school_id, class_name, roll, phone, email) values($1,$2,$3,$4,$5,$6)",
    [u.id, req.user.school_id, cls, next, phone.trim(), email || null]);
  res.json({ id: u.id, roll: next });
}));

app.get("/api/teacher/students", auth("teacher"), active, wrap(async (req, res) => {
  res.json(await q(`
    select st.user_id as id, st.roll, u.name, st.phone, st.email, a.status as today
    from students st join users u on u.id = st.user_id
    left join attendance a on a.student_id = st.user_id and a.day = $3
    where st.school_id=$1 and st.class_name=$2 order by st.roll`, [req.user.school_id, req.user.class_name, today()]));
}));

app.delete("/api/teacher/students/:id", auth("teacher"), active, wrap(async (req, res) => {
  await q("delete from users where id=$1 and school_id=$2 and role='student' and class_name=$3", [req.params.id, req.user.school_id, req.user.class_name]);
  res.json({ ok: true });
}));

app.post("/api/teacher/parents", auth("teacher"), active, wrap(async (req, res) => {
  const { studentId, loginId, password, name } = req.body;
  const hash = await bcrypt.hash(password, 10);
  const [p] = await q("insert into users(school_id, role, login_id, password_hash, name) values($1,'parent',$2,$3,$4) returning id",
    [req.user.school_id, loginId.trim(), hash, name]);
  await q("insert into parent_links(parent_id, student_id) values($1,$2)", [p.id, studentId]);
  res.json({ id: p.id });
}));

// everyone starts present; send the list of ABSENT student ids
app.post("/api/teacher/attendance", auth("teacher"), active, wrap(async (req, res) => {
  const absentIds = req.body.absentIds || [];
  const list = await q("select user_id from students where school_id=$1 and class_name=$2", [req.user.school_id, req.user.class_name]);
  for (const s of list) {
    await q(`insert into attendance(student_id, day, status) values($1,$2,$3)
             on conflict (student_id, day) do update set status = excluded.status`,
      [s.user_id, today(), absentIds.includes(s.user_id) ? "absent" : "present"]);
  }
  const absent = absentIds.length;
  res.json({ total: list.length, present: list.length - absent, absent });
}));

app.post("/api/teacher/late", auth("teacher"), active, wrap(async (req, res) => {
  const [s] = await q("select user_id from students where school_id=$1 and class_name=$2 and phone=$3", [req.user.school_id, req.user.class_name, String(req.body.phone).trim()]);
  if (!s) return res.status(404).json({ error: "No student found with this phone number" });
  await q(`insert into attendance(student_id, day, status) values($1,$2,'late')
           on conflict (student_id, day) do update set status='late'`, [s.user_id, today()]);
  res.json({ ok: true });
}));

app.post("/api/teacher/notices", auth("teacher"), active, wrap(async (req, res) => {
  const [n] = await q("insert into notices(school_id, audience, class_name, text, from_role) values($1,'parents',$2,$3,'Class teacher') returning *",
    [req.user.school_id, req.user.class_name, req.body.text]);
  res.json(n);
}));

// ---------- STUDENT ----------
app.get("/api/student/attendance", auth("student"), active, wrap(async (req, res) => {
  const rows = await q("select day, status from attendance where student_id=$1 and day >= date_trunc('month', now()) order by day", [req.user.id]);
  const present = rows.filter((r) => r.status !== "absent").length;
  res.json({ days: rows, percent: rows.length ? Math.round((present / rows.length) * 100) : 0 });
}));

// ---------- PARENT ----------
app.get("/api/parent/child", auth("parent"), active, wrap(async (req, res) => {
  const [c] = await q(`
    select u.name, st.class_name, st.roll,
      (select status from attendance a where a.student_id = st.user_id and a.day = $2) as today
    from parent_links pl join students st on st.user_id = pl.student_id join users u on u.id = st.user_id
    where pl.parent_id = $1 limit 1`, [req.user.id, today()]);
  res.json(c || null);
}));

app.get("/api/parent/attendance", auth("parent"), active, wrap(async (req, res) => {
  const rows = await q(`
    select a.day, a.status from parent_links pl join attendance a on a.student_id = pl.student_id
    where pl.parent_id=$1 and a.day >= date_trunc('month', now()) order by a.day`, [req.user.id]);
  res.json(rows);
}));

// ---------- NOTICES (read) ----------
app.get("/api/notices", auth("student", "teacher", "parent"), active, wrap(async (req, res) => {
  const audience = { student: "students", teacher: "teachers", parent: "parents" }[req.user.role];
  let cls = req.user.class_name;
  if (req.user.role === "parent") {
    const [c] = await q("select st.class_name from parent_links pl join students st on st.user_id=pl.student_id where pl.parent_id=$1 limit 1", [req.user.id]);
    cls = c?.class_name;
  }
  res.json(await q(`select text, from_role, created_at from notices
    where school_id=$1 and audience=$2 and (class_name is null or class_name=$3)
    order by created_at desc limit 50`, [req.user.school_id, audience, cls]));
}));

// ---------- BOOT ----------
async function seedSuperAdmin() {
  const id = process.env.SUPERADMIN_ID, pw = process.env.SUPERADMIN_PASSWORD;
  if (!id || !pw) return console.warn("SUPERADMIN_ID / SUPERADMIN_PASSWORD not set");
  const [exists] = await q("select 1 from users where role='superadmin' and login_id=$1", [id]);
  if (!exists) {
    await q("insert into users(role, login_id, password_hash, name) values('superadmin',$1,$2,'Owner')", [id, await bcrypt.hash(pw, 10)]);
    console.log("Super admin created:", id);
  }
}

const port = process.env.PORT || 4000;
seedSuperAdmin().then(() => app.listen(port, () => console.log("MyEdu API on :" + port)));
