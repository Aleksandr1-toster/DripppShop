const express = require('express'), { Pool, types } = require('pg'), bcrypt = require('bcryptjs'),
  jwt = require('jsonwebtoken'), crypto = require('crypto'), path = require('path');
types.setTypeParser(20, Number); // bigint -> number

const VERIFY = process.env.REQUIRE_EMAIL_VERIFY === '1'; // 1 = требовать подтверждение почты (нужен BREVO_KEY)
const { PORT = 3000, DATABASE_URL, JWT_SECRET, ADMIN_EMAIL = '', BASE_URL = 'http://localhost:3000',
  BREVO_KEY, MAIL_FROM, YK_SHOP_ID, YK_SECRET } = process.env;
if (!JWT_SECRET || !DATABASE_URL) { console.error('Нужны переменные JWT_SECRET и DATABASE_URL'); process.exit(1); }

const pool = new Pool({ connectionString: DATABASE_URL, ssl: /localhost|127\.0\.0\.1/.test(DATABASE_URL) ? false : { rejectUnauthorized: false } });
const q = (t, p) => pool.query(t, p);

// Письма через HTTP API Brevo (на бесплатных хостингах SMTP-порты часто закрыты)
async function sendMail(to, subject, html, link) {
  if (!BREVO_KEY || !MAIL_FROM) { console.log('[MAIL не настроен] ссылка для', to, ':', link); return; }
  const r = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: { 'api-key': BREVO_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({ sender: { name: 'DrippShop', email: MAIL_FROM }, to: [{ email: to }], subject, htmlContent: html })
  });
  if (!r.ok) console.error('Brevo:', r.status, await r.text());
}

const app = express();
app.use(express.json({ limit: '6mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.get('/healthz', (req, res) => res.send('ok'));

const getCookie = (req, n) => ((req.headers.cookie || '').split('; ').find(c => c.startsWith(n + '=')) || '').slice(n.length + 1);
async function auth(req, res, next) {
  let u = null;
  try {
    const d = jwt.verify(getCookie(req, 't'), JWT_SECRET);
    u = (await q('select * from users where id=$1', [d.id])).rows[0];
  } catch {}
  if (!u) return res.status(401).json({ error: 'Войдите в аккаунт' });
  req.user = u; next();
}
const adminOnly = (req, res, next) => req.user.role === 'admin' ? next() : res.status(403).json({ error: 'Только для админа' });
const wrap = fn => (req, res) => fn(req, res).catch(e => { if (!e.status) console.error(e); res.status(e.status || 500).json({ error: e.status ? e.message : 'Ошибка сервера' }); });
const fail = (status, message) => Object.assign(new Error(message), { status });
async function tx(fn) {
  const c = await pool.connect();
  try { await c.query('begin'); const r = await fn(c); await c.query('commit'); return r; }
  catch (e) { await c.query('rollback'); throw e; }
  finally { c.release(); }
}

/* ---------- auth ---------- */
function setSession(res, id) {
  const t = jwt.sign({ id }, JWT_SECRET, { expiresIn: '30d' });
  res.setHeader('Set-Cookie', `t=${t}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000${BASE_URL.startsWith('https') ? '; Secure' : ''}`);
}
app.post('/api/register', wrap(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase(), pw = String(req.body.password || '');
  if (!/^\S+@\S+\.\S+$/.test(email) || email.length > 120) throw fail(400, 'Введите корректную почту');
  if (pw.length < 6 || pw.length > 100) throw fail(400, 'Пароль — от 6 символов');
  const token = VERIFY ? crypto.randomBytes(24).toString('hex') : null;
  const role = ADMIN_EMAIL && email === ADMIN_EMAIL.toLowerCase() ? 'admin' : 'user';
  let id;
  try { id = (await q('insert into users(email,hash,role,verified,token) values($1,$2,$3,$4,$5) returning id', [email, bcrypt.hashSync(pw, 10), role, VERIFY ? 0 : 1, token])).rows[0].id; }
  catch (e) { if (e.code === '23505') throw fail(400, 'Такая почта уже зарегистрирована'); throw e; }
  if (VERIFY) {
    const link = `${BASE_URL}/api/verify?token=${token}`;
    await sendMail(email, 'Подтвердите почту — DrippShop', `<p>Добро пожаловать в DrippShop!</p><p><a href="${link}">Подтвердить почту</a></p>`, link);
    return res.json({ ok: true, verify: true });
  }
  setSession(res, id); // без подтверждения почты — сразу входим
  res.json({ ok: true, verify: false });
}));

app.get('/api/verify', wrap(async (req, res) => {
  const r = await q('update users set verified=1, token=null where token=$1 and token is not null', [String(req.query.token || '')]);
  res.redirect(r.rowCount ? '/?verified=1' : '/?verified=0');
}));

app.post('/api/login', wrap(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const u = (await q('select * from users where email=$1', [email])).rows[0];
  if (!u || !bcrypt.compareSync(String(req.body.password || ''), u.hash)) throw fail(401, 'Неверная почта или пароль');
  if (!u.verified) throw fail(403, 'Сначала подтвердите почту — письмо уже отправлено');
  setSession(res, u.id);
  res.json({ ok: true });
}));

app.post('/api/logout', (req, res) => { res.setHeader('Set-Cookie', 't=; HttpOnly; Path=/; Max-Age=0'); res.json({ ok: true }); });

app.get('/api/me', auth, wrap(async (req, res) => {
  const u = req.user;
  const orders = (await q('select created,sum,items from orders where user_id=$1 order by id desc limit 30', [u.id])).rows;
  res.json({ email: u.email, role: u.role, balance: u.balance, orders });
}));

/* ---------- товары (фото хранятся в базе) ---------- */
app.get('/api/products', auth, wrap(async (req, res) => {
  const off = Math.max(0, +req.query.offset || 0), L = 12;
  const like = '%' + String(req.query.q || '').trim().replace(/[%_\\]/g, '\\$&') + '%';
  const rows = (await q('select id,name,price,(image is not null) as has from products where name ilike $1 order by id desc limit $2 offset $3', [like, L + 1, off])).rows;
  res.json({ items: rows.slice(0, L).map(r => ({ id: r.id, name: r.name, price: r.price, img: r.has ? '/img/' + r.id : '' })), more: rows.length > L });
}));

app.get('/img/:id', wrap(async (req, res) => {
  const r = (await q('select image,mime from products where id=$1', [+req.params.id || 0])).rows[0];
  if (!r || !r.image) return res.sendStatus(404);
  res.set({ 'Content-Type': r.mime, 'Cache-Control': 'public, max-age=31536000, immutable' }).send(r.image);
}));

app.post('/api/products', auth, adminOnly, wrap(async (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 100), price = Math.round(+req.body.price);
  if (!name || !(price > 0) || price > 10000000) throw fail(400, 'Укажите название и цену');
  let image = null, mime = null;
  if (req.body.image) {
    const m = /^data:(image\/(?:jpeg|png|webp));base64,(.+)$/.exec(req.body.image);
    if (!m) throw fail(400, 'Неверный формат картинки');
    mime = m[1]; image = Buffer.from(m[2], 'base64');
  }
  const r = await q('insert into products(name,price,image,mime,created) values($1,$2,$3,$4,$5) returning id', [name, price, image, mime, Date.now()]);
  res.json({ id: r.rows[0].id });
}));

app.delete('/api/products/:id', auth, adminOnly, wrap(async (req, res) => {
  await q('delete from products where id=$1', [+req.params.id || 0]);
  res.json({ ok: true });
}));

/* ---------- покупка с баланса ---------- */
app.post('/api/checkout', auth, wrap(async (req, res) => {
  const ids = Array.isArray(req.body.ids) ? req.body.ids.map(Number).filter(Number.isInteger).slice(0, 100) : [];
  if (!ids.length) throw fail(400, 'Корзина пуста');
  const sum = await tx(async c => {
    const bal = (await c.query('select balance from users where id=$1 for update', [req.user.id])).rows[0].balance;
    let total = 0; const names = [];
    for (const id of ids) {
      const p = (await c.query('select name,price from products where id=$1', [id])).rows[0];
      if (!p) throw fail(400, 'Один из товаров больше недоступен');
      total += p.price; names.push(p.name);
    }
    if (bal < total) throw fail(402, 'Недостаточно средств на балансе');
    await c.query('update users set balance=balance-$1 where id=$2', [total, req.user.id]);
    await c.query('insert into orders(user_id,sum,items,created) values($1,$2,$3,$4)', [req.user.id, total, names.join(', ').slice(0, 200), Date.now()]);
    return total;
  });
  res.json({ ok: true, sum });
}));

/* ---------- ЮKassa: пополнение баланса ---------- */
const ykHeaders = () => ({ 'Content-Type': 'application/json', Authorization: 'Basic ' + Buffer.from(YK_SHOP_ID + ':' + YK_SECRET).toString('base64') });

app.post('/api/topup', auth, wrap(async (req, res) => {
  if (!YK_SHOP_ID || !YK_SECRET) throw fail(503, 'Оплата ещё не настроена');
  const amount = Math.round(+req.body.amount);
  if (!(amount >= 100 && amount <= 50000)) throw fail(400, 'Сумма от 100 до 50 000 ₽');
  const r = await fetch('https://api.yookassa.ru/v3/payments', {
    method: 'POST',
    headers: { ...ykHeaders(), 'Idempotence-Key': crypto.randomUUID() },
    body: JSON.stringify({
      amount: { value: amount.toFixed(2), currency: 'RUB' }, capture: true,
      confirmation: { type: 'redirect', return_url: BASE_URL + '/?paid=1' },
      description: 'Пополнение баланса DrippShop: ' + req.user.email
    })
  });
  const p = await r.json();
  if (!r.ok) { console.error('YooKassa:', p); throw fail(502, 'Платёжная система отклонила запрос'); }
  await q('insert into payments(id,user_id,amount,status) values($1,$2,$3,$4)', [p.id, req.user.id, amount, 'pending']);
  res.json({ url: p.confirmation.confirmation_url });
}));

// У уведомлений ЮKassa нет подписи, поэтому статус платежа перепроверяем запросом к их API
app.post('/api/yookassa/webhook', wrap(async (req, res) => {
  const id = req.body && req.body.object && req.body.object.id;
  if (typeof id !== 'string') return res.sendStatus(200);
  const row = (await q('select * from payments where id=$1', [id])).rows[0];
  if (!row || row.status === 'done') return res.sendStatus(200);
  const r = await fetch('https://api.yookassa.ru/v3/payments/' + encodeURIComponent(id), { headers: ykHeaders() });
  const p = await r.json();
  if (r.ok && p.status === 'succeeded' && p.paid) {
    await tx(async c => {
      const u = await c.query("update payments set status='done' where id=$1 and status='pending' returning amount,user_id", [id]);
      if (u.rows[0]) await c.query('update users set balance=balance+$1 where id=$2', [u.rows[0].amount, u.rows[0].user_id]);
    });
  }
  res.sendStatus(200);
}));

(async () => {
  await q(`
create table if not exists users(id serial primary key, email text unique, hash text, role text default 'user', balance integer default 0, verified integer default 0, token text);
create table if not exists products(id serial primary key, name text, price integer, image bytea, mime text, created bigint);
create table if not exists orders(id serial primary key, user_id integer, sum integer, items text, created bigint);
create table if not exists payments(id text primary key, user_id integer, amount integer, status text);`);
  app.listen(PORT, () => console.log('DrippShop запущен на порту ' + PORT));
})().catch(e => { console.error('Не удалось подключиться к базе:', e.message); process.exit(1); });
