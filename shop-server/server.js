const express = require('express'), Database = require('better-sqlite3'), bcrypt = require('bcryptjs'),
  jwt = require('jsonwebtoken'), nodemailer = require('nodemailer'), crypto = require('crypto'),
  fs = require('fs'), path = require('path');

const { PORT = 3000, DATA_DIR = './data', JWT_SECRET, ADMIN_EMAIL = '', BASE_URL = 'http://localhost:3000',
  SMTP_HOST, SMTP_PORT = 465, SMTP_USER, SMTP_PASS, SMTP_FROM, YK_SHOP_ID, YK_SECRET } = process.env;
if (!JWT_SECRET) { console.error('Задайте переменную JWT_SECRET'); process.exit(1); }

fs.mkdirSync(path.join(DATA_DIR, 'uploads'), { recursive: true });
const db = new Database(path.join(DATA_DIR, 'shop.db'));
db.exec(`
create table if not exists users(id integer primary key, email text unique, hash text, role text default 'user', balance integer default 0, verified integer default 0, token text);
create table if not exists products(id integer primary key, name text, price integer, img text, created integer);
create table if not exists orders(id integer primary key, user_id integer, sum integer, items text, created integer);
create table if not exists payments(id text primary key, user_id integer, amount integer, status text);
`);

const mailer = SMTP_HOST ? nodemailer.createTransport({ host: SMTP_HOST, port: +SMTP_PORT, secure: +SMTP_PORT === 465, auth: { user: SMTP_USER, pass: SMTP_PASS } }) : null;
async function sendMail(to, subject, html, link) {
  if (!mailer) { console.log('[MAIL не настроен] ссылка для', to, ':', link); return; }
  await mailer.sendMail({ from: SMTP_FROM || SMTP_USER, to, subject, html });
}

const app = express();
app.use(express.json({ limit: '6mb' }));
app.use('/uploads', express.static(path.join(DATA_DIR, 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));

const getCookie = (req, n) => ((req.headers.cookie || '').split('; ').find(c => c.startsWith(n + '=')) || '').slice(n.length + 1);
function auth(req, res, next) {
  try {
    const d = jwt.verify(getCookie(req, 't'), JWT_SECRET);
    const u = db.prepare('select * from users where id=?').get(d.id);
    if (!u) throw 0;
    req.user = u; next();
  } catch { res.status(401).json({ error: 'Войдите в аккаунт' }); }
}
const adminOnly = (req, res, next) => req.user.role === 'admin' ? next() : res.status(403).json({ error: 'Только для админа' });
const wrap = fn => (req, res) => fn(req, res).catch(e => { console.error(e); res.status(e.status || 500).json({ error: e.status ? e.message : 'Ошибка сервера' }); });
const fail = (status, message) => Object.assign(new Error(message), { status });

/* ---------- auth ---------- */
app.post('/api/register', wrap(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase(), pw = String(req.body.password || '');
  if (!/^\S+@\S+\.\S+$/.test(email) || email.length > 120) throw fail(400, 'Введите корректную почту');
  if (pw.length < 6 || pw.length > 100) throw fail(400, 'Пароль — от 6 символов');
  if (db.prepare('select 1 from users where email=?').get(email)) throw fail(400, 'Такая почта уже зарегистрирована');
  const token = crypto.randomBytes(24).toString('hex');
  const role = ADMIN_EMAIL && email === ADMIN_EMAIL.toLowerCase() ? 'admin' : 'user';
  db.prepare('insert into users(email,hash,role,token) values(?,?,?,?)').run(email, bcrypt.hashSync(pw, 10), role, token);
  const link = `${BASE_URL}/api/verify?token=${token}`;
  await sendMail(email, 'Подтвердите почту — DrippShop', `<p>Добро пожаловать в DrippShop!</p><p><a href="${link}">Подтвердить почту</a></p>`, link);
  res.json({ ok: true });
}));

app.get('/api/verify', (req, res) => {
  const r = db.prepare('update users set verified=1, token=null where token=? and token is not null').run(String(req.query.token || ''));
  res.redirect(r.changes ? '/?verified=1' : '/?verified=0');
});

app.post('/api/login', wrap(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const u = db.prepare('select * from users where email=?').get(email);
  if (!u || !bcrypt.compareSync(String(req.body.password || ''), u.hash)) throw fail(401, 'Неверная почта или пароль');
  if (!u.verified) throw fail(403, 'Сначала подтвердите почту — письмо уже отправлено');
  const t = jwt.sign({ id: u.id }, JWT_SECRET, { expiresIn: '30d' });
  res.setHeader('Set-Cookie', `t=${t}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000${BASE_URL.startsWith('https') ? '; Secure' : ''}`);
  res.json({ ok: true });
}));

app.post('/api/logout', (req, res) => { res.setHeader('Set-Cookie', 't=; HttpOnly; Path=/; Max-Age=0'); res.json({ ok: true }); });

app.get('/api/me', auth, (req, res) => {
  const u = req.user;
  const orders = db.prepare('select created,sum,items from orders where user_id=? order by id desc limit 30').all(u.id);
  res.json({ email: u.email, role: u.role, balance: u.balance, orders });
});

/* ---------- products ---------- */
app.get('/api/products', auth, (req, res) => {
  const off = Math.max(0, +req.query.offset || 0), q = '%' + String(req.query.q || '').trim() + '%', L = 12;
  const rows = db.prepare('select id,name,price,img from products where name like ? collate nocase order by id desc limit ? offset ?').all(q, L + 1, off);
  res.json({ items: rows.slice(0, L), more: rows.length > L });
});

app.post('/api/products', auth, adminOnly, wrap(async (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 100), price = Math.round(+req.body.price);
  if (!name || !(price > 0) || price > 10000000) throw fail(400, 'Укажите название и цену');
  let img = '';
  if (req.body.image) {
    const m = /^data:image\/(jpeg|png|webp);base64,(.+)$/.exec(req.body.image);
    if (!m) throw fail(400, 'Неверный формат картинки');
    const file = crypto.randomBytes(12).toString('hex') + '.' + (m[1] === 'jpeg' ? 'jpg' : m[1]);
    fs.writeFileSync(path.join(DATA_DIR, 'uploads', file), Buffer.from(m[2], 'base64'));
    img = '/uploads/' + file;
  }
  const r = db.prepare('insert into products(name,price,img,created) values(?,?,?,?)').run(name, price, img, Date.now());
  res.json({ id: r.lastInsertRowid });
}));

app.delete('/api/products/:id', auth, adminOnly, (req, res) => {
  db.prepare('delete from products where id=?').run(+req.params.id);
  res.json({ ok: true });
});

/* ---------- покупка с баланса ---------- */
app.post('/api/checkout', auth, wrap(async (req, res) => {
  const ids = Array.isArray(req.body.ids) ? req.body.ids.map(Number).filter(Number.isInteger).slice(0, 100) : [];
  if (!ids.length) throw fail(400, 'Корзина пуста');
  const tx = db.transaction(() => {
    let sum = 0; const names = [];
    for (const id of ids) {
      const p = db.prepare('select name,price from products where id=?').get(id);
      if (!p) throw fail(400, 'Один из товаров больше недоступен');
      sum += p.price; names.push(p.name);
    }
    const bal = db.prepare('select balance from users where id=?').get(req.user.id).balance;
    if (bal < sum) throw fail(402, 'Недостаточно средств на балансе');
    db.prepare('update users set balance=balance-? where id=?').run(sum, req.user.id);
    db.prepare('insert into orders(user_id,sum,items,created) values(?,?,?,?)').run(req.user.id, sum, names.join(', ').slice(0, 200), Date.now());
    return sum;
  });
  res.json({ ok: true, sum: tx() });
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
  db.prepare('insert into payments(id,user_id,amount,status) values(?,?,?,?)').run(p.id, req.user.id, amount, 'pending');
  res.json({ url: p.confirmation.confirmation_url });
}));

// В ЮKassa подпись у уведомлений нет, поэтому статус платежа перепроверяем запросом к их API
app.post('/api/yookassa/webhook', wrap(async (req, res) => {
  const id = req.body && req.body.object && req.body.object.id;
  if (typeof id !== 'string') return res.sendStatus(200);
  const row = db.prepare('select * from payments where id=?').get(id);
  if (!row || row.status === 'done') return res.sendStatus(200);
  const r = await fetch('https://api.yookassa.ru/v3/payments/' + encodeURIComponent(id), { headers: ykHeaders() });
  const p = await r.json();
  if (r.ok && p.status === 'succeeded' && p.paid) {
    db.transaction(() => {
      const u = db.prepare("update payments set status='done' where id=? and status='pending'").run(id);
      if (u.changes) db.prepare('update users set balance=balance+? where id=?').run(row.amount, row.user_id);
    })();
  }
  res.sendStatus(200);
}));

app.listen(PORT, () => console.log('DrippShop запущен на порту ' + PORT));
