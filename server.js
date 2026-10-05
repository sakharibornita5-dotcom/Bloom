const express = require('express'), cookieParser = require('cookie-parser'), bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken'), crypto = require('crypto'), Razorpay = require('razorpay');
const { DatabaseSync } = require('node:sqlite');
const { PORT = 3000, JWT_SECRET, RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET, RAZORPAY_WEBHOOK_SECRET, ADMIN_EMAIL, ADMIN_PASSWORD, NODE_ENV } = process.env;

if (!JWT_SECRET || JWT_SECRET.length < 24) { console.error('Add JWT_SECRET (24+ random characters) to your .env file.'); process.exit(1); }
const rzp = RAZORPAY_KEY_ID && RAZORPAY_KEY_SECRET ? new Razorpay({ key_id: RAZORPAY_KEY_ID, key_secret: RAZORPAY_KEY_SECRET }) : null;
if (!rzp) console.warn('Razorpay keys are missing, so payments are off until you add them to .env');

// ---------- database ----------
const db = new DatabaseSync('bloom.db');
db.exec(`
CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY AUTOINCREMENT, brand TEXT, name TEXT, cat TEXT, price INTEGER, mrp INTEGER, color TEXT, img TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, email TEXT UNIQUE, hash TEXT, role TEXT DEFAULT 'user');
CREATE TABLE IF NOT EXISTS orders(id TEXT PRIMARY KEY, user_id INTEGER, items TEXT, total INTEGER, addr TEXT, status TEXT, rzp_order TEXT, payment_id TEXT, created TEXT);`);
const CATS = ['Men', 'Women', 'Kids', 'Footwear', 'Accessories'];
if (db.prepare('SELECT COUNT(*) n FROM products').get().n === 0) {
  const ins = db.prepare('INSERT INTO products(brand,name,cat,price,mrp,color) VALUES(?,?,?,?,?,?)');
  [['Roadster','Slim Fit Denim Jacket','Men',2499,3999,'#7aa5d2'],['H&M','Cotton Crew T-Shirt','Men',599,999,'#f2b8a2'],
   ['Libas','Printed Anarkali Kurta','Women',1299,2599,'#ff8fab'],['Biba','Floral Maxi Dress','Women',1799,3299,'#ffc86b'],
   ['Zudio','High-Rise Mom Jeans','Women',999,1799,'#9bb7e0'],['Max','Kids Dino Hoodie','Kids',799,1299,'#b8e0a2'],
   ['Puma','Running Sneakers','Footwear',3199,5999,'#ff6b6b'],['Bata','Leather Formal Shoes','Footwear',1899,2999,'#c49a6c'],
   ['Crocs','Classic Clogs','Footwear',2495,3495,'#8ad0c8'],['Fossil','Analog Wrist Watch','Accessories',4999,8999,'#d4af37'],
   ['Lavie','Structured Tote Bag','Accessories',1599,3199,'#e58fb5'],['Ray-Ban','Aviator Sunglasses','Accessories',5490,7990,'#6b7a8f']
  ].forEach(p => ins.run(...p));
}
if (ADMIN_EMAIL && ADMIN_PASSWORD && !db.prepare('SELECT 1 FROM users WHERE email=?').get(ADMIN_EMAIL.toLowerCase()))
  db.prepare('INSERT INTO users(name,email,hash,role) VALUES(?,?,?,?)').run('Admin', ADMIN_EMAIL.toLowerCase(), bcrypt.hashSync(ADMIN_PASSWORD, 10), 'admin');

// ---------- helpers ----------
const httpErr = (status, message) => Object.assign(new Error(message), { status });
const wrap = f => (req, res, next) => Promise.resolve(f(req, res, next)).catch(next);
const app = express();
app.disable('x-powered-by');
app.use((req, res, next) => { res.set({ 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'same-origin' }); next(); });
// Razorpay webhook: needs the raw body, so it sits before the JSON parser.
// It marks an order Paid even if the customer closes the tab right after paying.
app.post('/api/razorpay-webhook', express.raw({ type: '*/*', limit: '200kb' }), (req, res) => {
  if (!RAZORPAY_WEBHOOK_SECRET) return res.status(503).end();
  const sig = Buffer.from(String(req.get('X-Razorpay-Signature') || ''));
  const exp = Buffer.from(crypto.createHmac('sha256', RAZORPAY_WEBHOOK_SECRET).update(req.body).digest('hex'));
  if (sig.length !== exp.length || !crypto.timingSafeEqual(sig, exp)) return res.status(400).end();
  let ev; try { ev = JSON.parse(req.body.toString('utf8')); } catch { return res.status(400).end(); }
  if (ev.event === 'payment.captured' || ev.event === 'order.paid') {
    const pay = ev.payload?.payment?.entity, oid = pay?.order_id || ev.payload?.order?.entity?.id;
    const o = oid && db.prepare('SELECT total FROM orders WHERE rzp_order=?').get(oid);
    if (o && (!pay || pay.amount === o.total * 100))
      db.prepare("UPDATE orders SET status='Paid', payment_id=? WHERE rzp_order=? AND status!='Paid'").run(pay?.id || null, oid);
  }
  res.json({ ok: true });
});
app.use(express.json({ limit: '1mb' }), cookieParser());
app.use((req, res, next) => { try { req.u = jwt.verify(req.cookies.t, JWT_SECRET); } catch {} next(); });
const need = (req, res, next) => req.u ? next() : res.status(401).json({ error: 'Please log in first' });
const admin = (req, res, next) => req.u?.role === 'admin' ? next() : res.status(403).json({ error: 'Admins only' });
const tries = new Map();
const limit = (req, res, next) => {
  const n = (tries.get(req.ip) || []).filter(t => Date.now() - t < 9e5);
  if (n.length >= 10) return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
  n.push(Date.now()); tries.set(req.ip, n); next();
};
function sign(res, u) {
  res.cookie('t', jwt.sign({ id: u.id, name: u.name, email: u.email, role: u.role }, JWT_SECRET, { expiresIn: '7d' }),
    { httpOnly: true, sameSite: 'lax', secure: NODE_ENV === 'production', maxAge: 6048e5 });
  return { name: u.name, email: u.email, role: u.role };
}

// ---------- accounts ----------
app.post('/api/signup', limit, wrap((req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 60), email = String(req.body.email || '').trim().toLowerCase(), pw = String(req.body.password || '');
  if (!name || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || pw.length < 8) throw httpErr(400, 'Enter your name, a valid email and a password of 8+ characters');
  if (db.prepare('SELECT 1 FROM users WHERE email=?').get(email)) throw httpErr(409, 'That email is already registered');
  const r = db.prepare('INSERT INTO users(name,email,hash) VALUES(?,?,?)').run(name, email, bcrypt.hashSync(pw, 10));
  res.json({ user: sign(res, { id: Number(r.lastInsertRowid), name, email, role: 'user' }) });
}));
app.post('/api/login', limit, wrap((req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(String(req.body.email || '').trim().toLowerCase());
  if (!u || !bcrypt.compareSync(String(req.body.password || ''), u.hash)) throw httpErr(401, 'Wrong email or password');
  res.json({ user: sign(res, u) });
}));
app.post('/api/logout', (req, res) => { res.clearCookie('t'); res.json({ ok: true }); });
app.get('/api/me', (req, res) => res.json({ user: req.u ? { name: req.u.name, email: req.u.email, role: req.u.role } : null }));

// ---------- products (only admins can change them) ----------
function clean(b) {
  const s = (v, n) => String(v ?? '').trim().slice(0, n);
  const p = { brand: s(b.brand, 40), name: s(b.name, 80), cat: s(b.cat, 20), price: Math.round(+b.price), mrp: Math.round(+b.mrp),
    color: /^#[0-9a-f]{6}$/i.test(b.color) ? b.color : '#ff8fab',
    img: typeof b.img === 'string' && b.img.length < 700000 && (b.img === '' || /^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/.test(b.img)) ? b.img : '' };
  if (!p.brand || !p.name || !CATS.includes(p.cat) || !(p.price > 0) || !(p.mrp >= p.price)) throw httpErr(400, 'Check the product details');
  return p;
}
const getP = id => db.prepare('SELECT * FROM products WHERE id=?').get(id);
app.get('/api/products', (req, res) => res.json(db.prepare('SELECT * FROM products ORDER BY id').all()));
app.post('/api/products', need, admin, wrap((req, res) => {
  const p = clean(req.body);
  const r = db.prepare('INSERT INTO products(brand,name,cat,price,mrp,color,img) VALUES(?,?,?,?,?,?,?)').run(p.brand, p.name, p.cat, p.price, p.mrp, p.color, p.img);
  res.json(getP(Number(r.lastInsertRowid)));
}));
app.put('/api/products/:id', need, admin, wrap((req, res) => {
  const id = +req.params.id, p = clean(req.body);
  if (!getP(id)) throw httpErr(404, 'Product not found');
  db.prepare('UPDATE products SET brand=?,name=?,cat=?,price=?,mrp=?,color=?,img=? WHERE id=?').run(p.brand, p.name, p.cat, p.price, p.mrp, p.color, p.img, id);
  res.json(getP(id));
}));
app.delete('/api/products/:id', need, admin, wrap((req, res) => { db.prepare('DELETE FROM products WHERE id=?').run(+req.params.id); res.json({ ok: true }); }));

// ---------- checkout & payments (prices always come from the database) ----------
app.post('/api/checkout', need, wrap(async (req, res) => {
  if (!rzp) throw httpErr(503, 'Payments are not set up yet');
  const { items, addr } = req.body;
  if (!Array.isArray(items) || !items.length || items.length > 30 || typeof addr !== 'string' || addr.length < 10 || addr.length > 400) throw httpErr(400, 'Check your bag and delivery address');
  let total = 0; const lines = [];
  for (const i of items) {
    const p = getP(+i.id), q = Math.floor(+i.qty);
    if (!p || !(q >= 1 && q <= 10)) throw httpErr(400, 'An item in your bag is no longer available');
    total += p.price * q;
    lines.push({ id: p.id, brand: p.brand, name: p.name, cat: p.cat, color: p.color, size: String(i.size || 'M').slice(0, 4), qty: q, price: p.price });
  }
  const id = 'BL' + Date.now().toString().slice(-8) + crypto.randomInt(10, 99);
  const r = await rzp.orders.create({ amount: total * 100, currency: 'INR', receipt: id });
  db.prepare('INSERT INTO orders(id,user_id,items,total,addr,status,rzp_order,created) VALUES(?,?,?,?,?,?,?,?)')
    .run(id, req.u.id, JSON.stringify(lines), total, addr, 'Payment pending', r.id, new Date().toISOString());
  res.json({ orderId: id, rzpOrder: r.id, amount: r.amount, key: RAZORPAY_KEY_ID });
}));
app.post('/api/verify', need, wrap((req, res) => {
  if (!rzp) throw httpErr(503, 'Payments are not set up yet');
  const { order, razorpay_order_id: ro, razorpay_payment_id: rp, razorpay_signature: rs } = req.body;
  const o = db.prepare('SELECT * FROM orders WHERE id=? AND user_id=?').get(String(order), req.u.id);
  if (!o || o.rzp_order !== String(ro)) throw httpErr(400, 'Order not found');
  const a = Buffer.from(crypto.createHmac('sha256', RAZORPAY_KEY_SECRET).update(o.rzp_order + '|' + String(rp)).digest('hex')), b = Buffer.from(String(rs));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) throw httpErr(400, 'Payment could not be verified');
  db.prepare("UPDATE orders SET status='Paid', payment_id=? WHERE id=?").run(String(rp), o.id);
  res.json({ ok: true });
}));
app.get('/api/orders', need, (req, res) => res.json(
  db.prepare('SELECT id,items,total,addr,status,created FROM orders WHERE user_id=? ORDER BY created DESC').all(req.u.id)
    .map(o => ({ ...o, items: JSON.parse(o.items), date: o.created }))));

app.use(express.static('public'));
app.use((e, req, res, next) => { console.error(e); res.status(e.status || 500).json({ error: e.status ? e.message : 'Something went wrong' }); });
app.listen(PORT, () => console.log(`Bloom is running at http://localhost:${PORT}`));