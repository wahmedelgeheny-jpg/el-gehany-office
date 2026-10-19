require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');

const required = ['SUPABASE_URL','SUPABASE_ANON_KEY','SUPABASE_SERVICE_ROLE_KEY','ADMIN_EMAIL','COOKIE_SECRET'];
for (const key of required) if (!process.env[key]) { console.error(`Missing environment variable: ${key}`); process.exit(1); }
if (process.env.COOKIE_SECRET.length < 32) throw new Error('COOKIE_SECRET must be at least 32 characters.');

const app = express();
const production = process.env.NODE_ENV === 'production';
const PORT = process.env.PORT || 3000;
const authClient = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY, { auth: { autoRefreshToken: false, persistSession: false } });
const db = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, { auth: { autoRefreshToken: false, persistSession: false } });
const cookieName = production ? '__Host-gh_admin' : 'gh_admin';
const services = new Set(['بطاقة الرقم القومي','جواز السفر','شهادة ميلاد','شهادة وفاة','مستندات الزواج','استفسار عام']);
const statuses = new Set(['جديد','قيد المتابعة','تم التواصل','مكتمل','مرفوض']);

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: { directives: {
  defaultSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
  fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'], scriptSrc: ["'self'"],
  imgSrc: ["'self'", 'data:'], connectSrc: ["'self'"], objectSrc: ["'none'"], baseUri: ["'self'"], frameAncestors: ["'none'"]
} } }));
app.use(express.json({ limit: '20kb' }));
app.use(express.urlencoded({ extended: false, limit: '20kb' }));
app.use(cookieParser());
app.use(express.static('public', { extensions: ['html'] }));
const limiter = (limit) => rateLimit({ windowMs: 15 * 60 * 1000, limit, standardHeaders: 'draft-7', legacyHeaders: false });
const clean = (v, n = 200) => typeof v === 'string' ? v.trim().replace(/\s+/g, ' ').slice(0, n) : '';
const cookieOptions = () => ({ httpOnly: true, secure: production, sameSite: 'lax', path: '/', maxAge: 8 * 60 * 60 * 1000 });

async function requireAdmin(req, res, next) {
  try {
    const token = req.cookies[cookieName];
    if (!token) return res.status(401).json({ error: 'سجّل الدخول أولًا.' });
    const { data, error } = await authClient.auth.getUser(token);
    if (error || !data.user) { res.clearCookie(cookieName, { path: '/' }); return res.status(401).json({ error: 'انتهت الجلسة. سجّل الدخول مرة أخرى.' }); }
    const email = String(data.user.email || '').trim().toLowerCase();
    if (email !== process.env.ADMIN_EMAIL.trim().toLowerCase()) return res.status(403).json({ error: 'ليس لديك صلاحية الإدارة.' });
    req.admin = { id: data.user.id, email }; next();
  } catch (e) { console.error('Admin auth:', e.message); res.status(500).json({ error: 'تعذر التحقق من الدخول.' }); }
}

app.get('/api/health', (_req, res) => res.json({ ok: true }));
app.post('/api/requests', limiter(10), async (req, res) => {
  try {
    const name = clean(req.body.name, 100), phone = clean(req.body.phone, 11), service = clean(req.body.service, 80), details = clean(req.body.details, 1200);
    if (clean(req.body.website, 200)) return res.json({ ok: true, message: 'تم استلام طلبك.' });
    if (name.length < 2) return res.status(400).json({ error: 'اكتب الاسم بشكل صحيح.' });
    if (!/^01[0125][0-9]{8}$/.test(phone)) return res.status(400).json({ error: 'اكتب رقم موبايل مصري صحيحًا.' });
    if (!services.has(service)) return res.status(400).json({ error: 'اختار الخدمة من القائمة.' });
    if (details.length < 3) return res.status(400).json({ error: 'اكتب تفاصيل الاستفسار.' });
    const { error } = await db.from('service_requests').insert({ name, phone, service, details, status: 'جديد' });
    if (error) { console.error('Database insert:', error.message); return res.status(500).json({ error: 'تعذر حفظ الطلب. اتصل بالمكتب مباشرة.' }); }
    res.status(201).json({ ok: true, message: 'تم إرسال استفسارك بنجاح.' });
  } catch (e) { console.error('Request:', e.message); res.status(500).json({ error: 'حدث خطأ غير متوقع.' }); }
});

app.post('/api/admin/login', limiter(8), async (req, res) => {
  try {
    const email = clean(req.body.email, 254).toLowerCase();
    const password = typeof req.body.password === 'string' ? req.body.password : '';
    if (email !== process.env.ADMIN_EMAIL.trim().toLowerCase()) return res.status(401).json({ error: 'بيانات الدخول غير صحيحة.' });
    if (!password || password.length > 256) return res.status(400).json({ error: 'اكتب كلمة المرور.' });
    const { data, error } = await authClient.auth.signInWithPassword({ email, password });
    if (error || !data.user || !data.session?.access_token) return res.status(401).json({ error: 'بيانات الدخول غير صحيحة.' });
    res.cookie(cookieName, data.session.access_token, cookieOptions());
    res.json({ ok: true });
  } catch (e) { console.error('Login:', e.message); res.status(500).json({ error: 'تعذر تسجيل الدخول.' }); }
});
app.post('/api/admin/logout', (_req, res) => { res.clearCookie(cookieName, { httpOnly: true, secure: production, sameSite: 'lax', path: '/' }); res.json({ ok: true }); });
app.get('/api/admin/me', limiter(120), requireAdmin, (req, res) => res.json({ ok: true, email: req.admin.email }));
app.get('/api/admin/requests', limiter(120), requireAdmin, async (_req, res) => {
  try { const { data, error } = await db.from('service_requests').select('id,name,phone,service,details,status,created_at').order('created_at', { ascending: false }).limit(500); if (error) throw error; res.json({ requests: data || [] }); }
  catch (e) { console.error('Fetch requests:', e.message); res.status(500).json({ error: 'تعذر تحميل الطلبات.' }); }
});
app.patch('/api/admin/requests/:id', limiter(120), requireAdmin, async (req, res) => {
  const id = clean(req.params.id, 80), status = clean(req.body.status, 40);
  if (!/^[0-9a-f-]{36}$/i.test(id)) return res.status(400).json({ error: 'معرّف الطلب غير صحيح.' });
  if (!statuses.has(status)) return res.status(400).json({ error: 'الحالة غير صحيحة.' });
  try { const { data, error } = await db.from('service_requests').update({ status }).eq('id', id).select('id,status').single(); if (error || !data) return res.status(404).json({ error: 'لم يتم العثور على الطلب.' }); res.json({ ok: true, request: data }); }
  catch (e) { console.error('Update:', e.message); res.status(500).json({ error: 'تعذر تحديث حالة الطلب.' }); }
});
app.delete('/api/admin/requests/:id', limiter(120), requireAdmin, async (req, res) => {
  const id = clean(req.params.id, 80); if (!/^[0-9a-f-]{36}$/i.test(id)) return res.status(400).json({ error: 'معرّف الطلب غير صحيح.' });
  try { const { error } = await db.from('service_requests').delete().eq('id', id); if (error) throw error; res.json({ ok: true }); }
  catch (e) { console.error('Delete:', e.message); res.status(500).json({ error: 'تعذر حذف الطلب.' }); }
});
app.listen(PORT, () => console.log(`الموقع يعمل على http://localhost:${PORT}`));
