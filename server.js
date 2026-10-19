const express = require('express'), nodemailer = require('nodemailer');
const crypto = require('crypto'), fs = require('fs'), path = require('path');

try { for (const l of fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split(/\r?\n/)) {
  const m = l.match(/^\s*([A-Z_]+)\s*=\s*(.*?)\s*$/); if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
} } catch {}
const E = process.env, PORT = E.PORT || 3000, STUDIO = E.STUDIO_NAME || 'Mi Estudio';
const PUBLIC_URL = (E.PUBLIC_URL || 'http://localhost:' + PORT).replace(/\/$/, '');
const DATA = path.join(E.DATA_DIR || __dirname, 'data.json');

let db = { users: [], sessions: {}, news: [], settings: {} };
try { db = { ...db, ...JSON.parse(fs.readFileSync(DATA, 'utf8')) }; } catch {}
const save = () => { fs.writeFileSync(DATA + '.tmp', JSON.stringify(db)); fs.renameSync(DATA + '.tmp', DATA); };
const sha = s => crypto.createHash('sha256').update(String(s)).digest('hex');
const hashPw = (pw, salt = crypto.randomBytes(16).toString('hex')) => salt + ':' + crypto.scryptSync(pw, salt, 64).toString('hex');
const checkPw = (pw, st) => { const [salt, h] = (st || ':').split(':'); const a = Buffer.from(h, 'hex'), b = crypto.scryptSync(pw, salt, 64); return a.length === b.length && crypto.timingSafeEqual(a, b); };

const fake = /tucorreo|tu-contraseña/i.test((E.SMTP_USER || '') + (E.SMTP_PASS || ''));
const mailer = E.SMTP_HOST && !fake ? nodemailer.createTransport({ host: E.SMTP_HOST, port: +E.SMTP_PORT || 465, secure: (+E.SMTP_PORT || 465) === 465, auth: { user: E.SMTP_USER, pass: E.SMTP_PASS } }) : null;
async function mail(to, subject, text) {
  if (E.RESEND_API_KEY) {
    const r = await fetch('https://api.resend.com/emails', { method: 'POST', headers: { Authorization: 'Bearer ' + E.RESEND_API_KEY, 'Content-Type': 'application/json' }, body: JSON.stringify({ from: E.MAIL_FROM, to: [to], subject, text }) });
    if (!r.ok) throw new Error('Resend: ' + (await r.text()));
    return;
  }
  if (!mailer) { console.log(`\n[CORREO SIMULADO] Para: ${to}\nAsunto: ${subject}\n${text}\n`); return; }
  await mailer.sendMail({ from: E.MAIL_FROM || E.SMTP_USER, to, subject, text });
}
async function sendCode(u) {
  u.code = String(crypto.randomInt(100000, 1000000)); u.codeExp = Date.now() + 15 * 60000; u.tries = 0; u.lastSend = Date.now();
  await mail(u.email, `Tu código de verificación de ${STUDIO}`, `Hola ${u.name},\n\nTu código de verificación es: ${u.code}\n\nCaduca en 15 minutos. Si no creaste esta cuenta, ignora este mensaje.`);
}

const newSession = u => { const t = crypto.randomBytes(32).toString('hex'); db.sessions[sha(t)] = { id: u.id, at: Date.now() }; return t; };
const userFor = t => { const s = db.sessions[sha(t || '')]; return s && Date.now() - s.at < 90 * 864e5 ? db.users.find(u => u.id === s.id) : null; };

const hits = new Map();
const limit = (req, res, next) => {
  const now = Date.now(), a = (hits.get(req.ip) || []).filter(t => now - t < 600000);
  if (a.length >= 30) return res.status(429).json({ ok: false, error: 'Demasiados intentos. Espera unos minutos.' });
  a.push(now); hits.set(req.ip, a); next();
};
const bad = (res, error, extra = {}) => res.json({ ok: false, error, ...extra });

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '20kb' }));

app.post('/api/register', limit, async (req, res) => {
  try {
    const { name, email, password, news } = req.body || {};
    if (!/^\w{3,16}$/.test(name || '')) return bad(res, 'El nombre debe tener de 3 a 16 letras, números o _ (sin espacios).');
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email || '')) return bad(res, 'Correo no válido.');
    if (typeof password !== 'string' || password.length < 8) return bad(res, 'La contraseña debe tener al menos 8 caracteres.');
    db.users = db.users.filter(u => u.verified || Date.now() - u.created < 3600e3); // limpia cuentas sin verificar
    const em = email.toLowerCase();
    let u = db.users.find(x => x.email === em);
    if (u && u.verified) return bad(res, 'Ese correo ya tiene una cuenta. Inicia sesión.');
    if (db.users.some(x => x !== u && x.name.toLowerCase() === name.toLowerCase())) return bad(res, 'Ese nombre ya está en uso.');
    if (!u) { u = { id: crypto.randomUUID(), email: em, created: Date.now(), unsub: crypto.randomBytes(16).toString('hex') }; db.users.push(u); }
    Object.assign(u, { name, passHash: hashPw(password), verified: false, news: !!news });
    await sendCode(u); save(); res.json({ ok: true });
  } catch (e) { console.log('ERROR AL ENVIAR CORREO:', e.message); bad(res, 'No se pudo enviar el correo. Revisa la configuración del correo en el servidor.'); }
});

app.post('/api/verify', limit, (req, res) => {
  const { email, code } = req.body || {};
  const u = db.users.find(x => x.email === String(email || '').toLowerCase());
  if (!u || !u.code) return bad(res, 'Pide un código nuevo.');
  if (u.tries >= 5 || Date.now() > u.codeExp) return bad(res, 'El código caducó. Pide uno nuevo.');
  if (String(code).trim() !== u.code) { u.tries++; save(); return bad(res, 'Código incorrecto.'); }
  u.verified = true; u.code = null;
  const token = newSession(u); save(); res.json({ ok: true, name: u.name, token });
});

app.post('/api/resend', limit, async (req, res) => {
  const u = db.users.find(x => x.email === String((req.body || {}).email || '').toLowerCase());
  if (!u || u.verified) return bad(res, 'No hay nada que verificar.');
  if (Date.now() - (u.lastSend || 0) < 60000) return bad(res, 'Espera un minuto para pedir otro código.');
  try { await sendCode(u); save(); res.json({ ok: true }); } catch { bad(res, 'No se pudo enviar el correo.'); }
});

app.post('/api/login', limit, async (req, res) => {
  const { user, password } = req.body || {}, q = String(user || '').toLowerCase();
  const u = db.users.find(x => x.name.toLowerCase() === q || x.email === q);
  if (!u || typeof password !== 'string' || !checkPw(password, u.passHash)) return bad(res, 'Usuario o contraseña incorrectos.');
  if (!u.verified) {
    try { if (Date.now() - (u.lastSend || 0) > 60000) { await sendCode(u); save(); } } catch {}
    return bad(res, 'Falta verificar tu correo. Te enviamos un código.', { needsVerify: true, email: u.email });
  }
  const token = newSession(u); save(); res.json({ ok: true, name: u.name, token });
});

app.post('/api/session', limit, (req, res) => { const u = userFor((req.body || {}).token); u ? res.json({ ok: true, name: u.name }) : res.json({ ok: false }); });
app.post('/api/logout', (req, res) => { delete db.sessions[sha((req.body || {}).token || '')]; save(); res.json({ ok: true }); });
app.get('/api/news', (_, res) => res.json(db.news.slice(0, 10)));

app.get('/unsubscribe', (req, res) => {
  const u = db.users.find(x => x.unsub === req.query.t);
  if (u) { u.news = false; save(); }
  res.send('<meta charset="utf-8"><body style="font-family:sans-serif;padding:40px">Listo, ya no recibirás novedades por correo.</body>');
});

// ---------- Panel para ti (owner): enviar novedades ----------
const adminOk = req => E.ADMIN_KEY && crypto.timingSafeEqual(Buffer.from(sha(req.get('x-admin-key') || '')), Buffer.from(sha(E.ADMIN_KEY)));
app.get('/api/remote', (_, res) => res.json(db.settings || {}));
app.get('/admin', (_, res) => res.send(`<!doctype html><meta charset="utf-8"><title>Panel</title>
<style>body{font-family:sans-serif;max-width:620px;margin:30px auto;padding:0 14px;display:grid;gap:10px}
h2{margin:18px 0 0}input,textarea,select{padding:8px;font:inherit}.row{display:flex;gap:8px;align-items:center}
.row label{flex:1}input[type=color]{padding:0;height:36px;width:60px;flex:none}</style>
<h2>Panel de ${STUDIO.replace(/[<&]/g, '')}</h2>
<input id="k" type="password" placeholder="Tu clave de administrador (ADMIN_KEY)">
<h2>Enviar novedades</h2>
<input id="s" placeholder="Asunto / título"><textarea id="t" rows="6" placeholder="Mensaje"></textarea>
<label><input type="checkbox" id="e" checked> Enviar por correo a quienes aceptaron novedades</label>
<label><input type="checkbox" id="l" checked> Mostrar en el launcher</label>
<button id="b">Enviar novedad</button><div id="m"></div>
<h2>Apariencia del launcher</h2>
<input id="name" placeholder="Nombre del estudio"><input id="tag" placeholder="Frase bajo el nombre">
<div class="row"><label>Fondo <input type="color" id="c_background"></label><label>Panel <input type="color" id="c_panel"></label><label>Texto <input type="color" id="c_text"></label></div>
<div class="row"><label>Botón <input type="color" id="c_accent"></label><label>Texto del botón <input type="color" id="c_accentText"></label></div>
<input id="bg" placeholder="Imagen de fondo (enlace https://...)">
<input id="nt" placeholder="Aviso en el launcher (vacío = sin aviso)">
<select id="nl"><option value="info">Aviso normal</option><option value="warn">Aviso importante</option></select>
<div class="row"><input id="host" placeholder="IP o dirección del servidor de Minecraft" style="flex:3"><input id="port" placeholder="Puerto" style="flex:1"></div>
<button id="sv">Guardar apariencia</button><div id="m2"></div>
<script>
var $=function(i){return document.getElementById(i)},cols=['background','panel','text','accent','accentText'];
var D={background:'#101a1f',panel:'#17262d',text:'#eef2ee',accent:'#e9b44c',accentText:'#1a1405'};
function H(){return {'Content-Type':'application/json','x-admin-key':$('k').value}}
fetch('/api/remote').then(function(r){return r.json()}).then(function(c){var t=c.theme||{};
 $('name').value=c.studioName||'';$('tag').value=c.tagline||'';$('bg').value=t.backgroundImage||'';
 cols.forEach(function(x){$('c_'+x).value=t[x]||D[x]});
 $('nt').value=c.notice?c.notice.text:'';$('nl').value=(c.notice&&c.notice.level)||'info';
 $('host').value=c.server?c.server.host:'';$('port').value=c.server?c.server.port:''});
$('b').onclick=function(){fetch('/admin/broadcast',{method:'POST',headers:H(),body:JSON.stringify({subject:$('s').value,text:$('t').value,email:$('e').checked,launcher:$('l').checked})}).then(function(r){return r.json()}).then(function(r){$('m').textContent=r.ok?'Listo. Correos en cola: '+r.queued:r.error})};
$('sv').onclick=function(){var o={studioName:$('name').value,tagline:$('tag').value,backgroundImage:$('bg').value,noticeText:$('nt').value,noticeLevel:$('nl').value,host:$('host').value,port:$('port').value};
 cols.forEach(function(x){o[x]=$('c_'+x).value});
 fetch('/admin/settings',{method:'POST',headers:H(),body:JSON.stringify(o)}).then(function(r){return r.json()}).then(function(r){$('m2').textContent=r.ok?'Guardado. Los launchers lo verán en menos de 2 minutos.':r.error})};
</script>`));

app.post('/admin/broadcast', (req, res) => {
  if (!adminOk(req)) return res.status(401).json({ ok: false, error: 'Clave incorrecta.' });
  const { subject, text, email, launcher } = req.body || {};
  if (!subject || !text) return bad(res, 'Falta el asunto o el mensaje.');
  if (launcher) { db.news.unshift({ id: 'n' + Date.now(), title: subject, text, date: new Date().toISOString().slice(0, 10), push: true }); db.news = db.news.slice(0, 20); save(); }
  const to = email ? db.users.filter(u => u.verified && u.news) : [];
  (async () => { for (const u of to) {
    try { await mail(u.email, subject, `${text}\n\n—\n${STUDIO}\nPara dejar de recibir novedades: ${PUBLIC_URL}/unsubscribe?t=${u.unsub}`); }
    catch (e) { console.log('Fallo correo a', u.email, e.message); }
    await new Promise(r => setTimeout(r, 400));
  } })();
  res.json({ ok: true, queued: to.length });
});

app.post('/admin/settings', (req, res) => {
  if (!adminOk(req)) return res.status(401).json({ ok: false, error: 'Clave incorrecta.' });
  const b = req.body || {}, hex = /^#[0-9a-f]{6}$/i, st = {};
  if (b.studioName) st.studioName = String(b.studioName).slice(0, 40);
  if (b.tagline) st.tagline = String(b.tagline).slice(0, 80);
  st.theme = {};
  for (const k of ['background', 'panel', 'text', 'accent', 'accentText']) if (hex.test(b[k] || '')) st.theme[k] = b[k];
  if (/^https:\/\/[^\s'"()]+$/.test(b.backgroundImage || '')) st.theme.backgroundImage = b.backgroundImage;
  st.notice = b.noticeText ? { id: 'n' + Date.now(), level: b.noticeLevel === 'warn' ? 'warn' : 'info', text: String(b.noticeText).slice(0, 200) } : null;
  if (/^[\w.-]+$/.test(b.host || '')) { const p = parseInt(b.port, 10); st.server = { host: b.host, port: p > 0 && p < 65536 ? p : 25565 }; }
  db.settings = st; save(); res.json({ ok: true });
});

app.listen(PORT, () => console.log(`Servidor de cuentas listo en http://localhost:${PORT}  (panel de novedades: /admin)`));
