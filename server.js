const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { MongoClient } = require('mongodb');

const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI; // À définir dans Render → Environment

function hashPw(pw) { return crypto.createHash('sha256').update(pw + '_docshare2026').digest('hex'); }
function uid() { return crypto.randomBytes(8).toString('hex'); }

// ─── MongoDB ──────────────────────────────────────────────────────────────────
let db;
async function connectDB() {
  const client = new MongoClient(MONGO_URI);
  await client.connect();
  db = client.db('docshare');
  console.log('✅ MongoDB connecté');

  // Créer admin par défaut si pas d'utilisateurs
  const users = db.collection('users');
  const count = await users.countDocuments();
  if (count === 0) {
    await users.insertOne({
      id: 'admin_001', name: 'Administrateur',
      email: 'admin@entreprise.com', password: hashPw('admin123'),
      role: 'admin', dept: 'Direction', createdAt: Date.now()
    });
    console.log('✅ Admin créé');
  }
}

// Helpers pour accéder aux collections
const col = (name) => db.collection(name);

// ─── Sessions (en mémoire, OK car légères) ───────────────────────────────────
const sessions = {};
function createSession(userId) { const t = crypto.randomBytes(32).toString('hex'); sessions[t] = { userId, createdAt: Date.now() }; return t; }
function getSession(token) { const s = sessions[token]; if (!s) return null; if (Date.now() - s.createdAt > 86400000) { delete sessions[token]; return null; } return s; }

// ─── Parsers ─────────────────────────────────────────────────────────────────
function parseBody(req) {
  return new Promise((resolve) => {
    let body = [];
    req.on('data', c => body.push(c));
    req.on('end', () => {
      const buf = Buffer.concat(body);
      const ct = req.headers['content-type'] || '';
      if (ct.includes('multipart/form-data')) {
        const boundary = ct.split('boundary=')[1];
        resolve({ type: 'multipart', data: parseMultipart(buf, boundary) });
      } else {
        try { resolve({ type: 'json', data: JSON.parse(buf.toString()) }); }
        catch { resolve({ type: 'raw', data: buf }); }
      }
    });
  });
}

function indexOf(buf, search, start = 0) {
  for (let i = start; i <= buf.length - search.length; i++) {
    let ok = true;
    for (let j = 0; j < search.length; j++) { if (buf[i + j] !== search[j]) { ok = false; break; } }
    if (ok) return i;
  }
  return -1;
}

function parseMultipart(buffer, boundary) {
  const parts = {}, bb = Buffer.from('--' + boundary); let start = 0;
  while (start < buffer.length) {
    const bs = indexOf(buffer, bb, start); if (bs === -1) break;
    start = bs + bb.length;
    if (buffer[start] === 45 && buffer[start + 1] === 45) break;
    if (buffer[start] === 13) start += 2;
    const he = indexOf(buffer, Buffer.from('\r\n\r\n'), start); if (he === -1) break;
    const hdr = buffer.slice(start, he).toString(); start = he + 4;
    const nb = indexOf(buffer, bb, start); const ce = nb === -1 ? buffer.length : nb - 2;
    const content = buffer.slice(start, ce);
    const nm = hdr.match(/name="([^"]+)"/); const fm = hdr.match(/filename="([^"]+)"/);
    if (nm) { parts[nm[1]] = fm ? { filename: fm[1], data: content } : content.toString(); }
    start = nb !== -1 ? nb : buffer.length;
  }
  return parts;
}

// ─── Auth helpers ─────────────────────────────────────────────────────────────
async function auth(req) {
  const t = (req.headers['authorization'] || '').replace('Bearer ', '');
  const s = getSession(t);
  if (!s) return null;
  return await col('users').findOne({ id: s.userId }, { projection: { _id: 0 } });
}
function json(res, data, status = 200) { res.writeHead(status, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }); res.end(JSON.stringify(data)); }
function err(res, msg, status = 400) { json(res, { error: msg }, status); }

function serveHTML(res) {
  const f = path.join(__dirname, 'index.html');
  if (fs.existsSync(f)) { res.writeHead(200, { 'Content-Type': 'text/html;charset=utf-8' }); res.end(fs.readFileSync(f)); }
  else { res.writeHead(404); res.end('index.html not found'); }
}

// ─── Serveur ──────────────────────────────────────────────────────────────────
http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  if (req.method === 'OPTIONS') { res.writeHead(200); res.end(); return; }

  const url = req.url.split('?')[0], method = req.method;

  if (method === 'GET' && (url === '/' || url === '/index.html')) return serveHTML(res);

  // LOGIN
  if (method === 'POST' && url === '/api/login') {
    const b = await parseBody(req); const { email, password } = b.data;
    const user = await col('users').findOne({ email: email?.toLowerCase(), password: hashPw(password) }, { projection: { _id: 0 } });
    if (!user) return err(res, 'Email ou mot de passe incorrect', 401);
    const token = createSession(user.id);
    return json(res, { token, user: { id: user.id, name: user.name, email: user.email, role: user.role, dept: user.dept } });
  }

  // ME
  if (method === 'GET' && url === '/api/me') {
    const u = await auth(req); if (!u) return err(res, 'Non authentifié', 401);
    return json(res, { id: u.id, name: u.name, email: u.email, role: u.role, dept: u.dept });
  }

  // USERS - GET
  if (method === 'GET' && url === '/api/users') {
    const u = await auth(req); if (!u) return err(res, 'Non authentifié', 401);
    const users = await col('users').find({}, { projection: { _id: 0, password: 0 } }).toArray();
    return json(res, users);
  }

  // USERS - CREATE
  if (method === 'POST' && url === '/api/users') {
    const u = await auth(req); if (!u || u.role !== 'admin') return err(res, 'Accès refusé', 403);
    const b = await parseBody(req); const { name, email, password, dept, role } = b.data;
    if (!name || !email || !password) return err(res, 'Champs manquants');
    if (await col('users').findOne({ email: email.toLowerCase() })) return err(res, 'Email déjà utilisé');
    if (password.length < 6) return err(res, 'Mot de passe trop court');
    const nu = { id: uid(), name, email: email.toLowerCase(), password: hashPw(password), dept: dept || '—', role: role || 'user', createdAt: Date.now() };
    await col('users').insertOne(nu);
    return json(res, { id: nu.id, name: nu.name, email: nu.email, role: nu.role, dept: nu.dept, createdAt: nu.createdAt });
  }

  // USERS - UPDATE
  if (method === 'PUT' && url.startsWith('/api/users/')) {
    const u = await auth(req); if (!u || u.role !== 'admin') return err(res, 'Accès refusé', 403);
    const tid = url.split('/api/users/')[1];
    const b = await parseBody(req); const { name, email, password, dept, role } = b.data;
    const target = await col('users').findOne({ id: tid });
    if (!target) return err(res, 'Utilisateur non trouvé', 404);
    if (email && email !== target.email && await col('users').findOne({ email: email.toLowerCase() })) return err(res, 'Email déjà utilisé');
    const upd = {};
    if (name) upd.name = name;
    if (email) upd.email = email.toLowerCase();
    if (password && password.length >= 6) upd.password = hashPw(password);
    if (dept) upd.dept = dept;
    if (role) upd.role = role;
    await col('users').updateOne({ id: tid }, { $set: upd });
    const updated = await col('users').findOne({ id: tid }, { projection: { _id: 0, password: 0 } });
    return json(res, updated);
  }

  // FILES - GET LIST
  if (method === 'GET' && url === '/api/files') {
    const u = await auth(req); if (!u) return err(res, 'Non authentifié', 401);
    const sharedFileIds = (await col('shares').find({ toUserId: u.id }).toArray()).map(s => s.fileId);
    const query = u.role === 'admin' ? {} : { $or: [{ ownerId: u.id }, { id: { $in: sharedFileIds } }] };
    const files = await col('files').find(query, { projection: { _id: 0, data: 0 } }).toArray();
    const users = await col('users').find({}, { projection: { _id: 0, id: 1, name: 1 } }).toArray();
    return json(res, files.map(f => ({ ...f, ownerName: users.find(x => x.id === f.ownerId)?.name })));
  }

  // FILES - UPLOAD
  if (method === 'POST' && url === '/api/files') {
    const u = await auth(req); if (!u) return err(res, 'Non authentifié', 401);
    const b = await parseBody(req); if (b.type !== 'multipart') return err(res, 'Fichier requis');
    const fd = b.data.file; if (!fd || !fd.filename) return err(res, 'Fichier manquant');
    if (!fd.filename.match(/\.(xlsx|xls|csv)$/i)) return err(res, 'Seuls xlsx, xls, csv acceptés');
    const nf = { id: uid(), name: fd.filename, size: fd.data.length, dept: u.dept || '—', ownerId: u.id, uploadedAt: Date.now(), data: fd.data.toString('base64') };
    await col('files').insertOne(nf);
    return json(res, { id: nf.id, name: nf.name, size: nf.size, dept: nf.dept, ownerId: nf.ownerId, ownerName: u.name, uploadedAt: nf.uploadedAt });
  }

  // FILES - DOWNLOAD
  if (method === 'GET' && url.startsWith('/api/files/') && url.endsWith('/download')) {
    const u = await auth(req); if (!u) return err(res, 'Non authentifié', 401);
    const fid = url.split('/api/files/')[1].replace('/download', '');
    const file = await col('files').findOne({ id: fid });
    if (!file) return err(res, 'Fichier non trouvé', 404);
    const ok = file.ownerId === u.id || u.role === 'admin' || await col('shares').findOne({ fileId: fid, toUserId: u.id });
    if (!ok) return err(res, 'Accès refusé', 403);
    const buf = Buffer.from(file.data, 'base64');
    res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Disposition': `attachment; filename="${file.name}"`, 'Content-Length': buf.length, 'Access-Control-Allow-Origin': '*' });
    res.end(buf); return;
  }

  // FILES - DELETE
  if (method === 'DELETE' && url.startsWith('/api/files/')) {
    const u = await auth(req); if (!u) return err(res, 'Non authentifié', 401);
    const fid = url.split('/api/files/')[1];
    const file = await col('files').findOne({ id: fid });
    if (!file) return err(res, 'Fichier non trouvé', 404);
    if (file.ownerId !== u.id && u.role !== 'admin') return err(res, 'Accès refusé', 403);
    await col('files').deleteOne({ id: fid });
    await col('shares').deleteMany({ fileId: fid });
    return json(res, { ok: true });
  }

  // SHARES - GET
  if (method === 'GET' && url === '/api/shares') {
    const u = await auth(req); if (!u) return err(res, 'Non authentifié', 401);
    const query = u.role === 'admin' ? {} : { $or: [{ fromUserId: u.id }, { toUserId: u.id }] };
    const shares = await col('shares').find(query, { projection: { _id: 0 } }).toArray();
    const users = await col('users').find({}, { projection: { _id: 0, id: 1, name: 1 } }).toArray();
    const files = await col('files').find({}, { projection: { _id: 0, id: 1, name: 1 } }).toArray();
    return json(res, shares.map(s => ({ ...s, fromUserName: users.find(x => x.id === s.fromUserId)?.name, toUserName: users.find(x => x.id === s.toUserId)?.name, fileName: files.find(f => f.id === s.fileId)?.name })));
  }

  // SHARES - CREATE
  if (method === 'POST' && url === '/api/shares') {
    const u = await auth(req); if (!u) return err(res, 'Non authentifié', 401);
    const b = await parseBody(req); const { fileId, toUserId } = b.data;
    const file = await col('files').findOne({ id: fileId });
    if (!file) return err(res, 'Fichier non trouvé', 404);
    if (file.ownerId !== u.id && u.role !== 'admin') return err(res, 'Accès refusé', 403);
    if (await col('shares').findOne({ fileId, toUserId })) return err(res, 'Déjà partagé');
    const s = { id: uid(), fileId, fromUserId: u.id, toUserId, sharedAt: Date.now() };
    await col('shares').insertOne(s);
    const toUser = await col('users').findOne({ id: toUserId }, { projection: { name: 1 } });
    return json(res, { ...s, fromUserName: u.name, toUserName: toUser?.name, fileName: file.name });
  }

  res.writeHead(404); res.end(JSON.stringify({ error: 'Route non trouvée' }));

}).listen(PORT, '0.0.0.0', () => console.log(`✅ DocShare sur http://0.0.0.0:${PORT}`));

// Démarrage avec connexion DB
connectDB().catch(e => { console.error('❌ Erreur MongoDB:', e); process.exit(1); });
