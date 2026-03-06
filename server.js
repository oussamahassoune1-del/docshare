const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data.json');

function hashPw(pw) { return crypto.createHash('sha256').update(pw + '_docshare2026').digest('hex'); }
function uid() { return crypto.randomBytes(8).toString('hex'); }

function loadData() {
  try { if (fs.existsSync(DATA_FILE)) return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); } catch {}
  return { users: [{ id: 'admin_001', name: 'Administrateur', email: 'admin@entreprise.com', password: hashPw('admin123'), role: 'admin', dept: 'Direction', createdAt: Date.now() }], files: [], shares: [] };
}
function saveData(data) { try { fs.writeFileSync(DATA_FILE, JSON.stringify(data)); } catch(e) { console.error(e); } }

let db = loadData();
const sessions = {};

function createSession(userId) { const t = crypto.randomBytes(32).toString('hex'); sessions[t] = { userId, createdAt: Date.now() }; return t; }
function getSession(token) { const s = sessions[token]; if (!s) return null; if (Date.now() - s.createdAt > 86400000) { delete sessions[token]; return null; } return s; }

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

function indexOf(buf, search, start=0) {
  for (let i=start; i<=buf.length-search.length; i++) {
    let ok=true;
    for (let j=0; j<search.length; j++) { if(buf[i+j]!==search[j]){ok=false;break;} }
    if(ok) return i;
  }
  return -1;
}

function parseMultipart(buffer, boundary) {
  const parts={}, bb=Buffer.from('--'+boundary); let start=0;
  while(start<buffer.length) {
    const bs=indexOf(buffer,bb,start); if(bs===-1) break;
    start=bs+bb.length;
    if(buffer[start]===45&&buffer[start+1]===45) break;
    if(buffer[start]===13) start+=2;
    const he=indexOf(buffer,Buffer.from('\r\n\r\n'),start); if(he===-1) break;
    const hdr=buffer.slice(start,he).toString(); start=he+4;
    const nb=indexOf(buffer,bb,start); const ce=nb===-1?buffer.length:nb-2;
    const content=buffer.slice(start,ce);
    const nm=hdr.match(/name="([^"]+)"/); const fm=hdr.match(/filename="([^"]+)"/);
    if(nm){parts[nm[1]]=fm?{filename:fm[1],data:content}:content.toString();}
    start=nb!==-1?nb:buffer.length;
  }
  return parts;
}

function auth(req) { const t=(req.headers['authorization']||'').replace('Bearer ',''); const s=getSession(t); return s?db.users.find(u=>u.id===s.userId):null; }
function json(res,data,status=200){res.writeHead(status,{'Content-Type':'application/json','Access-Control-Allow-Origin':'*'});res.end(JSON.stringify(data));}
function err(res,msg,status=400){json(res,{error:msg},status);}

function serveHTML(res) {
  const f=path.join(__dirname,'index.html');
  if(fs.existsSync(f)){res.writeHead(200,{'Content-Type':'text/html;charset=utf-8'});res.end(fs.readFileSync(f));}
  else{res.writeHead(404);res.end('index.html not found');}
}

http.createServer(async(req,res)=>{
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Methods','GET,POST,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers','Content-Type,Authorization');
  if(req.method==='OPTIONS'){res.writeHead(200);res.end();return;}
  const url=req.url.split('?')[0],method=req.method;

  if(method==='GET'&&(url==='/'||url==='/index.html')) return serveHTML(res);

  if(method==='POST'&&url==='/api/login'){
    const b=await parseBody(req);const{email,password}=b.data;
    const user=db.users.find(u=>u.email.toLowerCase()===email?.toLowerCase()&&u.password===hashPw(password));
    if(!user) return err(res,'Email ou mot de passe incorrect',401);
    const token=createSession(user.id);
    return json(res,{token,user:{id:user.id,name:user.name,email:user.email,role:user.role,dept:user.dept}});
  }

  if(method==='GET'&&url==='/api/me'){
    const u=auth(req);if(!u) return err(res,'Non authentifié',401);
    return json(res,{id:u.id,name:u.name,email:u.email,role:u.role,dept:u.dept});
  }

  if(method==='GET'&&url==='/api/users'){
    const u=auth(req);if(!u||u.role!=='admin') return err(res,'Accès refusé',403);
    return json(res,db.users.map(u=>({id:u.id,name:u.name,email:u.email,role:u.role,dept:u.dept,createdAt:u.createdAt})));
  }

  if(method==='POST'&&url==='/api/users'){
    const u=auth(req);if(!u||u.role!=='admin') return err(res,'Accès refusé',403);
    const b=await parseBody(req);const{name,email,password,dept,role}=b.data;
    if(!name||!email||!password) return err(res,'Champs manquants');
    if(db.users.find(u=>u.email.toLowerCase()===email.toLowerCase())) return err(res,'Email déjà utilisé');
    if(password.length<6) return err(res,'Mot de passe trop court');
    const nu={id:uid(),name,email:email.toLowerCase(),password:hashPw(password),dept:dept||'—',role:role||'user',createdAt:Date.now()};
    db.users.push(nu);saveData(db);
    return json(res,{id:nu.id,name:nu.name,email:nu.email,role:nu.role,dept:nu.dept,createdAt:nu.createdAt});
  }

  if(method==='DELETE'&&url.startsWith('/api/users/')){
    const u=auth(req);if(!u||u.role!=='admin') return err(res,'Accès refusé',403);
    const tid=url.split('/api/users/')[1];
    if(db.users.filter(u=>u.role==='admin').length===1&&db.users.find(u=>u.id===tid)?.role==='admin') return err(res,'Impossible de supprimer le seul admin');
    db.users=db.users.filter(u=>u.id!==tid);saveData(db);
    return json(res,{ok:true});
  }

  if(method==='GET'&&url==='/api/files'){
    const u=auth(req);if(!u) return err(res,'Non authentifié',401);
    const sharedFileIds=db.shares.filter(s=>s.toUserId===u.id).map(s=>s.fileId);
const files=u.role==='admin'
  ? db.files
  : db.files.filter(f=>f.ownerId===u.id || sharedFileIds.includes(f.id));
    return json(res,files.map(f=>({id:f.id,name:f.name,size:f.size,dept:f.dept,ownerId:f.ownerId,ownerName:db.users.find(x=>x.id===f.ownerId)?.name,uploadedAt:f.uploadedAt})));
  }

  if(method==='POST'&&url==='/api/files'){
    const u=auth(req);if(!u) return err(res,'Non authentifié',401);
    const b=await parseBody(req);if(b.type!=='multipart') return err(res,'Fichier requis');
    const fd=b.data.file;if(!fd||!fd.filename) return err(res,'Fichier manquant');
    if(!fd.filename.match(/\.(xlsx|xls|csv)$/i)) return err(res,'Seuls xlsx, xls, csv acceptés');
    const nf={id:uid(),name:fd.filename,size:fd.data.length,dept:u.dept||'—',ownerId:u.id,uploadedAt:Date.now(),data:fd.data.toString('base64')};
    db.files.push(nf);saveData(db);
    return json(res,{id:nf.id,name:nf.name,size:nf.size,dept:nf.dept,ownerId:nf.ownerId,ownerName:u.name,uploadedAt:nf.uploadedAt});
  }

  if(method==='GET'&&url.startsWith('/api/files/')&&url.endsWith('/download')){
    const u=auth(req);if(!u) return err(res,'Non authentifié',401);
    const fid=url.split('/api/files/')[1].replace('/download','');
    const file=db.files.find(f=>f.id===fid);if(!file) return err(res,'Fichier non trouvé',404);
    const ok=file.ownerId===u.id||u.role==='admin'||db.shares.find(s=>s.fileId===fid&&s.toUserId===u.id);
    if(!ok) return err(res,'Accès refusé',403);
    const buf=Buffer.from(file.data,'base64');
    res.writeHead(200,{'Content-Type':'application/octet-stream','Content-Disposition':`attachment; filename="${file.name}"`,'Content-Length':buf.length,'Access-Control-Allow-Origin':'*'});
    res.end(buf);return;
  }

  if(method==='DELETE'&&url.startsWith('/api/files/')){
    const u=auth(req);if(!u) return err(res,'Non authentifié',401);
    const fid=url.split('/api/files/')[1];
    const file=db.files.find(f=>f.id===fid);if(!file) return err(res,'Fichier non trouvé',404);
    if(file.ownerId!==u.id&&u.role!=='admin') return err(res,'Accès refusé',403);
    db.files=db.files.filter(f=>f.id!==fid);db.shares=db.shares.filter(s=>s.fileId!==fid);
    saveData(db);return json(res,{ok:true});
  }

  if(method==='GET'&&url==='/api/shares'){
    const u=auth(req);if(!u) return err(res,'Non authentifié',401);
    const shares=db.shares.filter(s=>s.fromUserId===u.id||s.toUserId===u.id||u.role==='admin');
    return json(res,shares.map(s=>({...s,fromUserName:db.users.find(x=>x.id===s.fromUserId)?.name,toUserName:db.users.find(x=>x.id===s.toUserId)?.name,fileName:db.files.find(f=>f.id===s.fileId)?.name})));
  }

  if(method==='POST'&&url==='/api/shares'){
    const u=auth(req);if(!u) return err(res,'Non authentifié',401);
    const b=await parseBody(req);const{fileId,toUserId}=b.data;
    const file=db.files.find(f=>f.id===fileId);if(!file) return err(res,'Fichier non trouvé',404);
    if(file.ownerId!==u.id&&u.role!=='admin') return err(res,'Accès refusé',403);
    if(db.shares.find(s=>s.fileId===fileId&&s.toUserId===toUserId)) return err(res,'Déjà partagé');
    const s={id:uid(),fileId,fromUserId:u.id,toUserId,sharedAt:Date.now()};
    db.shares.push(s);saveData(db);
    return json(res,{...s,fromUserName:u.name,toUserName:db.users.find(x=>x.id===toUserId)?.name,fileName:file.name});
  }

  res.writeHead(404);res.end(JSON.stringify({error:'Route non trouvée'}));

}).listen(PORT,'0.0.0.0',()=>console.log(`✅ DocShare sur http://0.0.0.0:${PORT}`));
