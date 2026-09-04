import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { createClient } from '@libsql/client';
import crypto from 'node:crypto';

const app = express();
const port = Number(process.env.PORT || 8787);

// TURSO_DATABASE_URL looks like libsql://your-db-org.turso.io — leave it unset and
// this falls back to a local SQLite file, so the exact same code runs for local dev
// and for a real, free, persistent Turso database in production.
const db = createClient({
  url: process.env.TURSO_DATABASE_URL || `file:${process.env.DB_FILE || './karsk.sqlite'}`,
  authToken: process.env.TURSO_AUTH_TOKEN || undefined,
});

const sessions = new Map();
const loginAttempts = new Map();
const sessionMs = Number(process.env.SESSION_DAYS || 7) * 86400000;
const allowedOrigins = String(process.env.WEB_ORIGIN || 'http://localhost:5500').split(',').map(value => value.trim()).filter(Boolean);
const secureCookies = process.env.NODE_ENV === 'production';

app.use(cors({ origin(origin, callback) { callback(null, !origin || allowedOrigins.includes(origin)); }, credentials: true }));
app.use(express.json({ limit: '8mb' }));

// Small helper so async route handlers don't need a try/catch each — Express 4
// does not forward rejected promises to error handling on its own.
const ah = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

async function setupSchema() {
  await db.executeMultiple(`
    CREATE TABLE IF NOT EXISTS users (
      username TEXT PRIMARY KEY, display_name TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'agent',
      salt TEXT NOT NULL, password_hash TEXT NOT NULL, permissions_json TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS records (
      scope TEXT NOT NULL, owner TEXT NOT NULL DEFAULT '', record_key TEXT NOT NULL,
      value_json TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY(scope, owner, record_key)
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, expires_at INTEGER NOT NULL,
      FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS live_presence (
      username TEXT PRIMARY KEY, status TEXT NOT NULL, region_id TEXT, district_id TEXT, location_id TEXT,
      online INTEGER NOT NULL DEFAULT 0, visible_to_agents INTEGER NOT NULL DEFAULT 1, last_seen INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS live_events (
      id TEXT PRIMARY KEY, type TEXT NOT NULL, title TEXT NOT NULL, description TEXT, region_id TEXT, district_id TEXT,
      severity TEXT NOT NULL DEFAULT 'LOW', chaos_delta REAL NOT NULL DEFAULT 0, start_at TEXT NOT NULL, end_at TEXT,
      state_id TEXT, created_by TEXT NOT NULL, created_at TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS live_transmissions (
      id TEXT PRIMARY KEY, sender TEXT NOT NULL, channel TEXT NOT NULL, body TEXT NOT NULL, type TEXT NOT NULL,
      scope TEXT NOT NULL DEFAULT 'GLOBAL', target_id TEXT, interference TEXT NOT NULL DEFAULT 'CLEAR',
      urgent INTEGER NOT NULL DEFAULT 0, scheduled_at TEXT, created_by TEXT NOT NULL, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS city_states (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT, timestamp TEXT NOT NULL,
      created_by TEXT NOT NULL, created_at TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 0
    );
  `);
}

const liveClients = new Set();
function broadcastLive(type, payload) { const message = `data: ${JSON.stringify({ type, payload })}\n\n`; liveClients.forEach(client => client.write(message)); }

const hashPassword = (password, salt) => crypto.scryptSync(password, salt, 64).toString('hex');
function makePassword(password) { const salt = crypto.randomBytes(16).toString('hex'); return { salt, hash: hashPassword(password, salt) }; }
function publicUser(row) { return { username: row.username, displayName: row.display_name, role: row.role, permissions: JSON.parse(row.permissions_json) }; }
function tokenHash(token) { return crypto.createHash('sha256').update(token).digest('hex'); }

async function run(sql, args = []) { return db.execute({ sql, args }); }
async function get(sql, args = []) { const r = await db.execute({ sql, args }); return r.rows[0] || null; }
async function all(sql, args = []) { const r = await db.execute({ sql, args }); return r.rows; }

async function issueSession(username) {
  const token = crypto.randomBytes(32).toString('hex');
  await run('INSERT INTO sessions VALUES (?, ?, ?)', [tokenHash(token), username, Date.now() + sessionMs]);
  return token;
}
function cookieValue(req, name) {
  const header = req.get('cookie') || '';
  const found = header.split(';').map(item => item.trim()).find(item => item.startsWith(name+'='));
  return found ? decodeURIComponent(found.slice(name.length+1)) : '';
}
const auth = ah(async (req, res, next) => {
  const bearer = req.get('authorization')?.replace(/^Bearer\s+/i, '');
  const origin = req.get('origin');
  if (req.method !== 'GET' && origin && !allowedOrigins.includes(origin)) return res.status(403).json({ error: 'ORIGIN_NOT_ALLOWED' });
  const token = bearer || cookieValue(req, 'karsk_session');
  const session = token && await get('SELECT * FROM sessions WHERE token_hash=? AND expires_at>?', [tokenHash(token), Date.now()]);
  if (!session) return res.status(401).json({ error: 'AUTH_REQUIRED' });
  const row = await get('SELECT * FROM users WHERE username=?', [session.username]);
  if (!row) return res.status(401).json({ error: 'AUTH_REQUIRED' });
  req.user = row; req.token = token; next();
});
function admin(req, res, next) { if (req.user.role !== 'admin') return res.status(403).json({ error: 'ADMIN_REQUIRED' }); next(); }
function permissionsFor(user) { try { return JSON.parse(user.permissions_json || '{}'); } catch { return {}; } }
function canAccessEntity(user, entity) {
  if (user.role === 'admin') return true;
  const permissions = permissionsFor(user);
  if (permissions.allRegions) return true;
  const allowed = new Set(permissions.allowedRegionIds || []);
  return Boolean(entity && (allowed.has(entity.id) || allowed.has(entity.parent)));
}
function filterSharedValue(user, key, value) {
  if (user.role === 'admin') return value;
  const permissions = permissionsFor(user);
  if (key === 'karsk:news' && Array.isArray(value)) {
    const allowed = new Set(permissions.allowedNewsIds || []);
    return value.filter(item => item.published && (permissions.allNews || allowed.has(item.id) || (item.regionId && (permissions.allowedRegionIds || []).includes(item.regionId))));
  }
  if (key === 'karsk:mission-archive' && Array.isArray(value)) {
    const allowed = new Set(permissions.allowedArchiveIds || []);
    return value.filter(item => item.published !== false && (permissions.allArchive || allowed.has(item.id) || (item.regionId && (permissions.allowedRegionIds || []).includes(item.regionId))));
  }
  if (key.startsWith('karsk:custom:')) return canAccessEntity(user, value) ? value : null;
  if (key.startsWith('karsk:override:')) return canAccessEntity(user, { id: key.slice('karsk:override:'.length) }) ? value : null;
  const readableKeys = new Set(['karsk:map-titles','karsk:urban-areas','karsk:build-settings','karsk:news','karsk:mission-archive','karsk:map-background']);
  const readablePrefix = ['karsk:media:'];
  if (readableKeys.has(key) || readablePrefix.some(prefix => key.startsWith(prefix))) return value;
  return null;
}
function canReadSharedKey(user, key, value) { return user.role === 'admin' || filterSharedValue(user, key, value) !== null; }

app.get('/api/health', (_req, res) => res.json({ ok: true, service: 'karsk-backend' }));

app.post('/api/auth/login', ah(async (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const now = Date.now();
  const attempt = loginAttempts.get(username) || { count:0, blockedUntil:0 };
  if (attempt.blockedUntil > now) return res.status(429).json({ error: 'TOO_MANY_ATTEMPTS' });
  const row = await get('SELECT * FROM users WHERE username=?', [username]);
  let valid = false;
  try { valid = Boolean(row && crypto.timingSafeEqual(Buffer.from(hashPassword(password, row.salt), 'hex'), Buffer.from(row.password_hash, 'hex'))); } catch { valid = false; }
  if (!valid) {
    attempt.count += 1;
    if (attempt.count >= 5) { attempt.count = 0; attempt.blockedUntil = now + 15*60*1000; }
    loginAttempts.set(username, attempt);
    return res.status(401).json({ error: 'INVALID_CREDENTIALS' });
  }
  loginAttempts.delete(username);
  const token = await issueSession(username);
  res.setHeader('Set-Cookie', `karsk_session=${encodeURIComponent(token)}; HttpOnly; SameSite=${secureCookies ? 'None' : 'Lax'}; Path=/; Max-Age=${Math.floor(sessionMs/1000)}${secureCookies ? '; Secure' : ''}`);
  res.json({ token, user: publicUser(row) });
}));
app.post('/api/auth/logout', auth, ah(async (req, res) => {
  await run('DELETE FROM sessions WHERE token_hash=?', [tokenHash(req.token)]);
  res.setHeader('Set-Cookie', `karsk_session=; HttpOnly; SameSite=${secureCookies ? 'None' : 'Lax'}; Path=/; Max-Age=0${secureCookies ? '; Secure' : ''}`);
  res.json({ ok: true });
}));
app.get('/api/auth/me', auth, (req, res) => res.json({ user: publicUser(req.user) }));

app.get('/api/live/stream', auth, (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream'); res.setHeader('Cache-Control', 'no-cache'); res.setHeader('Connection', 'keep-alive'); res.flushHeaders();
  liveClients.add(res); res.write(`data: ${JSON.stringify({ type:'ready' })}\n\n`); req.on('close', () => liveClients.delete(res));
});
app.get('/api/live/snapshot', auth, ah(async (req, res) => {
  const permissions=permissionsFor(req.user), allowed=new Set(permissions.allowedRegionIds||[]);
  const visibleRegion=(regionId,districtId)=>req.user.role==='admin'||permissions.allRegions||(!regionId&&!districtId)||allowed.has(regionId)||allowed.has(districtId);
  const presenceRows = await all('SELECT username AS userId, username AS agentId, status, region_id AS regionId, district_id AS districtId, location_id AS locationId, online, visible_to_agents AS visibleToAgents, last_seen AS lastSeen FROM live_presence WHERE online=1 OR last_seen>?', [Date.now()-120000]);
  const presence = presenceRows.filter(item => (req.user.role==='admin' || item.visibleToAgents) && visibleRegion(item.regionId,item.districtId));
  const eventRows = await all('SELECT * FROM live_events WHERE active=1 ORDER BY created_at DESC LIMIT 100');
  const events = eventRows.filter(item=>visibleRegion(item.region_id,item.district_id));
  const transmissionRows = await all('SELECT * FROM live_transmissions ORDER BY created_at DESC LIMIT 100');
  const transmissions = transmissionRows.filter(item=>item.scope==='GLOBAL'||req.user.role==='admin'||(item.scope==='REGIONAL'&&allowed.has(item.target_id))||(item.scope==='DISTRICT'&&allowed.has(item.target_id))||(item.scope==='PRIVATE'&&item.target_id===req.user.username));
  const states = await all('SELECT * FROM city_states ORDER BY timestamp DESC LIMIT 50');
  res.json({ presence, events, transmissions, states });
}));
app.put('/api/live/presence', auth, ah(async (req, res) => {
  const row = { status:String(req.body.status||'ONLINE'), regionId:req.body.regionId||null, districtId:req.body.districtId||null, locationId:req.body.locationId||null, online:req.body.online===false?0:1, visibleToAgents:req.body.visibleToAgents===false?0:1, lastSeen:Date.now() };
  await run('INSERT INTO live_presence VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(username) DO UPDATE SET status=excluded.status, region_id=excluded.region_id, district_id=excluded.district_id, location_id=excluded.location_id, online=excluded.online, visible_to_agents=excluded.visible_to_agents, last_seen=excluded.last_seen', [req.user.username,row.status,row.regionId,row.districtId,row.locationId,row.online,row.visibleToAgents,row.lastSeen]);
  broadcastLive('presence', row); res.json({ ok:true, presence:row });
}));
app.post('/api/live/events', auth, admin, ah(async (req, res) => {
  const event={id:'evt-'+crypto.randomBytes(8).toString('hex'),type:String(req.body.type||'ALERT'),title:String(req.body.title||'EVENTO SEM TÍTULO'),description:String(req.body.description||''),region_id:req.body.regionId||null,district_id:req.body.districtId||null,severity:String(req.body.severity||'LOW'),chaos_delta:Number(req.body.chaosDelta||0),start_at:req.body.startAt||new Date().toISOString(),end_at:req.body.endAt||null,state_id:req.body.stateId||null,created_by:req.user.username,created_at:new Date().toISOString(),active:1};
  await run('INSERT INTO live_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', Object.values(event));
  broadcastLive('event',event);
  if (['HIGH','CRITICAL'].includes(event.severity)) {
    const transmission={id:'tx-'+crypto.randomBytes(8).toString('hex'),sender:'CENTRAL',channel:'CENTRAL',body:event.title+(event.description?' — '+event.description:''),type:'EMERGENCY',scope:event.district_id?'DISTRICT':event.region_id?'REGIONAL':'GLOBAL',target_id:event.district_id||event.region_id,interference:event.severity==='CRITICAL'?'HIGH':'MEDIUM',urgent:1,scheduled_at:null,created_by:req.user.username,created_at:new Date().toISOString()};
    await run('INSERT INTO live_transmissions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', Object.values(transmission));
    broadcastLive('transmission',transmission);
  }
  res.status(201).json({ event });
}));
app.post('/api/live/transmissions', auth, admin, ah(async (req, res) => {
  const transmission={id:'tx-'+crypto.randomBytes(8).toString('hex'),sender:String(req.body.sender||'CENTRAL'),channel:String(req.body.channel||'CENTRAL'),body:String(req.body.body||''),type:String(req.body.type||'CENTRAL'),scope:String(req.body.scope||'GLOBAL'),target_id:req.body.targetId||null,interference:String(req.body.interference||'CLEAR'),urgent:req.body.urgent?1:0,scheduled_at:req.body.scheduledAt||null,created_by:req.user.username,created_at:new Date().toISOString()};
  await run('INSERT INTO live_transmissions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', Object.values(transmission));
  broadcastLive('transmission',transmission); res.status(201).json({ transmission });
}));
app.post('/api/live/states', auth, admin, ah(async (req, res) => {
  const state={id:'state-'+crypto.randomBytes(8).toString('hex'),name:String(req.body.name||'PRESENTE'),description:String(req.body.description||''),timestamp:req.body.timestamp||new Date().toISOString(),created_by:req.user.username,created_at:new Date().toISOString(),active:1};
  await run('UPDATE city_states SET active=0');
  await run('INSERT INTO city_states VALUES (?, ?, ?, ?, ?, ?, ?)', Object.values(state));
  broadcastLive('state',state); res.status(201).json({ state });
}));

app.get('/api/users', auth, admin, ah(async (_req, res) => res.json({ users: (await all('SELECT * FROM users ORDER BY username')).map(publicUser) })));
app.post('/api/users', auth, admin, ah(async (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const displayName = String(req.body.displayName || username).trim();
  const password = String(req.body.password || '');
  if (!/^[a-z0-9][a-z0-9._-]{2,48}$/.test(username) || password.length < 10) return res.status(400).json({ error: 'USERNAME_OR_PASSWORD_INVALID' });
  if (await get('SELECT username FROM users WHERE username=?', [username])) return res.status(409).json({ error: 'USERNAME_EXISTS' });
  const p = makePassword(password);
  await run('INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?)', [username, displayName, 'agent', p.salt, p.hash, JSON.stringify(req.body.permissions || {}), new Date().toISOString()]);
  res.status(201).json({ user: publicUser(await get('SELECT * FROM users WHERE username=?', [username])) });
}));
app.put('/api/users/:username', auth, admin, ah(async (req, res) => {
  const username = req.params.username.toLowerCase();
  const current = await get('SELECT * FROM users WHERE username=?', [username]);
  if (!current) return res.status(404).json({ error: 'USER_NOT_FOUND' });
  const displayName = String(req.body.displayName || current.display_name).trim();
  const permissions = JSON.stringify(req.body.permissions || JSON.parse(current.permissions_json));
  if (req.body.password) {
    const p = makePassword(String(req.body.password));
    await run('UPDATE users SET display_name=?, salt=?, password_hash=?, permissions_json=? WHERE username=?', [displayName, p.salt, p.hash, permissions, username]);
  } else {
    await run('UPDATE users SET display_name=?, permissions_json=? WHERE username=?', [displayName, permissions, username]);
  }
  res.json({ user: publicUser(await get('SELECT * FROM users WHERE username=?', [username])) });
}));
app.delete('/api/users/:username', auth, admin, ah(async (req, res) => {
  const username = req.params.username.toLowerCase();
  if (username === req.user.username) return res.status(400).json({ error: 'CANNOT_DELETE_SELF' });
  await run('DELETE FROM users WHERE username=?', [username]);
  res.json({ ok: true });
}));

app.get('/api/storage/:scope/:key', auth, ah(async (req, res) => {
  const scope = req.params.scope === 'shared' ? 'shared' : 'personal';
  const owner = scope === 'shared' ? '' : req.user.username;
  const row = await get('SELECT value_json FROM records WHERE scope=? AND owner=? AND record_key=?', [scope, owner, req.params.key]);
  const raw = row ? JSON.parse(row.value_json) : null;
  const value = (scope === 'shared' && row) ? filterSharedValue(req.user, req.params.key, raw) : raw;
  res.json({ value });
}));
app.get('/api/storage/:scope', auth, ah(async (req, res) => {
  const scope = req.params.scope === 'shared' ? 'shared' : 'personal';
  const owner = scope === 'shared' ? '' : req.user.username;
  const prefix = String(req.query.prefix || '');
  const rows = await all('SELECT record_key, value_json FROM records WHERE scope=? AND owner=? AND record_key LIKE ?', [scope, owner, prefix+'%']);
  const keys = rows.filter(row => {
    if (scope !== 'shared') return true;
    try { return canReadSharedKey(req.user, row.record_key, JSON.parse(row.value_json)); } catch { return false; }
  }).map(row => row.record_key);
  res.json({ keys });
}));
app.put('/api/storage/:scope/:key', auth, ah(async (req, res) => {
  const scope = req.params.scope === 'shared' ? 'shared' : 'personal';
  const owner = scope === 'shared' ? '' : req.user.username;
  if (scope === 'shared' && req.user.role !== 'admin') return res.status(403).json({ error: 'ADMIN_REQUIRED' });
  const now = new Date().toISOString();
  await run('INSERT INTO records VALUES (?, ?, ?, ?, ?) ON CONFLICT(scope,owner,record_key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at', [scope, owner, req.params.key, JSON.stringify(req.body.value), now]);
  res.json({ ok: true });
}));
app.delete('/api/storage/:scope/:key', auth, ah(async (req, res) => {
  const scope = req.params.scope === 'shared' ? 'shared' : 'personal';
  const owner = scope === 'shared' ? '' : req.user.username;
  if (scope === 'shared' && req.user.role !== 'admin') return res.status(403).json({ error: 'ADMIN_REQUIRED' });
  await run('DELETE FROM records WHERE scope=? AND owner=? AND record_key=?', [scope, owner, req.params.key]);
  res.json({ ok: true });
}));

// Errors from any ah()-wrapped handler land here instead of crashing the process.
app.use((err, _req, res, _next) => { console.error('Unhandled route error:', err); res.status(500).json({ error: 'INTERNAL_ERROR' }); });

async function main() {
  await setupSchema();

  const adminUsername = String(process.env.KARSK_ADMIN_USERNAME || 'dinamo').toLowerCase();
  if (!(await get('SELECT username FROM users WHERE username=?', [adminUsername]))) {
    const password = process.env.KARSK_ADMIN_PASSWORD;
    if (!password || password === 'change-this-before-production') {
      console.warn('Set KARSK_ADMIN_PASSWORD before creating the first admin account.');
    } else {
      const p = makePassword(password);
      await run('INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?)', [adminUsername, 'DINAMO', 'admin', p.salt, p.hash, JSON.stringify({ allRegions:true, allNews:true, allArchive:true, allDocuments:true }), new Date().toISOString()]);
    }
  }

  setInterval(() => { run('DELETE FROM sessions WHERE expires_at<=?', [Date.now()]).catch(e => console.error('session cleanup failed', e)); }, 15*60*1000).unref();

  app.listen(port, () => console.log(`KARSK backend listening on http://localhost:${port}`));
}

main().catch(err => { console.error('Fatal startup error:', err); process.exit(1); });
