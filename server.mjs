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
    CREATE TABLE IF NOT EXISTS agent_files (
      id TEXT PRIMARY KEY, owner TEXT NOT NULL, type TEXT NOT NULL DEFAULT 'nota',
      classification TEXT NOT NULL DEFAULT 'PESSOAL', folder TEXT NOT NULL DEFAULT '',
      title TEXT NOT NULL DEFAULT '', content TEXT NOT NULL DEFAULT '', data_url TEXT,
      shared_with_agents INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
      FOREIGN KEY(owner) REFERENCES users(username) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS audit_log (
      id TEXT PRIMARY KEY, username TEXT NOT NULL, action TEXT NOT NULL, detail TEXT, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS mission_rounds (
      round INTEGER PRIMARY KEY AUTOINCREMENT, status TEXT NOT NULL DEFAULT 'voting',
      opened_by TEXT NOT NULL, opened_at TEXT NOT NULL, closed_at TEXT, winner_option_id TEXT
    );
    CREATE TABLE IF NOT EXISTS mission_options (
      id TEXT PRIMARY KEY, round INTEGER NOT NULL, title TEXT NOT NULL, type TEXT, loc TEXT,
      desc_text TEXT NOT NULL DEFAULT '', clues_json TEXT NOT NULL DEFAULT '[]',
      created_by TEXT NOT NULL, created_at TEXT NOT NULL,
      FOREIGN KEY(round) REFERENCES mission_rounds(round) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS mission_votes (
      round INTEGER NOT NULL, username TEXT NOT NULL, option_id TEXT NOT NULL, created_at TEXT NOT NULL,
      PRIMARY KEY(round, username),
      FOREIGN KEY(round) REFERENCES mission_rounds(round) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS missions (
      id TEXT PRIMARY KEY, code TEXT, level INTEGER NOT NULL DEFAULT 1,
      title TEXT NOT NULL, type TEXT, loc TEXT, priority TEXT NOT NULL DEFAULT 'normal',
      status TEXT NOT NULL DEFAULT 'draft', kind TEXT NOT NULL DEFAULT 'normal',
      summary_agent TEXT NOT NULL DEFAULT '', summary_gm TEXT NOT NULL DEFAULT '',
      hook TEXT NOT NULL DEFAULT '', development TEXT NOT NULL DEFAULT '', climax TEXT NOT NULL DEFAULT '',
      outcomes_json TEXT NOT NULL DEFAULT '[]', consequences_json TEXT NOT NULL DEFAULT '{}',
      triggers_json TEXT NOT NULL DEFAULT '[]', entity TEXT, region_id TEXT, triggered_by TEXT,
      created_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS mission_clues (
      id TEXT PRIMARY KEY, mission_id TEXT NOT NULL, text TEXT NOT NULL, category TEXT NOT NULL DEFAULT 'evidencia',
      reveals TEXT, reveals_mission_id TEXT, visibility TEXT NOT NULL DEFAULT 'publico',
      unlocked_by_clue_id TEXT, found INTEGER NOT NULL DEFAULT 0, order_idx INTEGER NOT NULL DEFAULT 0,
      FOREIGN KEY(mission_id) REFERENCES missions(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS vote_rounds (
      round INTEGER PRIMARY KEY AUTOINCREMENT, status TEXT NOT NULL DEFAULT 'voting',
      mission_ids_json TEXT NOT NULL DEFAULT '[]',
      opened_by TEXT NOT NULL, opened_at TEXT NOT NULL, closed_at TEXT, winner_mission_id TEXT
    );
    CREATE TABLE IF NOT EXISTS mission_ballots (
      round INTEGER NOT NULL, username TEXT NOT NULL, mission_id TEXT NOT NULL, created_at TEXT NOT NULL,
      PRIMARY KEY(round, username),
      FOREIGN KEY(round) REFERENCES vote_rounds(round) ON DELETE CASCADE
    );
  `);
}
const FILE_TYPES = new Set(['nota','imagem','documento','evidencia']);
const CLASSIFICATIONS = new Set(['PESSOAL','CONFIDENCIAL','EVIDENCIA','COMPARTILHADO']);
function publicAgentFile(row){ return { id: row.id, owner: row.owner, type: row.type, classification: row.classification, folder: row.folder, title: row.title, content: row.content, dataUrl: row.data_url, sharedWithAgents: !!row.shared_with_agents, createdAt: row.created_at, updatedAt: row.updated_at }; }
async function logAudit(username, action, detail){
  try{ await run('INSERT INTO audit_log VALUES (?, ?, ?, ?, ?)', ['aud-'+crypto.randomBytes(8).toString('hex'), username, action, detail ? String(detail).slice(0,500) : null, new Date().toISOString()]); }
  catch(e){ console.warn('audit log write failed', e); }
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
  await logAudit(username, 'login', null);
  res.json({ token, user: publicUser(row) });
}));
app.post('/api/auth/logout', auth, ah(async (req, res) => {
  await run('DELETE FROM sessions WHERE token_hash=?', [tokenHash(req.token)]);
  res.setHeader('Set-Cookie', `karsk_session=; HttpOnly; SameSite=${secureCookies ? 'None' : 'Lax'}; Path=/; Max-Age=0${secureCookies ? '; Secure' : ''}`);
  await logAudit(req.user.username, 'logout', null);
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
  const presenceRows = await all('SELECT p.username AS userId, p.username AS agentId, u.display_name AS displayName, p.status, p.region_id AS regionId, p.district_id AS districtId, p.location_id AS locationId, p.online, p.visible_to_agents AS visibleToAgents, p.last_seen AS lastSeen FROM live_presence p LEFT JOIN users u ON u.username=p.username WHERE p.online=1 OR p.last_seen>?', [Date.now()-120000]);
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
app.delete('/api/live/events/:id', auth, admin, ah(async (req, res) => {
  await run('DELETE FROM live_events WHERE id=?', [req.params.id]);
  broadcastLive('event_deleted', { id: req.params.id });
  res.json({ ok: true });
}));
app.delete('/api/live/transmissions/:id', auth, admin, ah(async (req, res) => {
  await run('DELETE FROM live_transmissions WHERE id=?', [req.params.id]);
  broadcastLive('transmission_deleted', { id: req.params.id });
  res.json({ ok: true });
}));

function publicMissionOption(row){ return { id: row.id, round: row.round, title: row.title, type: row.type, loc: row.loc, desc: row.desc_text, clues: JSON.parse(row.clues_json||'[]'), createdBy: row.created_by, createdAt: row.created_at }; }
async function getCurrentMissionRound(){ return await get('SELECT * FROM mission_rounds ORDER BY round DESC LIMIT 1'); }

app.get('/api/missions/current', auth, ah(async (req, res) => {
  const round = await getCurrentMissionRound();
  if (!round) return res.json({ round: null, options: [], tally: {}, myVote: null, voters: null });
  const options = (await all('SELECT * FROM mission_options WHERE round=? ORDER BY created_at', [round.round])).map(publicMissionOption);
  const voteRows = await all('SELECT option_id, COUNT(*) as n FROM mission_votes WHERE round=? GROUP BY option_id', [round.round]);
  const tally = {}; voteRows.forEach(v => { tally[v.option_id] = v.n; });
  const myVoteRow = await get('SELECT option_id FROM mission_votes WHERE round=? AND username=?', [round.round, req.user.username]);
  const voters = req.user.role === 'admin' ? await all('SELECT username, option_id FROM mission_votes WHERE round=?', [round.round]) : null;
  res.json({
    round: { number: round.round, status: round.status, openedBy: round.opened_by, openedAt: round.opened_at, closedAt: round.closed_at, winnerOptionId: round.winner_option_id },
    options, tally, myVote: myVoteRow ? myVoteRow.option_id : null, voters
  });
}));

app.post('/api/missions/round', auth, admin, ah(async (req, res) => {
  const existing = await get("SELECT round FROM mission_rounds WHERE status='voting'");
  if (existing) return res.status(409).json({ error: 'ROUND_ALREADY_OPEN', round: existing.round });
  const now = new Date().toISOString();
  const result = await run('INSERT INTO mission_rounds (status, opened_by, opened_at) VALUES (?, ?, ?)', ['voting', req.user.username, now]);
  const roundNumber = Number(result.lastInsertRowid);
  await logAudit(req.user.username, 'abrir_votacao_missao', 'rodada '+roundNumber);
  broadcastLive('mission_round_opened', { round: roundNumber });
  res.status(201).json({ round: roundNumber });
}));

app.post('/api/missions/round/:round/options', auth, admin, ah(async (req, res) => {
  const round = await get('SELECT * FROM mission_rounds WHERE round=?', [req.params.round]);
  if (!round || round.status !== 'voting') return res.status(400).json({ error: 'ROUND_NOT_OPEN' });
  const now = new Date().toISOString();
  const option = {
    id: 'opt-'+crypto.randomBytes(8).toString('hex'), round: round.round,
    title: String(req.body.title || '').slice(0, 200) || 'MISSÃO SEM TÍTULO',
    type: String(req.body.type || '').slice(0, 60), loc: String(req.body.loc || '').slice(0, 60),
    desc_text: String(req.body.desc || '').slice(0, 4000),
    clues_json: JSON.stringify(Array.isArray(req.body.clues) ? req.body.clues.slice(0, 8).map(c => String(c).slice(0, 300)) : []),
    created_by: req.user.username, created_at: now
  };
  await run('INSERT INTO mission_options VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', Object.values(option));
  broadcastLive('mission_option_added', { round: round.round });
  res.status(201).json({ option: publicMissionOption(option) });
}));

app.delete('/api/missions/options/:id', auth, admin, ah(async (req, res) => {
  const opt = await get('SELECT * FROM mission_options WHERE id=?', [req.params.id]);
  if (!opt) return res.status(404).json({ error: 'NOT_FOUND' });
  await run('DELETE FROM mission_options WHERE id=?', [req.params.id]);
  await run('DELETE FROM mission_votes WHERE option_id=?', [req.params.id]);
  broadcastLive('mission_option_removed', { round: opt.round });
  res.json({ ok: true });
}));

app.post('/api/missions/round/:round/vote', auth, ah(async (req, res) => {
  const round = await get('SELECT * FROM mission_rounds WHERE round=?', [req.params.round]);
  if (!round || round.status !== 'voting') return res.status(400).json({ error: 'ROUND_NOT_OPEN' });
  const option = await get('SELECT * FROM mission_options WHERE id=? AND round=?', [req.body.optionId, round.round]);
  if (!option) return res.status(400).json({ error: 'OPTION_NOT_FOUND' });
  const now = new Date().toISOString();
  await run('INSERT INTO mission_votes VALUES (?, ?, ?, ?) ON CONFLICT(round,username) DO UPDATE SET option_id=excluded.option_id, created_at=excluded.created_at', [round.round, req.user.username, option.id, now]);
  broadcastLive('mission_vote_cast', { round: round.round });
  res.json({ ok: true });
}));

app.post('/api/missions/round/:round/close', auth, admin, ah(async (req, res) => {
  const round = await get('SELECT * FROM mission_rounds WHERE round=?', [req.params.round]);
  if (!round || round.status !== 'voting') return res.status(400).json({ error: 'ROUND_NOT_OPEN' });
  const tallyRows = await all(
    `SELECT v.option_id, COUNT(*) as n, MIN(o.created_at) as oc
     FROM mission_votes v JOIN mission_options o ON o.id=v.option_id
     WHERE v.round=? GROUP BY v.option_id ORDER BY n DESC, oc ASC`, [round.round]);
  const winnerOptionId = tallyRows.length ? tallyRows[0].option_id : null;
  const now = new Date().toISOString();
  await run('UPDATE mission_rounds SET status=?, closed_at=?, winner_option_id=? WHERE round=?', ['closed', now, winnerOptionId, round.round]);
  await logAudit(req.user.username, 'fechar_votacao_missao', 'rodada '+round.round);
  broadcastLive('mission_round_closed', { round: round.round, winnerOptionId });
  res.json({ ok: true, winnerOptionId });
}));

/* ============================================================================
   MISSÕES — sistema completo (Fase 1). Cada missão tem duas camadas: o que o
   agente vê (sem spoiler) e a Visão do Mestre (o que realmente acontece,
   desfechos, gatilhos). Pistas têm categoria e podem ser públicas ou secretas.
   O gerador olha pro estado da cidade (caos/criminalidade) que o cliente manda,
   e escreve uma situação narrativa de verdade, não só um título aleatório.
   ============================================================================ */
function publicMission(row, isAdmin){
  const base = {
    id: row.id, code: row.code, level: row.level, title: row.title, type: row.type, loc: row.loc,
    priority: row.priority, status: row.status, kind: row.kind,
    summaryAgent: row.summary_agent, entity: row.entity, regionId: row.region_id,
    createdAt: row.created_at, updatedAt: row.updated_at
  };
  if (isAdmin){
    base.summaryGm = row.summary_gm; base.hook = row.hook; base.development = row.development; base.climax = row.climax;
    base.outcomes = JSON.parse(row.outcomes_json||'[]'); base.consequences = JSON.parse(row.consequences_json||'{}');
    base.triggers = JSON.parse(row.triggers_json||'[]'); base.createdBy = row.created_by; base.triggeredBy = row.triggered_by;
  }
  return base;
}
function publicClue(row, isAdmin){
  if (row.visibility==='secreto' && !isAdmin) return null;
  return { id: row.id, missionId: row.mission_id, text: row.text, category: row.category,
    reveals: row.reveals, revealsMissionId: row.reveals_mission_id, visibility: row.visibility,
    unlockedByClueId: row.unlocked_by_clue_id, found: !!row.found, order: row.order_idx };
}
async function missionWithClues(id, isAdmin){
  const row = await get('SELECT * FROM missions WHERE id=?', [id]);
  if (!row) return null;
  const m = publicMission(row, isAdmin);
  const clueRows = await all('SELECT * FROM mission_clues WHERE mission_id=? ORDER BY order_idx', [id]);
  m.clues = clueRows.map(c => publicClue(c, isAdmin)).filter(Boolean);
  return m;
}

const MISSION_TYPES = ['Assassinato','Desaparecimento','Anomalia','Culto','Sabotagem','Experimento','Contrabando','Criatura','Corrupção','Sequestro','Sinal','Lugar impossível'];
const MISSION_LOC = ['Old City','New City','Metrô','Porto','Zona Industrial','Distrito Comercial','Hospital','Universidade','Complexo Corporativo','Subterrâneo','Bairro Residencial','Cemitério'];
const MISSION_ENTITIES = ['O Vazio','A Carne','O Sinal','A Máscara','O Abismo'];
const MISSION_CLUE_CATEGORIES = ['evidencia_fisica','testemunho','documento','gravacao','comportamento','ambiental','conexao','falsa'];
const MISSION_CLUE_TEMPLATES = [
  'Um objeto no local tem a mesma marca de outro incidente arquivado.',
  'Uma testemunha jura ter visto a mesma pessoa em dois lugares ao mesmo tempo.',
  'Os registros oficiais do horário do incidente foram alterados.',
  'Um som/cheiro fora do comum é relatado por mais de uma pessoa.',
  'Um documento cita um nome que não deveria estar naquele arquivo.',
  'Uma gravação contém uma resposta a uma pergunta que ninguém fez em voz alta.',
  'Um símbolo repetido aparece em um ponto que não faz sentido geograficamente.',
  'Um dos envolvidos mudou de comportamento dias antes do incidente.',
  'Uma câmera mostra alguém entrando, mas nunca saindo do local.',
  'Um relatório antigo da L.O.B. menciona algo muito parecido.',
  'Uma linha telefônica encontrada no local não pertence a ninguém registrado.',
  'Os relógios do local pararam todos no mesmo horário exato.',
  'Um cheiro ou resíduo químico não combina com a explicação oficial.',
  'Uma pessoa relacionada ao caso desapareceu dos registros públicos.',
  'Uma marca no chão/parede sugere que algo foi arrastado dali.'
];
const MISSION_WORD1=['The','A','No','Last','Black','Hollow','Dead','Silent','Broken','Forgotten','Ashen','Empty','False','Cold','Red'];
const MISSION_WORD2=['Grave','Signal','House','Passenger','Room','Door','Witness','Choir','Archive','Child','Station','Floor','Market','Face','Path','Harbor'];

function pick(arr){ return arr[Math.floor(Math.random()*arr.length)]; }
function pickN(arr, n){ const copy=arr.slice(); const out=[]; for(let i=0;i<n&&copy.length;i++) out.push(copy.splice(Math.floor(Math.random()*copy.length),1)[0]); return out; }

function weightedMissionType(city){
  const crime = Math.max(0, Math.min(100, Number(city&&city.crime)||0));
  const chaos = Math.max(0, Math.min(100, Number(city&&city.chaos)||0));
  const pool = [];
  MISSION_TYPES.forEach(t=>{
    let weight = 3;
    if (['Assassinato','Contrabando','Corrupção','Sequestro'].includes(t)) weight += Math.round(crime/20);
    if (['Anomalia','Criatura','Lugar impossível','Sinal'].includes(t)) weight += Math.round(chaos/20);
    for (let i=0;i<weight;i++) pool.push(t);
  });
  return pick(pool);
}
function generateOneMission({ level, city }){
  const type = weightedMissionType(city);
  const loc = pick(MISSION_LOC);
  const entity = pick(MISSION_ENTITIES);
  const chaos = Math.max(0, Math.min(100, Number(city&&city.chaos)||0));
  const code = 'K-'+String(100+Math.floor(Math.random()*900));
  const title = pick(MISSION_WORD1)+' '+pick(MISSION_WORD2);
  const summaryAgent = `Um caso de ${type.toLowerCase()} é reportado em ${loc}. A L.O.B. recebeu autorização para investigar.`;
  const hook = `A L.O.B. recebe um chamado sobre ${type.toLowerCase()} em ${loc}. `+pick([
    'Um funcionário local aciona a linha de emergência.', 'Uma denúncia anônima chega ao escritório.',
    'Um agente de campo relata algo fora do padrão.', 'Um relatório policial é encaminhado à L.O.B. por engano.'
  ]);
  const development = 'Os agentes encontram sinais de que o caso começou antes do relatado. '+pick([
    'Testemunhas dão versões contraditórias.', 'Parte dos registros foi apagada.',
    'Um segundo grupo parece interessado no mesmo local.', 'A cena não bate com a descrição inicial.'
  ])+' Conforme investigam, a situação se mostra maior do que parecia.';
  const climax = pick([
    `A causa real não é humana — há sinais de influência de ${entity}.`,
    'O verdadeiro responsável está mais próximo da L.O.B. do que imaginavam.',
    'O incidente é só um sintoma de algo maior ainda não resolvido.',
    'O local esconde uma passagem ou estrutura que não deveria existir.'
  ]);
  const summaryGm = 'O QUE REALMENTE ESTÁ ACONTECENDO: '+climax+' Os agentes podem descobrir isso investigando as pistas ligadas ao caso.';
  const outcomes = [
    { label:'Final A', text:'Os agentes resolvem o caso e contêm a situação.' },
    { label:'Final B', text:'O caso é contido, mas com um custo ou consequência lateral.' },
    { label:'Final C', text:'A equipe falha e o caso se transforma em algo maior.' }
  ];
  const consequences = {
    completed: { chaos:-4, crime:-3, entity:0, lob:2 },
    ignored: { chaos:2, crime:3, entity:2, lob:0 },
    failed: { chaos:6, crime:6, entity:5, lob:-2 }
  };
  const clueCount = 3 + Math.floor(Math.random()*4);
  const clueTexts = pickN(MISSION_CLUE_TEMPLATES, clueCount);
  const clues = clueTexts.map((text, i) => ({
    text, category: pick(MISSION_CLUE_CATEGORIES),
    reveals: i===clueCount-1 ? `Conexão com outro caso ligado a ${entity}.` : null,
    visibility: i>=clueCount-2 ? 'secreto' : 'publico'
  }));
  return { code, title, type, loc, priority: chaos>=60?'alta':'normal', kind:'normal', entity, summaryAgent, summaryGm, hook, development, climax, outcomes, consequences, clues };
}

app.get('/api/missions', auth, ah(async (req, res) => {
  const isAdmin = req.user.role==='admin';
  let sql = 'SELECT * FROM missions WHERE 1=1'; const args = [];
  if (req.query.level){ sql += ' AND level=?'; args.push(Number(req.query.level)); }
  if (req.query.status){ sql += ' AND status=?'; args.push(req.query.status); }
  if (!isAdmin) sql += " AND status!='draft'";
  sql += ' ORDER BY created_at DESC';
  const rows = await all(sql, args);
  const missions = [];
  for (const row of rows) missions.push(await missionWithClues(row.id, isAdmin));
  res.json({ missions });
}));

app.post('/api/missions', auth, admin, ah(async (req, res) => {
  const now = new Date().toISOString();
  const id = 'mis-'+crypto.randomBytes(8).toString('hex');
  const row = {
    id, code: req.body.code || null, level: Number(req.body.level)||1,
    title: String(req.body.title||'SEM TÍTULO').slice(0,200), type: req.body.type||null, loc: req.body.loc||null,
    priority: req.body.priority||'normal', status: req.body.status||'draft', kind: req.body.kind||'normal',
    summary_agent: String(req.body.summaryAgent||'').slice(0,2000), summary_gm: String(req.body.summaryGm||'').slice(0,4000),
    hook: String(req.body.hook||'').slice(0,2000), development: String(req.body.development||'').slice(0,3000), climax: String(req.body.climax||'').slice(0,2000),
    outcomes_json: JSON.stringify(req.body.outcomes||[]), consequences_json: JSON.stringify(req.body.consequences||{}),
    triggers_json: JSON.stringify(req.body.triggers||[]), entity: req.body.entity||null, region_id: req.body.regionId||null,
    triggered_by: req.body.triggeredBy||null, created_by: req.user.username, created_at: now, updated_at: now
  };
  await run('INSERT INTO missions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', Object.values(row));
  if (Array.isArray(req.body.clues)){
    for (let i=0;i<req.body.clues.length;i++){
      const c = req.body.clues[i];
      await run('INSERT INTO mission_clues VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', [
        'clue-'+crypto.randomBytes(6).toString('hex'), id, String(c.text||'').slice(0,500), c.category||'evidencia',
        c.reveals||null, c.revealsMissionId||null, c.visibility==='secreto'?'secreto':'publico', c.unlockedByClueId||null, 0, i
      ]);
    }
  }
  await logAudit(req.user.username, 'criar_missao', row.title);
  res.status(201).json({ mission: await missionWithClues(id, true) });
}));

app.post('/api/missions/generate', auth, admin, ah(async (req, res) => {
  const count = Math.max(1, Math.min(5, Number(req.body.count)||1));
  const level = Number(req.body.level)||1;
  const city = req.body.city || {};
  const now = new Date().toISOString();
  const created = [];
  for (let i=0;i<count;i++){
    const draft = generateOneMission({ level, city });
    const id = 'mis-'+crypto.randomBytes(8).toString('hex');
    const row = {
      id, code: draft.code, level, title: draft.title, type: draft.type, loc: draft.loc,
      priority: draft.priority, status: 'draft', kind: draft.kind,
      summary_agent: draft.summaryAgent, summary_gm: draft.summaryGm, hook: draft.hook, development: draft.development, climax: draft.climax,
      outcomes_json: JSON.stringify(draft.outcomes), consequences_json: JSON.stringify(draft.consequences), triggers_json: '[]',
      entity: draft.entity, region_id: null, triggered_by: null,
      created_by: req.user.username, created_at: now, updated_at: now
    };
    await run('INSERT INTO missions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', Object.values(row));
    for (let ci=0; ci<draft.clues.length; ci++){
      const c = draft.clues[ci];
      await run('INSERT INTO mission_clues VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', [
        'clue-'+crypto.randomBytes(6).toString('hex'), id, c.text, c.category, c.reveals||null, null, c.visibility, null, 0, ci
      ]);
    }
    created.push(await missionWithClues(id, true));
  }
  await logAudit(req.user.username, 'gerar_missoes', count+' missão(ões), nível '+level);
  res.json({ missions: created });
}));

app.put('/api/missions/:id', auth, admin, ah(async (req, res) => {
  const existing = await get('SELECT * FROM missions WHERE id=?', [req.params.id]);
  if (!existing) return res.status(404).json({ error: 'NOT_FOUND' });
  const colMap = { code:'code', level:'level', title:'title', type:'type', loc:'loc', priority:'priority', status:'status', kind:'kind', summaryAgent:'summary_agent', summaryGm:'summary_gm', hook:'hook', development:'development', climax:'climax', entity:'entity', regionId:'region_id' };
  const sets = [], args = [];
  Object.keys(colMap).forEach(f => { if (req.body[f]!==undefined){ sets.push(colMap[f]+'=?'); args.push(f==='level' ? Number(req.body[f]) : req.body[f]); } });
  if (req.body.outcomes!==undefined){ sets.push('outcomes_json=?'); args.push(JSON.stringify(req.body.outcomes)); }
  if (req.body.consequences!==undefined){ sets.push('consequences_json=?'); args.push(JSON.stringify(req.body.consequences)); }
  if (req.body.triggers!==undefined){ sets.push('triggers_json=?'); args.push(JSON.stringify(req.body.triggers)); }
  sets.push('updated_at=?'); args.push(new Date().toISOString());
  args.push(req.params.id);
  if (sets.length>1) await run('UPDATE missions SET '+sets.join(', ')+' WHERE id=?', args);
  await logAudit(req.user.username, 'editar_missao', existing.title);
  res.json({ mission: await missionWithClues(req.params.id, true) });
}));

app.delete('/api/missions/:id', auth, admin, ah(async (req, res) => {
  const existing = await get('SELECT * FROM missions WHERE id=?', [req.params.id]);
  if (!existing) return res.status(404).json({ error: 'NOT_FOUND' });
  await run('DELETE FROM missions WHERE id=?', [req.params.id]);
  await run('DELETE FROM mission_clues WHERE mission_id=?', [req.params.id]);
  await logAudit(req.user.username, 'excluir_missao', existing.title);
  res.json({ ok: true });
}));

app.post('/api/missions/:id/clues', auth, admin, ah(async (req, res) => {
  const mission = await get('SELECT id FROM missions WHERE id=?', [req.params.id]);
  if (!mission) return res.status(404).json({ error: 'MISSION_NOT_FOUND' });
  const countRow = await get('SELECT COUNT(*) as n FROM mission_clues WHERE mission_id=?', [req.params.id]);
  const clue = {
    id: 'clue-'+crypto.randomBytes(6).toString('hex'), mission_id: req.params.id,
    text: String(req.body.text||'').slice(0,500), category: req.body.category||'evidencia',
    reveals: req.body.reveals||null, reveals_mission_id: req.body.revealsMissionId||null,
    visibility: req.body.visibility==='secreto'?'secreto':'publico',
    unlocked_by_clue_id: req.body.unlockedByClueId||null, found: 0, order_idx: countRow ? countRow.n : 0
  };
  await run('INSERT INTO mission_clues VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', Object.values(clue));
  res.status(201).json({ clue: publicClue(clue, true) });
}));
app.put('/api/missions/clues/:id', auth, admin, ah(async (req, res) => {
  const existing = await get('SELECT * FROM mission_clues WHERE id=?', [req.params.id]);
  if (!existing) return res.status(404).json({ error: 'NOT_FOUND' });
  const text = req.body.text!==undefined ? String(req.body.text).slice(0,500) : existing.text;
  const category = req.body.category!==undefined ? req.body.category : existing.category;
  const reveals = req.body.reveals!==undefined ? req.body.reveals : existing.reveals;
  const visibility = req.body.visibility!==undefined ? (req.body.visibility==='secreto'?'secreto':'publico') : existing.visibility;
  const found = req.body.found!==undefined ? (req.body.found?1:0) : existing.found;
  await run('UPDATE mission_clues SET text=?, category=?, reveals=?, visibility=?, found=? WHERE id=?', [text, category, reveals, visibility, found, req.params.id]);
  res.json({ clue: publicClue(await get('SELECT * FROM mission_clues WHERE id=?', [req.params.id]), true) });
}));
app.delete('/api/missions/clues/:id', auth, admin, ah(async (req, res) => {
  await run('DELETE FROM mission_clues WHERE id=?', [req.params.id]);
  res.json({ ok: true });
}));

app.get('/api/missions/rounds/current', auth, ah(async (req, res) => {
  const round = await get('SELECT * FROM vote_rounds ORDER BY round DESC LIMIT 1');
  if (!round) return res.json({ round: null, missions: [], tally: {}, myVote: null, voters: null });
  const isAdmin = req.user.role==='admin';
  const missionIds = JSON.parse(round.mission_ids_json||'[]');
  const missions = [];
  for (const mid of missionIds){ const m = await missionWithClues(mid, isAdmin); if (m) missions.push(m); }
  const voteRows = await all('SELECT mission_id, COUNT(*) as n FROM mission_ballots WHERE round=? GROUP BY mission_id', [round.round]);
  const tally = {}; voteRows.forEach(v => { tally[v.mission_id] = v.n; });
  const myVoteRow = await get('SELECT mission_id FROM mission_ballots WHERE round=? AND username=?', [round.round, req.user.username]);
  const voters = isAdmin ? await all('SELECT username, mission_id FROM mission_ballots WHERE round=?', [round.round]) : null;
  res.json({
    round: { number: round.round, status: round.status, openedBy: round.opened_by, openedAt: round.opened_at, closedAt: round.closed_at, winnerMissionId: round.winner_mission_id },
    missions, tally, myVote: myVoteRow ? myVoteRow.mission_id : null, voters
  });
}));
app.post('/api/missions/rounds', auth, admin, ah(async (req, res) => {
  const existing = await get("SELECT round FROM vote_rounds WHERE status='voting'");
  if (existing) return res.status(409).json({ error: 'ROUND_ALREADY_OPEN', round: existing.round });
  const missionIds = Array.isArray(req.body.missionIds) ? req.body.missionIds : [];
  if (!missionIds.length) return res.status(400).json({ error: 'NO_MISSIONS_SELECTED' });
  const now = new Date().toISOString();
  const result = await run('INSERT INTO vote_rounds (status, mission_ids_json, opened_by, opened_at) VALUES (?, ?, ?, ?)', ['voting', JSON.stringify(missionIds), req.user.username, now]);
  const roundNumber = Number(result.lastInsertRowid);
  for (const mid of missionIds) await run("UPDATE missions SET status='voting', updated_at=? WHERE id=?", [now, mid]);
  await logAudit(req.user.username, 'abrir_votacao_missao', 'rodada '+roundNumber);
  broadcastLive('mission_round_opened', { round: roundNumber });
  res.status(201).json({ round: roundNumber });
}));
app.post('/api/missions/rounds/:round/vote', auth, ah(async (req, res) => {
  const round = await get('SELECT * FROM vote_rounds WHERE round=?', [req.params.round]);
  if (!round || round.status!=='voting') return res.status(400).json({ error: 'ROUND_NOT_OPEN' });
  const missionIds = JSON.parse(round.mission_ids_json||'[]');
  if (!missionIds.includes(req.body.missionId)) return res.status(400).json({ error: 'MISSION_NOT_IN_ROUND' });
  const now = new Date().toISOString();
  await run('INSERT INTO mission_ballots VALUES (?, ?, ?, ?) ON CONFLICT(round,username) DO UPDATE SET mission_id=excluded.mission_id, created_at=excluded.created_at', [round.round, req.user.username, req.body.missionId, now]);
  broadcastLive('mission_vote_cast', { round: round.round });
  res.json({ ok: true });
}));
app.post('/api/missions/rounds/:round/close', auth, admin, ah(async (req, res) => {
  const round = await get('SELECT * FROM vote_rounds WHERE round=?', [req.params.round]);
  if (!round || round.status!=='voting') return res.status(400).json({ error: 'ROUND_NOT_OPEN' });
  const missionIds = JSON.parse(round.mission_ids_json||'[]');
  const tallyRows = await all('SELECT mission_id, COUNT(*) as n, MIN(created_at) as oc FROM mission_ballots WHERE round=? GROUP BY mission_id ORDER BY n DESC, oc ASC', [round.round]);
  const winnerMissionId = tallyRows.length ? tallyRows[0].mission_id : missionIds[0];
  const now = new Date().toISOString();
  await run('UPDATE vote_rounds SET status=?, closed_at=?, winner_mission_id=? WHERE round=?', ['closed', now, winnerMissionId, round.round]);
  for (const mid of missionIds) await run('UPDATE missions SET status=?, updated_at=? WHERE id=?', [mid===winnerMissionId ? 'active' : 'ignored', now, mid]);
  await logAudit(req.user.username, 'fechar_votacao_missao', 'rodada '+round.round);
  broadcastLive('mission_round_closed', { round: round.round, winnerMissionId });
  res.json({ ok: true, winnerMissionId });
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

function canSeeFile(requester, row){
  if (requester.username === row.owner) return true;
  if (requester.role === 'admin') return row.classification !== 'PESSOAL';
  return row.classification === 'COMPARTILHADO' && !!row.shared_with_agents;
}
app.get('/api/files/shared-feed', auth, ah(async (req, res) => {
  const rows = await all("SELECT * FROM agent_files WHERE classification='COMPARTILHADO' AND shared_with_agents=1 AND owner!=? ORDER BY updated_at DESC LIMIT 100", [req.user.username]);
  res.json({ files: rows.map(publicAgentFile) });
}));
app.get('/api/files', auth, ah(async (req, res) => {
  const owner = String(req.query.owner || req.user.username).toLowerCase();
  const rows = await all('SELECT * FROM agent_files WHERE owner=? ORDER BY updated_at DESC', [owner]);
  res.json({ files: rows.filter(row => canSeeFile(req.user, row)).map(publicAgentFile) });
}));
app.post('/api/files', auth, ah(async (req, res) => {
  const type = FILE_TYPES.has(req.body.type) ? req.body.type : 'nota';
  const classification = CLASSIFICATIONS.has(req.body.classification) ? req.body.classification : 'PESSOAL';
  const now = new Date().toISOString();
  const row = {
    id: 'file-'+crypto.randomBytes(8).toString('hex'), owner: req.user.username, type, classification,
    folder: String(req.body.folder||'').slice(0,120), title: String(req.body.title||'SEM TÍTULO').slice(0,200),
    content: String(req.body.content||'').slice(0,50000),
    data_url: req.body.dataUrl ? String(req.body.dataUrl).slice(0,6*1024*1024) : null,
    shared_with_agents: (classification==='COMPARTILHADO' && req.body.sharedWithAgents) ? 1 : 0,
    created_at: now, updated_at: now
  };
  await run('INSERT INTO agent_files VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', Object.values(row));
  await logAudit(req.user.username, 'criar_arquivo', type+':'+row.title);
  res.status(201).json({ file: publicAgentFile(row) });
}));
app.put('/api/files/:id', auth, ah(async (req, res) => {
  const existing = await get('SELECT * FROM agent_files WHERE id=?', [req.params.id]);
  if (!existing) return res.status(404).json({ error: 'FILE_NOT_FOUND' });
  if (existing.owner !== req.user.username && req.user.role !== 'admin') return res.status(403).json({ error: 'FORBIDDEN' });
  const classification = CLASSIFICATIONS.has(req.body.classification) ? req.body.classification : existing.classification;
  const title = req.body.title!=null ? String(req.body.title).slice(0,200) : existing.title;
  const content = req.body.content!=null ? String(req.body.content).slice(0,50000) : existing.content;
  const folder = req.body.folder!=null ? String(req.body.folder).slice(0,120) : existing.folder;
  const sharedWithAgents = classification==='COMPARTILHADO' ? (req.body.sharedWithAgents!=null ? (req.body.sharedWithAgents?1:0) : existing.shared_with_agents) : 0;
  const dataUrl = req.body.dataUrl!==undefined ? (req.body.dataUrl ? String(req.body.dataUrl).slice(0,6*1024*1024) : null) : existing.data_url;
  await run('UPDATE agent_files SET title=?, content=?, folder=?, classification=?, shared_with_agents=?, data_url=?, updated_at=? WHERE id=?', [title, content, folder, classification, sharedWithAgents, dataUrl, new Date().toISOString(), req.params.id]);
  await logAudit(req.user.username, 'editar_arquivo', existing.type+':'+title);
  res.json({ file: publicAgentFile(await get('SELECT * FROM agent_files WHERE id=?', [req.params.id])) });
}));
app.delete('/api/files/:id', auth, ah(async (req, res) => {
  const existing = await get('SELECT * FROM agent_files WHERE id=?', [req.params.id]);
  if (!existing) return res.status(404).json({ error: 'FILE_NOT_FOUND' });
  if (existing.owner !== req.user.username && req.user.role !== 'admin') return res.status(403).json({ error: 'FORBIDDEN' });
  await run('DELETE FROM agent_files WHERE id=?', [req.params.id]);
  await logAudit(req.user.username, 'excluir_arquivo', existing.type+':'+existing.title);
  res.json({ ok: true });
}));

app.post('/api/audit', auth, ah(async (req, res) => {
  await logAudit(req.user.username, String(req.body.action||'acao').slice(0,80), req.body.detail);
  res.json({ ok: true });
}));
app.get('/api/audit', auth, admin, ah(async (req, res) => {
  const username = req.query.username ? String(req.query.username).toLowerCase() : null;
  const limit = Math.min(500, Math.max(1, Number(req.query.limit)||200));
  const rows = username
    ? await all('SELECT * FROM audit_log WHERE username=? ORDER BY created_at DESC LIMIT ?', [username, limit])
    : await all('SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ?', [limit]);
  res.json({ entries: rows });
}));

app.get('/api/admin/backup', auth, admin, ah(async (req, res) => {
  const records = await all('SELECT record_key, value_json, updated_at FROM records WHERE scope=?', ['shared']);
  const users = (await all('SELECT username, display_name, role, permissions_json, created_at FROM users')).map(u => ({ username: u.username, displayName: u.display_name, role: u.role, permissions: JSON.parse(u.permissions_json), createdAt: u.created_at }));
  const agentFiles = (await all('SELECT * FROM agent_files')).map(publicAgentFile);
  const auditLog = await all('SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 2000');
  const events = await all('SELECT * FROM live_events');
  const transmissions = await all('SELECT * FROM live_transmissions');
  const states = await all('SELECT * FROM city_states');
  const missionRounds = await all('SELECT * FROM mission_rounds ORDER BY round');
  const missionOptions = (await all('SELECT * FROM mission_options')).map(publicMissionOption);
  const missionVotes = await all('SELECT * FROM mission_votes');
  res.json({
    exportedAt: new Date().toISOString(), version: 3, service: 'karsk-backend',
    shared: records.map(r => ({ key: r.record_key, value: JSON.parse(r.value_json), updatedAt: r.updated_at })),
    users, agentFiles, auditLog, events, transmissions, states, missionRounds, missionOptions, missionVotes
  });
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
