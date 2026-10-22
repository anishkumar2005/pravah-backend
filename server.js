// PRAVAAH BACKEND SERVER
// - receives sensor readings and calculates risk
// - serves the home page, live map and safe-route planner to everyone
// - serves the municipal dashboard only to signed-in staff
// - tracks each overflow through: alert raised, crew assigned, work in progress, cleaned

const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(cors());
app.use(express.json({ limit: '50kb' }));
app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin'
  });
  next();
});

// ---------- SETTINGS ----------
// Risk thresholds, as a score out of 100 (percent full plus the rate-of-rise bonus).
// Change these two numbers, or set WATCH_SCORE / CRITICAL_SCORE on Render, to move the states.
const WATCH_SCORE = Number(process.env.WATCH_SCORE) || 40;
const CRITICAL_SCORE = Number(process.env.CRITICAL_SCORE) || 90;
const HAZARD_RADIUS_M = Number(process.env.HAZARD_RADIUS_M) || 250;   // area around an overflowing drain to avoid
const STALE_MIN = 30;                                                 // readings older than this are ignored for routing
const CLEANED_SHOW_MIN = Number(process.env.CLEANED_SHOW_MIN) || 10;  // how long "Cleaned" stays visible
const SESSION_HOURS = 8;
const OSRM_URL = process.env.OSRM_URL || 'https://router.project-osrm.org';
const NOMINATIM_URL = process.env.NOMINATIM_URL || 'https://nominatim.openstreetmap.org';
const USER_AGENT = 'Pravaah-flood-demo/2.0 (student project)';

// ======================================================================
//  STAFF SIGN-IN
//  Set MUNICIPAL_USERS on Render, for example:  ravi:MyPassword1;meena:OtherPass2
// ======================================================================
function parseUsers(raw) {
  const users = {};
  String(raw || '').split(';').forEach(pair => {
    const i = pair.indexOf(':');
    if (i < 1) return;
    const name = pair.slice(0, i).trim();
    const pass = pair.slice(i + 1).trim();
    if (!name || !pass) return;
    const salt = crypto.randomBytes(16);
    users[name.toLowerCase()] = { name, salt, hash: crypto.scryptSync(pass, salt, 32) };
  });
  return users;
}
const USERS = parseUsers(process.env.MUNICIPAL_USERS);
if (!Object.keys(USERS).length) {
  console.warn('WARNING: MUNICIPAL_USERS is not set, so nobody can sign in to the staff dashboard.');
}
const SECRET = process.env.SESSION_SECRET
  ? Buffer.from(process.env.SESSION_SECRET)
  : crypto.createHash('sha256').update('pravaah-session:' + (process.env.MUNICIPAL_USERS || crypto.randomBytes(16).toString('hex'))).digest();

const DUMMY_SALT = crypto.randomBytes(16);
function checkLogin(username, password) {
  const u = USERS[String(username || '').trim().toLowerCase()];
  const pw = String(password || '').slice(0, 200);
  const hash = crypto.scryptSync(pw, u ? u.salt : DUMMY_SALT, 32);   // always do the work, so timing doesn't reveal valid names
  const expected = u ? u.hash : crypto.randomBytes(32);
  const same = crypto.timingSafeEqual(hash, expected);
  return u && same ? u.name : null;
}

function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  return body + '.' + sig;
}
function verifyToken(token) {
  if (!token || token.indexOf('.') < 0) return null;
  const [body, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  const a = Buffer.from(sig || ''), b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const p = JSON.parse(Buffer.from(body, 'base64url').toString());
    return p && p.exp > Date.now() ? p : null;
  } catch (e) { return null; }
}
function getCookie(req, name) {
  const header = req.headers.cookie || '';
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) {
      try { return decodeURIComponent(part.slice(i + 1).trim()); } catch (e) { return null; }
    }
  }
  return null;
}
function currentUser(req) {
  const p = verifyToken(getCookie(req, 'pravaah_session'));
  return p && USERS[String(p.u).toLowerCase()] ? USERS[String(p.u).toLowerCase()].name : null;
}
function startSession(req, res, name) {
  const token = sign({ u: name, exp: Date.now() + SESSION_HOURS * 3600e3 });
  res.append('Set-Cookie', `pravaah_session=${encodeURIComponent(token)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_HOURS * 3600}${req.secure ? '; Secure' : ''}`);
}
function endSession(req, res) {
  res.append('Set-Cookie', `pravaah_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${req.secure ? '; Secure' : ''}`);
}
function requireStaffPage(req, res, next) {
  const u = currentUser(req);
  if (!u) return res.redirect('/login?next=/dashboard');
  req.user = u;
  next();
}
function requireStaffApi(req, res, next) {
  const u = currentUser(req);
  if (!u) return res.status(401).json({ error: 'Please sign in as municipal staff.' });
  req.user = u;
  next();
}

// Too many wrong passwords from one address locks sign-in for a while
const failures = new Map();
const MAX_FAILS = 5, LOCK_MS = 10 * 60e3;
function lockedSeconds(ip) {
  const f = failures.get(ip);
  if (!f) return 0;
  if (Date.now() - f.first > LOCK_MS) { failures.delete(ip); return 0; }
  return f.n >= MAX_FAILS ? Math.ceil((f.first + LOCK_MS - Date.now()) / 1000) : 0;
}
function recordFailure(ip) {
  const f = failures.get(ip);
  if (!f || Date.now() - f.first > LOCK_MS) failures.set(ip, { n: 1, first: Date.now() });
  else f.n++;
}

app.post('/api/auth/login', (req, res) => {
  if (!Object.keys(USERS).length) {
    return res.status(503).json({ error: 'Staff sign-in has not been set up on the server yet.' });
  }
  if (!req.is('application/json')) return res.status(415).json({ error: 'Unsupported request.' });
  const wait = lockedSeconds(req.ip);
  if (wait) {
    res.set('Retry-After', String(wait));
    return res.status(429).json({ error: `Too many wrong attempts. Try again in ${Math.ceil(wait / 60)} minute(s).` });
  }
  const name = checkLogin(req.body && req.body.username, req.body && req.body.password);
  if (!name) {
    recordFailure(req.ip);
    return res.status(401).json({ error: 'Incorrect username or password.' });
  }
  failures.delete(req.ip);
  startSession(req, res, name);
  res.json({ ok: true, user: name });
});
app.post('/api/auth/logout', (req, res) => { endSession(req, res); res.json({ ok: true }); });
app.get('/api/auth/me', (req, res) => {
  const u = currentUser(req);
  if (!u) return res.status(401).json({ error: 'Not signed in.' });
  res.json({ user: u });
});

// ======================================================================
//  DRAIN DATA AND THE CLEAN-UP WORKFLOW
// ======================================================================
const readings = {};   // node_id -> { history, latest, work_status, work_updated, work_log, last_cleaned }

const STATUS_LABEL = {
  monitoring: 'Monitoring',
  alert: 'Alert raised, waiting for a crew',
  crew_assigned: 'Crew assigned',
  in_progress: 'Work in progress',
  cleaned: 'Cleaned'
};
const NEXT_STATUS = { monitoring: 'crew_assigned', alert: 'crew_assigned', crew_assigned: 'in_progress', in_progress: 'cleaned' };

function calculateRisk(percentFull, rateOfRise) {
  let score = percentFull;
  if (rateOfRise > 2) score += 20;
  else if (rateOfRise > 0.5) score += 10;
  return Math.max(0, Math.min(Math.round(score), 100));
}
function getRiskLevel(score) {
  if (score >= CRITICAL_SCORE) return 'critical';
  if (score >= WATCH_SCORE) return 'watch';
  return 'safe';
}
function setWork(node, status, by) {
  const at = new Date().toISOString();
  node.work_status = status;
  node.work_updated = at;
  node.work_log.push({ status, at, by });
  if (node.work_log.length > 60) node.work_log.shift();
  if (status === 'cleaned') node.last_cleaned = at;
}
// "Cleaned" is shown for a while, then the drain returns to normal monitoring
function refreshWork(node) {
  if (node.work_status === 'cleaned' && node.latest && node.latest.risk_level === 'safe' &&
      Date.now() - new Date(node.work_updated).getTime() > CLEANED_SHOW_MIN * 60e3) {
    setWork(node, 'monitoring', 'system');
  }
}
function publicNode(id) {
  const n = readings[id];
  refreshWork(n);
  return {
    node_id: id,
    ...n.latest,
    work_status: n.work_status,
    work_label: STATUS_LABEL[n.work_status],
    work_updated: n.work_updated,
    last_cleaned: n.last_cleaned,
    hazard_radius_m: HAZARD_RADIUS_M,
    watch_pct: WATCH_SCORE,
    critical_pct: CRITICAL_SCORE
  };
}

app.post('/api/readings', (req, res) => {
  const d = req.body || {};
  const id = typeof d.node_id === 'string' ? d.node_id.trim().slice(0, 32) : '';
  const level = Number(d.water_level_cm);
  const pct = Number(d.percent_full);
  const rate = d.rate_of_rise_cm_per_min === undefined ? 0 : Number(d.rate_of_rise_cm_per_min);
  const cap = Number(d.capacity_cm);
  const lat = Number(d.lat), lng = Number(d.lng);
  if (!id || !isFinite(level) || !isFinite(pct)) {
    return res.status(400).json({ error: 'Missing or invalid fields' });
  }

  const riskScore = calculateRisk(pct, isFinite(rate) ? rate : 0);
  const record = {
    node_id: id,
    ...(isFinite(lat) && Math.abs(lat) <= 90 ? { lat } : {}),
    ...(isFinite(lng) && Math.abs(lng) <= 180 ? { lng } : {}),
    water_level_cm: level,
    rate_of_rise_cm_per_min: isFinite(rate) ? rate : 0,
    percent_full: pct,
    ...(isFinite(cap) && cap > 0 ? { capacity_cm: cap } : {}),
    risk_score: riskScore,
    risk_level: getRiskLevel(riskScore),
    timestamp: new Date().toISOString()
  };

  if (!readings[id]) {
    readings[id] = { history: [], latest: null, work_status: 'monitoring', work_updated: null, work_log: [], last_cleaned: null };
  }
  const node = readings[id];
  const prevRisk = node.latest ? node.latest.risk_level : null;
  node.latest = record;
  node.history.push(record);
  if (node.history.length > 500) node.history.shift();

  // The workflow follows the sensor: a critical drain raises an alert automatically
  refreshWork(node);
  if (record.risk_level === 'critical') {
    if (node.work_status === 'monitoring') setWork(node, 'alert', 'system');
    else if (node.work_status === 'cleaned' && prevRisk !== 'critical') setWork(node, 'alert', 'system');
  } else if (record.risk_level === 'safe' && node.work_status === 'alert') {
    setWork(node, 'monitoring', 'system');
  }

  console.log('Received:', id, record.water_level_cm, 'cm,', record.risk_level, '/', node.work_status);
  res.status(200).json({ message: 'Reading saved', risk_level: record.risk_level, work_status: node.work_status });
});

app.get('/api/nodes', (req, res) => {
  res.json(Object.keys(readings).filter(id => readings[id].latest).map(publicNode));
});

app.get('/api/nodes/:id/history', (req, res) => {
  const node = readings[req.params.id];
  if (!node) return res.status(404).json({ error: 'Node not found' });
  res.json(node.history);
});

// ---------- staff only ----------
app.get('/api/staff/nodes', requireStaffApi, (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json(Object.keys(readings).filter(id => readings[id].latest).map(id => ({
    ...publicNode(id),
    work_log: readings[id].work_log
  })));
});

app.post('/api/nodes/:id/status', requireStaffApi, (req, res) => {
  if (!req.is('application/json')) return res.status(415).json({ error: 'Unsupported request.' });
  const node = readings[req.params.id];
  if (!node || !node.latest) return res.status(404).json({ error: 'Node not found' });
  refreshWork(node);
  const wanted = req.body && req.body.status;
  if (NEXT_STATUS[node.work_status] !== wanted) {
    return res.status(400).json({ error: `Cannot move from "${STATUS_LABEL[node.work_status]}" to "${STATUS_LABEL[wanted] || wanted}".` });
  }
  setWork(node, wanted, req.user);
  res.json({ ok: true, node: { ...publicNode(req.params.id), work_log: node.work_log } });
});

// ======================================================================
//  SAFE ROUTE PLANNER
//  Uses OpenStreetMap data: Nominatim (place search) and OSRM (road routes)
// ======================================================================
function limiter(max, windowMs) {
  const hits = new Map();
  return (req, res, next) => {
    const now = Date.now();
    const recent = (hits.get(req.ip) || []).filter(t => now - t < windowMs);
    if (recent.length >= max) {
      res.set('Retry-After', String(Math.ceil(windowMs / 1000)));
      return res.status(429).json({ error: 'Too many requests. Please wait a minute and try again.' });
    }
    recent.push(now);
    hits.set(req.ip, recent);
    if (hits.size > 5000) hits.clear();
    next();
  };
}
async function fetchWithTimeout(url, opts, ms) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), ms);
  try { return await fetch(url, { ...(opts || {}), signal: ac.signal }); }
  finally { clearTimeout(t); }
}
const sleep = ms => new Promise(r => setTimeout(r, ms));

// ----- place search -----
let nextGeocodeSlot = 0;
const geoCache = new Map();
app.get('/api/geocode', limiter(30, 60e3), async (req, res) => {
  const q = String(req.query.q || '').trim().slice(0, 120);
  if (q.length < 3) return res.json([]);
  const key = q.toLowerCase();
  if (geoCache.has(key)) return res.json(geoCache.get(key));
  try {
    const slot = Math.max(Date.now(), nextGeocodeSlot);   // Nominatim allows 1 request a second
    nextGeocodeSlot = slot + 1100;
    if (slot > Date.now()) await sleep(slot - Date.now());
    const url = `${NOMINATIM_URL}/search?format=jsonv2&limit=5&countrycodes=in&viewbox=79.9,13.4,80.5,12.7&q=${encodeURIComponent(q)}`;
    const r = await fetchWithTimeout(url, { headers: { 'User-Agent': USER_AGENT, 'Accept-Language': 'en' } }, 8000);
    if (!r.ok) throw new Error('geocoder ' + r.status);
    const data = await r.json();
    const out = data.map(p => ({ name: p.display_name, lat: Number(p.lat), lng: Number(p.lon) }));
    if (geoCache.size > 300) geoCache.clear();
    geoCache.set(key, out);
    res.json(out);
  } catch (e) {
    res.status(502).json({ error: 'Place search is not available right now. Please try again in a moment.' });
  }
});

// ----- geometry helpers (points are [lat, lng]) -----
const RAD = Math.PI / 180;
function haversine(a, b) {
  const dLat = (b[0] - a[0]) * RAD, dLng = (b[1] - a[1]) * RAD;
  const h = Math.sin(dLat / 2) ** 2 + Math.cos(a[0] * RAD) * Math.cos(b[0] * RAD) * Math.sin(dLng / 2) ** 2;
  return 6371000 * 2 * Math.asin(Math.sqrt(h));
}
function distanceToSegment(p, a, b) {
  const kx = Math.cos(p[0] * RAD) * 111320, ky = 110540;
  const ax = (a[1] - p[1]) * kx, ay = (a[0] - p[0]) * ky;
  const bx = (b[1] - p[1]) * kx, by = (b[0] - p[0]) * ky;
  const dx = bx - ax, dy = by - ay, len2 = dx * dx + dy * dy;
  const t = len2 ? Math.max(0, Math.min(1, -(ax * dx + ay * dy) / len2)) : 0;
  return Math.hypot(ax + t * dx, ay + t * dy);
}
function nearestOnRoute(p, coords) {
  let best = Infinity, index = 0;
  if (coords.length === 1) return { dist: haversine(p, coords[0]), index: 0 };
  for (let i = 0; i < coords.length - 1; i++) {
    const d = distanceToSegment(p, coords[i], coords[i + 1]);
    if (d < best) { best = d; index = i; }
  }
  return { dist: best, index };
}
// hazards the route passes through, in the order they are met along the route
function blockers(coords, hazards) {
  return hazards
    .map(h => ({ h, ...nearestOnRoute([h.lat, h.lng], coords) }))
    .filter(x => x.dist < x.h.radius_m)
    .sort((a, b) => a.index - b.index);
}
function bearing(a, b) {
  const y = Math.sin((b[1] - a[1]) * RAD) * Math.cos(b[0] * RAD);
  const x = Math.cos(a[0] * RAD) * Math.sin(b[0] * RAD) - Math.sin(a[0] * RAD) * Math.cos(b[0] * RAD) * Math.cos((b[1] - a[1]) * RAD);
  return (Math.atan2(y, x) / RAD + 360) % 360;
}
function offsetPoint(p, bearingDeg, meters) {
  const b = bearingDeg * RAD;
  return [p[0] + meters * Math.cos(b) / 110540, p[1] + meters * Math.sin(b) / (111320 * Math.cos(p[0] * RAD))];
}
function parseLatLng(s) {
  if (typeof s !== 'string') return null;
  const [a, b] = s.split(',').map(Number);
  return isFinite(a) && isFinite(b) && Math.abs(a) <= 90 && Math.abs(b) <= 180 ? [a, b] : null;
}

// drains that are overflowing right now and have reported recently
function liveHazards() {
  const out = [];
  Object.keys(readings).forEach(id => {
    const n = readings[id].latest;
    if (!n || n.risk_level !== 'critical' || n.lat === undefined || n.lng === undefined) return;
    if (Date.now() - new Date(n.timestamp).getTime() > STALE_MIN * 60e3) return;
    out.push({ id, lat: n.lat, lng: n.lng, radius_m: HAZARD_RADIUS_M, source: 'sensor' });
  });
  return out;
}

async function osrmRoute(points, alternatives) {
  const coords = points.map(p => `${p[1].toFixed(6)},${p[0].toFixed(6)}`).join(';');
  const url = `${OSRM_URL}/route/v1/driving/${coords}?overview=full&geometries=geojson&steps=false&alternatives=${alternatives ? 'true' : 'false'}`;
  const r = await fetchWithTimeout(url, { headers: { 'User-Agent': USER_AGENT } }, 12000);
  const j = await r.json().catch(() => ({}));
  if (j.code === 'NoRoute' || (j.code === 'Ok' && !(j.routes || []).length)) {
    const e = new Error('no route'); e.noRoute = true; throw e;
  }
  if (!r.ok || j.code !== 'Ok') throw new Error('routing service error');
  return j.routes.map(rt => ({
    distance_m: rt.distance,
    duration_s: rt.duration,
    coords: rt.geometry.coordinates.map(c => [c[1], c[0]])
  }));
}
const pack = rt => ({
  distance_m: Math.round(rt.distance_m),
  duration_s: Math.round(rt.duration_s),
  coordinates: rt.coords.map(c => [Number(c[0].toFixed(5)), Number(c[1].toFixed(5))])
});
function routeResult(status, safe, fastest, hazards, notes) {
  const extraM = safe.distance_m - fastest.distance_m, extraS = safe.duration_s - fastest.duration_s;
  let message;
  if (status === 'clear') {
    message = 'No flooded drains on your fastest route. You are good to go.';
  } else if (status === 'rerouted') {
    message = 'Your fastest route passes a flooded drain. This route avoids it' +
      (extraM > 50 ? `, adding about ${(extraM / 1000).toFixed(1)} km` : '') +
      (extraS >= 60 ? ` and ${Math.round(extraS / 60)} min` : '') + '.';
  } else {
    message = 'We could not find a road route that fully avoids the flooded area. Drive carefully, or wait until the crew has cleared it.';
  }
  return { status, message, notes, hazards, fastest: pack(fastest), safe: pack(safe), extra_distance_m: Math.round(extraM), extra_duration_s: Math.round(extraS) };
}

app.get('/api/route', limiter(20, 60e3), async (req, res) => {
  const from = parseLatLng(req.query.from), to = parseLatLng(req.query.to);
  if (!from || !to) return res.status(400).json({ error: 'Please give a starting point and a destination.' });
  if (haversine(from, to) > 300000) return res.status(400).json({ error: 'These two places are too far apart for this planner.' });

  const testHazards = [].concat(req.query.hazard || []).slice(0, 5).map(parseLatLng).filter(Boolean)
    .map((p, i) => ({ id: 'TEST-' + (i + 1), lat: p[0], lng: p[1], radius_m: HAZARD_RADIUS_M, source: 'test' }));
  const hazards = [...liveHazards(), ...testHazards];

  try {
    let calls = 1;
    const base = await osrmRoute([from, to], true);
    const fastest = base[0];

    // a flooded drain right at the start or end of the trip cannot be avoided
    const atEnds = hazards.filter(h => haversine(from, [h.lat, h.lng]) < h.radius_m || haversine(to, [h.lat, h.lng]) < h.radius_m);
    const avoid = hazards.filter(h => !atEnds.includes(h));
    const notes = atEnds.length ? ['Your start or destination is close to a flooded drain, so that part of the trip cannot be avoided.'] : [];

    const onFastest = blockers(fastest.coords, avoid);
    const hazardInfo = hazards.map(h => ({ ...h, on_fastest: onFastest.some(b => b.h === h) }));
    if (!onFastest.length) return res.json(routeResult('clear', fastest, fastest, hazardInfo, notes));

    // 1) one of the routes the routing service already offered may miss the flooded area
    const clearAlt = base.slice(1)
      .filter(r => !blockers(r.coords, avoid).length)
      .sort((a, b) => a.duration_s - b.duration_s)[0];
    if (clearAlt) return res.json(routeResult('rerouted', clearAlt, fastest, hazardInfo, notes));

    // 2) otherwise steer around each flooded drain by adding a waypoint beside it
    let current = fastest;
    const vias = [];
    const BUDGET = 18;
    for (let iter = 0; iter < 3; iter++) {
      const blocked = blockers(current.coords, avoid);
      if (!blocked.length) break;
      const first = blocked[0];
      const hz = [first.h.lat, first.h.lng];
      const i = Math.min(first.index, Math.max(0, current.coords.length - 2));
      const heading = current.coords.length > 1 ? bearing(current.coords[i], current.coords[i + 1]) : 0;
      const r0 = first.h.radius_m;
      const candidates = [];
      [r0 + 200, r0 + 600].forEach(m => [90, -90].forEach(s => candidates.push(offsetPoint(hz, (heading + s + 360) % 360, m))));
      [45, -45, 135, -135].forEach(s => candidates.push(offsetPoint(hz, (heading + s + 360) % 360, r0 + 350)));

      let best = null;
      for (let g = 0; g < candidates.length; g += 4) {
        if (calls >= BUDGET) break;
        const group = candidates.slice(g, g + 4);
        calls += group.length;
        const results = await Promise.allSettled(group.map(c => osrmRoute([from, ...vias, c, to], false)));
        results.forEach((r, k) => {
          if (r.status !== 'fulfilled') return;
          const rt = r.value[0];
          const nb = blockers(rt.coords, avoid).length;
          if (!best || nb < best.nb || (nb === best.nb && rt.duration_s < best.rt.duration_s)) best = { rt, via: group[k], nb };
        });
        if (best && best.nb < blocked.length) break;
      }
      if (!best || best.nb >= blocked.length) break;
      vias.push(best.via);
      current = best.rt;
    }
    const stillBlocked = blockers(current.coords, avoid).length > 0;
    res.json(routeResult(stillBlocked ? 'unavoidable' : 'rerouted', current, fastest, hazardInfo, notes));
  } catch (e) {
    if (e.noRoute) return res.status(404).json({ error: 'No road route was found between these two places.' });
    console.error('Route error:', e.message);
    res.status(502).json({ error: 'The routing service is busy right now. Please try again in a moment.' });
  }
});

// ======================================================================
//  PAGES
// ======================================================================
app.get('/health', (req, res) => res.send('Pravaah backend is running.'));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/map', (req, res) => res.sendFile(path.join(__dirname, 'public', 'map.html')));
app.get('/login', (req, res) => {
  if (currentUser(req)) return res.redirect('/dashboard');
  res.set('Cache-Control', 'no-store');
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});
// the dashboard file lives outside "public", so it can only be reached through this check
app.get('/dashboard', requireStaffPage, (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.sendFile(path.join(__dirname, 'views', 'dashboard.html'));
});
// an old unprotected copy must never be served
app.use((req, res, next) => (/dashboard\.html$/i.test(req.path) ? res.redirect('/dashboard') : next()));
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

app.use((err, req, res, next) => {
  if (err && err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid request.' });
  console.error(err);
  res.status(500).json({ error: 'Something went wrong.' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
