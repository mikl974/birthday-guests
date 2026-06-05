const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { MongoClient } = require('mongodb');

const CONFIG_FILE = path.join(__dirname, 'config.json');
const PUBLIC_DIR = path.join(__dirname, 'public');
const PORT = process.env.PORT || 3000;
const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8 hours

// --- Database ---
let guestsCol;

async function connectDB() {
  const uri = process.env.MONGODB_URI;
  if (!uri) throw new Error('MONGODB_URI environment variable is not set');
  const client = new MongoClient(uri);
  await client.connect();
  guestsCol = client.db('birthday').collection('guests');
  console.log('✅ Connected to MongoDB');
}

// --- Auth helpers ---

function getConfig() {
  return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf-8'));
}

function sha256(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}

const sessions = new Map();

function createSession() {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { createdAt: Date.now() });
  return token;
}

function isValidSession(token) {
  if (!token || !sessions.has(token)) return false;
  const session = sessions.get(token);
  if (Date.now() - session.createdAt > SESSION_TTL_MS) {
    sessions.delete(token);
    return false;
  }
  return true;
}

function parseCookies(req) {
  const cookies = {};
  (req.headers.cookie || '').split(';').forEach(part => {
    const [k, ...v] = part.trim().split('=');
    if (k) cookies[k.trim()] = decodeURIComponent(v.join('='));
  });
  return cookies;
}

function redirect(res, location) {
  res.writeHead(302, { Location: location });
  res.end();
}

function requireAuth(req, res) {
  const cookies = parseCookies(req);
  if (isValidSession(cookies.session)) return true;
  redirect(res, '/login');
  return false;
}

const MIME_TYPES = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.json': 'application/json',
};

function sendJSON(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function getGuests() {
  return guestsCol.find({}, { projection: { _id: 0 } }).toArray();
}

function getGuest(id) {
  return guestsCol.findOne({ id }, { projection: { _id: 0 } });
}

function serveStatic(res, filePath) {
  const ext = path.extname(filePath);
  const contentType = MIME_TYPES[ext] || 'text/plain';
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404);
      res.end('Not found');
      return;
    }
    res.writeHead(200, { 'Content-Type': contentType });
    res.end(data);
  });
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => (body += chunk));
    req.on('end', () => {
      const ct = req.headers['content-type'] || '';
      try {
        if (ct.includes('application/x-www-form-urlencoded')) {
          const params = {};
          new URLSearchParams(body).forEach((v, k) => { params[k] = v; });
          resolve(params);
        } else {
          resolve(body ? JSON.parse(body) : {});
        }
      } catch {
        reject(new Error('Invalid body'));
      }
    });
  });
}

const server = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const url = new URL(req.url, `http://localhost:${PORT}`);
  const pathname = url.pathname;

  // --- Login page ---
  if (pathname === '/login' && req.method === 'GET') {
    return serveStatic(res, path.join(PUBLIC_DIR, 'login.html'));
  }

  // --- Login submit ---
  if (pathname === '/login' && req.method === 'POST') {
    try {
      const body = await parseBody(req);
      const config = getConfig();
      if (sha256(body.password || '') === config.passwordHash) {
        const token = createSession();
        res.writeHead(302, {
          Location: '/',
          'Set-Cookie': `session=${token}; HttpOnly; Path=/; Max-Age=${SESSION_TTL_MS / 1000}`,
        });
        res.end();
      } else {
        redirect(res, '/login?error=1');
      }
    } catch {
      redirect(res, '/login?error=1');
    }
    return;
  }

  // --- Logout ---
  if (pathname === '/logout' && req.method === 'GET') {
    const cookies = parseCookies(req);
    sessions.delete(cookies.session);
    res.writeHead(302, {
      Location: '/login',
      'Set-Cookie': 'session=; HttpOnly; Path=/; Max-Age=0',
    });
    res.end();
    return;
  }

  // --- API routes (protected) ---
  if (pathname === '/api/guests' && req.method === 'GET') {
    if (!requireAuth(req, res)) return;
    return sendJSON(res, 200, await getGuests());
  }

  if (pathname === '/api/guests' && req.method === 'POST') {
    if (!requireAuth(req, res)) return;
    try {
      const body = await parseBody(req);
      const name = (body.name || '').trim();
      if (!name) return sendJSON(res, 400, { error: 'Name is required' });
      const companions = Math.max(1, parseInt(body.companions) || 1);
      const guest = { id: crypto.randomUUID(), name, companions, rsvp: 'pending' };
      await guestsCol.insertOne(guest);
      return sendJSON(res, 201, { id: guest.id, name: guest.name, companions: guest.companions, rsvp: guest.rsvp });
    } catch {
      return sendJSON(res, 400, { error: 'Invalid request' });
    }
  }

  const guestMatch = pathname.match(/^\/api\/guests\/([^/]+)$/);
  if (guestMatch) {
    if (!requireAuth(req, res)) return;
    const id = guestMatch[1];

    if (req.method === 'PATCH') {
      try {
        const body = await parseBody(req);
        const update = {};
        if (body.rsvp && ['confirmed', 'declined', 'pending'].includes(body.rsvp)) update.rsvp = body.rsvp;
        if (body.name && body.name.trim()) update.name = body.name.trim();
        if (body.companions !== undefined) update.companions = Math.max(1, parseInt(body.companions) || 1);
        const result = await guestsCol.findOneAndUpdate(
          { id },
          { $set: update },
          { returnDocument: 'after', projection: { _id: 0 } }
        );
        if (!result) return sendJSON(res, 404, { error: 'Guest not found' });
        return sendJSON(res, 200, result);
      } catch {
        return sendJSON(res, 400, { error: 'Invalid request' });
      }
    }

    if (req.method === 'DELETE') {
      const result = await guestsCol.deleteOne({ id });
      if (result.deletedCount === 0) return sendJSON(res, 404, { error: 'Guest not found' });
      return sendJSON(res, 200, { success: true });
    }
  }

  // Serve static files (protected, except login assets)
  if (req.method === 'GET') {
    if (!requireAuth(req, res)) return;
    const safePath = pathname === '/' ? '/index.html' : pathname;
    const filePath = path.join(PUBLIC_DIR, safePath.replace(/\.\./g, ''));
    return serveStatic(res, filePath);
  }

  res.writeHead(404);
  res.end('Not found');
});

connectDB().then(() => {
  server.listen(PORT, () => {
    console.log(`🎂 Birthday Guest Manager running at http://localhost:${PORT}`);
  });
}).catch(err => {
  console.error('Failed to connect to MongoDB:', err.message);
  process.exit(1);
});
