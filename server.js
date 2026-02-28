const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const USERS_FILE = path.join(__dirname, 'users.json');
const HISTORY_FILE = path.join(__dirname, 'login-history.json');
const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD_HASH = crypto.createHash('sha256').update('admin').digest('hex');

// In-memory session store: token -> { masterId, username, role, historyEntryId }
const sessions = new Map();

function sha256(str) {
    return crypto.createHash('sha256').update(str).digest('hex');
}

function generateId() {
    return crypto.randomBytes(16).toString('hex');
}

async function readUsers() {
    try {
        const data = await fs.promises.readFile(USERS_FILE, 'utf8');
        return JSON.parse(data);
    } catch {
        throw new Error('Failed to read user data. Please ensure users.json is valid JSON.');
    }
}

async function writeUsers(users) {
    await fs.promises.writeFile(USERS_FILE, JSON.stringify(users, null, 2));
}

async function readHistory() {
    try {
        const data = await fs.promises.readFile(HISTORY_FILE, 'utf8');
        return JSON.parse(data);
    } catch {
        return [];
    }
}

async function writeHistory(history) {
    await fs.promises.writeFile(HISTORY_FILE, JSON.stringify(history, null, 2));
}

function parseBody(req) {
    return new Promise((resolve, reject) => {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', () => {
            try { resolve(JSON.parse(body)); }
            catch { reject(new Error('Invalid JSON')); }
        });
        req.on('error', reject);
    });
}

function sendJSON(res, status, data) {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(data));
}

function sendCSV(res, csv, filename) {
    res.writeHead(200, {
        'Content-Type': 'text/csv',
        'Content-Disposition': `attachment; filename="${filename}"`
    });
    res.end(csv);
}

// RFC 4180 CSV field escaping: wrap in quotes if field contains comma, quote, or newline
function csvField(val) {
    const s = String(val == null ? '' : val);
    if (s.includes(',') || s.includes('"') || s.includes('\n') || s.includes('\r')) {
        return '"' + s.replace(/"/g, '""') + '"';
    }
    return s;
}

// Update username in all login history entries for a given masterId
async function updateHistoryUsername(masterId, newUsername) {
    const history = await readHistory();
    history.filter(h => h.masterId === masterId).forEach(h => { h.username = newUsername; });
    await writeHistory(history);
}

function getClientIP(req) {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) return forwarded.split(',')[0].trim();
    return req.socket.remoteAddress || 'unknown';
}

function getDeviceName(req) {
    return req.headers['user-agent'] || 'unknown';
}

function getSessionFromHeader(req) {
    const auth = req.headers['authorization'];
    if (auth && auth.startsWith('Bearer ')) {
        const token = auth.slice(7);
        return sessions.get(token) || null;
    }
    return null;
}

function requireAdmin(req, res) {
    const session = getSessionFromHeader(req);
    if (!session || session.role !== 'admin') {
        sendJSON(res, 401, { error: 'Unauthorized.' });
        return null;
    }
    return session;
}

function requireUser(req, res) {
    const session = getSessionFromHeader(req);
    if (!session) {
        sendJSON(res, 401, { error: 'Unauthorized.' });
        return null;
    }
    return session;
}

function serveFile(res, filePath, contentType) {
    fs.readFile(filePath, (err, data) => {
        if (err) { res.writeHead(404); res.end('Not found'); return; }
        res.writeHead(200, { 'Content-Type': contentType });
        res.end(data);
    });
}

const server = http.createServer(async (req, res) => {
    const base = `http://${req.headers.host || 'localhost'}`;
    const parsed = new URL(req.url, base);
    const pathname = parsed.pathname;

    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
    }

    // Serve static HTML files
    if (req.method === 'GET' && pathname === '/') {
        return serveFile(res, path.join(__dirname, 'index.html'), 'text/html');
    }
    if (req.method === 'GET' && pathname === '/admin/admin-home.html') {
        return serveFile(res, path.join(__dirname, 'admin', 'admin-home.html'), 'text/html');
    }
    if (req.method === 'GET' && pathname === '/user/user-home.html') {
        return serveFile(res, path.join(__dirname, 'user', 'user-home.html'), 'text/html');
    }

    try {
        // POST /signup
        if (req.method === 'POST' && pathname === '/signup') {
            const { username, password, fullName, email, contact } = await parseBody(req);

            if (!username || !password) {
                return sendJSON(res, 400, { error: 'Username and password are required.' });
            }
            if (username === ADMIN_USERNAME) {
                return sendJSON(res, 400, { error: 'This username is reserved.' });
            }

            const users = await readUsers();
            if (users.find(u => u.username === username)) {
                return sendJSON(res, 409, { error: 'Username already exists.' });
            }

            const masterId = generateId();
            const passwordHash = sha256(password);
            users.push({
                masterId,
                username,
                passwordHash,
                fullName: fullName || '',
                email: email || '',
                contact: contact || '',
                active: true
            });
            await writeUsers(users);
            return sendJSON(res, 201, { message: 'Signup successful.', masterId });
        }

        // POST /login
        if (req.method === 'POST' && pathname === '/login') {
            const { username, password } = await parseBody(req);

            if (!username || !password) {
                return sendJSON(res, 400, { error: 'Username and password are required.' });
            }

            const passwordHash = sha256(password);
            const ip = getClientIP(req);
            const device = getDeviceName(req);

            // Admin login
            if (username === ADMIN_USERNAME) {
                if (passwordHash === ADMIN_PASSWORD_HASH) {
                    const token = generateId();
                    sessions.set(token, { masterId: 'admin', username: ADMIN_USERNAME, role: 'admin' });
                    return sendJSON(res, 200, { message: 'Login successful.', role: 'admin', token });
                }
                return sendJSON(res, 401, { error: 'Invalid username or password.' });
            }

            const users = await readUsers();
            const user = users.find(u => u.username === username);
            if (!user || user.passwordHash !== passwordHash) {
                return sendJSON(res, 401, { error: 'Invalid username or password.' });
            }
            if (!user.active) {
                return sendJSON(res, 403, { error: 'Account is frozen. Please contact admin.' });
            }

            // Record login history
            const history = await readHistory();
            const historyEntry = {
                id: generateId(),
                masterId: user.masterId,
                username: user.username,
                loginTime: new Date().toISOString(),
                logoutTime: null,
                ipAddress: ip,
                deviceName: device
            };
            history.push(historyEntry);
            await writeHistory(history);

            const token = generateId();
            sessions.set(token, {
                masterId: user.masterId,
                username: user.username,
                role: 'user',
                historyEntryId: historyEntry.id
            });
            return sendJSON(res, 200, {
                message: 'Login successful.',
                role: 'user',
                token,
                masterId: user.masterId
            });
        }

        // POST /logout
        if (req.method === 'POST' && pathname === '/logout') {
            const session = getSessionFromHeader(req);
            if (session && session.historyEntryId) {
                const history = await readHistory();
                const entry = history.find(h => h.id === session.historyEntryId);
                if (entry && !entry.logoutTime) {
                    entry.logoutTime = new Date().toISOString();
                    await writeHistory(history);
                }
            }
            if (req.headers['authorization']) {
                const token = req.headers['authorization'].slice(7);
                sessions.delete(token);
            }
            return sendJSON(res, 200, { message: 'Logged out.' });
        }

        // GET /admin/stats
        if (req.method === 'GET' && pathname === '/admin/stats') {
            if (!requireAdmin(req, res)) return;
            const users = await readUsers();
            const active = users.filter(u => u.active).length;
            const frozen = users.filter(u => !u.active).length;
            return sendJSON(res, 200, { total: users.length, active, frozen });
        }

        // GET /admin/users — list users
        if (req.method === 'GET' && pathname === '/admin/users') {
            const authHeader = req.headers['authorization'];
            let authorized = false;
            if (authHeader && authHeader.startsWith('Basic ')) {
                const credentials = Buffer.from(authHeader.slice(6), 'base64').toString('utf8');
                const colonIndex = credentials.indexOf(':');
                const uname = credentials.slice(0, colonIndex);
                const pass = credentials.slice(colonIndex + 1);
                authorized = (uname === ADMIN_USERNAME && sha256(pass) === ADMIN_PASSWORD_HASH);
            } else if (authHeader && authHeader.startsWith('Bearer ')) {
                const session = sessions.get(authHeader.slice(7));
                authorized = !!(session && session.role === 'admin');
            }
            if (!authorized) return sendJSON(res, 401, { error: 'Unauthorized.' });
            const users = await readUsers();
            return sendJSON(res, 200, users.map(u => ({
                masterId: u.masterId || '',
                username: u.username,
                fullName: u.fullName || '',
                email: u.email || '',
                contact: u.contact || '',
                active: u.active
            })));
        }

        // GET /admin/users/export — export users as CSV
        if (req.method === 'GET' && pathname === '/admin/users/export') {
            if (!requireAdmin(req, res)) return;
            const users = await readUsers();
            const rows = ['masterId,username,fullName,email,contact,active'];
            for (const u of users) {
                rows.push([
                    csvField(u.masterId || ''),
                    csvField(u.username || ''),
                    csvField(u.fullName || ''),
                    csvField(u.email || ''),
                    csvField(u.contact || ''),
                    u.active ? 'true' : 'false'
                ].join(','));
            }
            return sendCSV(res, rows.join('\n'), 'users.csv');
        }

        // POST /admin/users/bulk — bulk import users from JSON array
        if (req.method === 'POST' && pathname === '/admin/users/bulk') {
            if (!requireAdmin(req, res)) return;
            const { records } = await parseBody(req);
            if (!Array.isArray(records)) {
                return sendJSON(res, 400, { error: 'records must be an array.' });
            }
            const users = await readUsers();
            const added = [];
            const skipped = [];
            for (const r of records) {
                const { username, password, fullName, email, contact } = r;
                if (!username || !password) { skipped.push(username || '(missing)'); continue; }
                if (username === ADMIN_USERNAME || users.find(u => u.username === username)) {
                    skipped.push(username);
                    continue;
                }
                const masterId = generateId();
                const passwordHash = sha256(password);
                users.push({
                    masterId,
                    username,
                    passwordHash,
                    fullName: fullName || '',
                    email: email || '',
                    contact: contact || '',
                    active: true
                });
                added.push(username);
            }
            await writeUsers(users);
            return sendJSON(res, 200, { added: added.length, skipped: skipped.length, skippedUsers: skipped });
        }

        // GET /admin/users/:masterId/history — login history for a specific user
        if (req.method === 'GET' && /^\/admin\/users\/[^/]+\/history$/.test(pathname)) {
            if (!requireAdmin(req, res)) return;
            const masterId = decodeURIComponent(pathname.split('/')[3]);
            const history = await readHistory();
            const userHistory = history.filter(h => h.masterId === masterId);
            if (parsed.searchParams.get('format') === 'csv') {
                const rows = ['username,loginTime,logoutTime,ipAddress,deviceName'];
                for (const h of userHistory) {
                    rows.push([
                        csvField(h.username || ''),
                        csvField(h.loginTime || ''),
                        csvField(h.logoutTime || ''),
                        csvField(h.ipAddress || ''),
                        csvField(h.deviceName || '')
                    ].join(','));
                }
                return sendCSV(res, rows.join('\n'), `history-${masterId}.csv`);
            }
            return sendJSON(res, 200, userHistory);
        }

        // PUT /admin/users/:masterId — activate/freeze or update credentials
        if (req.method === 'PUT' && pathname.startsWith('/admin/users/')) {
            const parts = pathname.split('/');
            if (parts.length !== 4) {
                res.writeHead(404); res.end('Not found'); return;
            }
            const targetId = decodeURIComponent(parts[3]);
            const body = await parseBody(req);

            let authorized = false;
            const authHeader = req.headers['authorization'];
            if (authHeader && authHeader.startsWith('Bearer ')) {
                const session = sessions.get(authHeader.slice(7));
                authorized = !!(session && session.role === 'admin');
            } else if (body.adminPassword && sha256(body.adminPassword) === ADMIN_PASSWORD_HASH) {
                authorized = true;
            }
            if (!authorized) return sendJSON(res, 401, { error: 'Unauthorized.' });

            const users = await readUsers();
            // Match by masterId first, fall back to username for backward compatibility
            const user = users.find(u => u.masterId === targetId) ||
                          users.find(u => u.username === targetId);
            if (!user) return sendJSON(res, 404, { error: 'User not found.' });

            if ('active' in body) user.active = Boolean(body.active);
            if (body.newUsername) {
                if (users.find(u => u.username === body.newUsername && u.masterId !== user.masterId)) {
                    return sendJSON(res, 409, { error: 'Username already taken.' });
                }
                user.username = body.newUsername;
                await updateHistoryUsername(user.masterId, body.newUsername);
            }
            if (body.newPassword) {
                user.passwordHash = sha256(body.newPassword);
            }

            await writeUsers(users);
            return sendJSON(res, 200, { message: `User ${user.username} updated.` });
        }

        // GET /user/profile
        if (req.method === 'GET' && pathname === '/user/profile') {
            const session = requireUser(req, res);
            if (!session) return;
            const users = await readUsers();
            const user = users.find(u => u.masterId === session.masterId);
            if (!user) return sendJSON(res, 404, { error: 'User not found.' });
            return sendJSON(res, 200, {
                masterId: user.masterId,
                username: user.username,
                fullName: user.fullName || '',
                email: user.email || '',
                contact: user.contact || ''
            });
        }

        // PUT /user/profile — update username
        if (req.method === 'PUT' && pathname === '/user/profile') {
            const session = requireUser(req, res);
            if (!session) return;
            const { newUsername } = await parseBody(req);
            if (!newUsername) return sendJSON(res, 400, { error: 'newUsername is required.' });

            const users = await readUsers();
            if (users.find(u => u.username === newUsername && u.masterId !== session.masterId)) {
                return sendJSON(res, 409, { error: 'Username already taken.' });
            }
            const user = users.find(u => u.masterId === session.masterId);
            if (!user) return sendJSON(res, 404, { error: 'User not found.' });
            user.username = newUsername;
            session.username = newUsername;
            await writeUsers(users);
            await updateHistoryUsername(session.masterId, newUsername);
            return sendJSON(res, 200, { message: 'Username updated.', username: newUsername });
        }

        // GET /user/history
        if (req.method === 'GET' && pathname === '/user/history') {
            const session = requireUser(req, res);
            if (!session) return;
            const history = await readHistory();
            const userHistory = history.filter(h => h.masterId === session.masterId);
            return sendJSON(res, 200, userHistory);
        }

        res.writeHead(404);
        res.end('Not found');
    } catch (err) {
        console.error('Server error:', err.message);
        sendJSON(res, 500, { error: 'Internal server error.' });
    }
});

if (require.main === module) {
    const PORT = process.env.PORT || 3000;
    server.listen(PORT, () => {
        console.log(`Server running on http://localhost:${PORT}`);
    });
}

module.exports = server;
