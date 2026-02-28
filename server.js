const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const USERS_FILE = path.join(__dirname, 'users.json');
const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD_HASH = crypto.createHash('sha256').update('admin').digest('hex');

function sha256(str) {
    return crypto.createHash('sha256').update(str).digest('hex');
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

const server = http.createServer(async (req, res) => {
    const base = `http://${req.headers.host || 'localhost'}`;
    const parsed = new URL(req.url, base);
    const pathname = parsed.pathname;

    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
    }

    // Serve index.html for root
    if (req.method === 'GET' && pathname === '/') {
        fs.readFile(path.join(__dirname, 'index.html'), (err, data) => {
            if (err) { res.writeHead(404); res.end('Not found'); return; }
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(data);
        });
        return;
    }

    try {
        // POST /signup
        if (req.method === 'POST' && pathname === '/signup') {
            const { username, password } = await parseBody(req);

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

            const passwordHash = sha256(password);
            users.push({ username, passwordHash, active: true });
            await writeUsers(users);
            return sendJSON(res, 201, { message: 'Signup successful.' });
        }

        // POST /login
        if (req.method === 'POST' && pathname === '/login') {
            const { username, password } = await parseBody(req);

            if (!username || !password) {
                return sendJSON(res, 400, { error: 'Username and password are required.' });
            }

            const passwordHash = sha256(password);

            // Admin login
            if (username === ADMIN_USERNAME) {
                if (passwordHash === ADMIN_PASSWORD_HASH) {
                    return sendJSON(res, 200, { message: 'Login successful.', role: 'admin' });
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
            return sendJSON(res, 200, { message: 'Login successful.' });
        }

        // GET /admin/users — list users (requires Basic auth with admin credentials)
        if (req.method === 'GET' && pathname === '/admin/users') {
            const authHeader = req.headers['authorization'];
            if (!authHeader || !authHeader.startsWith('Basic ')) {
                return sendJSON(res, 401, { error: 'Unauthorized.' });
            }
            const credentials = Buffer.from(authHeader.slice(6), 'base64').toString('utf8');
            const colonIndex = credentials.indexOf(':');
            const username = credentials.slice(0, colonIndex);
            const password = credentials.slice(colonIndex + 1);
            if (username !== ADMIN_USERNAME || sha256(password) !== ADMIN_PASSWORD_HASH) {
                return sendJSON(res, 401, { error: 'Unauthorized.' });
            }
            const users = await readUsers();
            return sendJSON(res, 200, users.map(u => ({ username: u.username, active: u.active })));
        }

        // PUT /admin/users/:username — activate or freeze a user
        if (req.method === 'PUT' && pathname.startsWith('/admin/users/')) {
            const targetUsername = decodeURIComponent(pathname.replace('/admin/users/', ''));
            const body = await parseBody(req);
            const { adminPassword, active } = body;

            if (!adminPassword || sha256(adminPassword) !== ADMIN_PASSWORD_HASH) {
                return sendJSON(res, 401, { error: 'Unauthorized.' });
            }

            const users = await readUsers();
            const user = users.find(u => u.username === targetUsername);
            if (!user) {
                return sendJSON(res, 404, { error: 'User not found.' });
            }

            user.active = Boolean(active);
            await writeUsers(users);
            return sendJSON(res, 200, { message: `User ${targetUsername} updated.` });
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
