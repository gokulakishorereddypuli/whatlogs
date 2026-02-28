const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const USERS_FILE = path.join(__dirname, 'users.json');
const HISTORY_FILE = path.join(__dirname, 'login-history.json');

function sha256(str) {
    return crypto.createHash('sha256').update(str).digest('hex');
}

// Save and restore users.json and login-history.json around tests
const originalData = fs.readFileSync(USERS_FILE, 'utf8');
const originalHistory = fs.existsSync(HISTORY_FILE) ? fs.readFileSync(HISTORY_FILE, 'utf8') : '[]';

async function run() {
    // Reset data files
    fs.writeFileSync(USERS_FILE, '[]');
    fs.writeFileSync(HISTORY_FILE, '[]');

    const server = require('./server');
    await new Promise(r => server.listen(0, r));
    const { port } = server.address();
    const base = `http://localhost:${port}`;

    async function post(url, body, token) {
        const headers = { 'Content-Type': 'application/json' };
        if (token) headers['Authorization'] = 'Bearer ' + token;
        const res = await fetch(url, {
            method: 'POST',
            headers,
            body: JSON.stringify(body)
        });
        return { status: res.status, data: await res.json() };
    }

    async function put(url, body, token) {
        const headers = { 'Content-Type': 'application/json' };
        if (token) headers['Authorization'] = 'Bearer ' + token;
        const res = await fetch(url, {
            method: 'PUT',
            headers,
            body: JSON.stringify(body)
        });
        return { status: res.status, data: await res.json() };
    }

    async function get(url, authHeader) {
        const headers = {};
        if (authHeader) headers['Authorization'] = authHeader;
        const res = await fetch(url, { headers });
        return { status: res.status, data: await res.json() };
    }

    // Test 1: Signup stores SHA-256 hashed password (not plain text), generates masterId
    const r1 = await post(`${base}/signup`, { username: 'alice', password: 'secret123', fullName: 'Alice Smith', email: 'alice@example.com', contact: '555-1234' });
    assert.strictEqual(r1.status, 201, 'Signup should return 201');
    assert.strictEqual(r1.data.message, 'Signup successful.');
    assert.ok(r1.data.masterId, 'Signup should return a masterId');
    const users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    assert.strictEqual(users.length, 1, 'One user should be stored');
    assert.notStrictEqual(users[0].passwordHash, 'secret123', 'Password must not be stored in plain text');
    assert.ok(/^[a-fA-F0-9]{64}$/.test(users[0].passwordHash), 'Password should be a SHA-256 hex hash');
    assert.strictEqual(users[0].active, true, 'New user should be active by default');
    assert.ok(/^[a-f0-9]{32}$/.test(users[0].masterId), 'masterId should be a 32-char hex string');
    assert.strictEqual(users[0].fullName, 'Alice Smith', 'fullName should be stored');
    assert.strictEqual(users[0].email, 'alice@example.com', 'email should be stored');
    console.log('✓ Signup stores hashed password, active status, masterId, and profile fields');

    // Test 2: Duplicate signup rejected
    const r2 = await post(`${base}/signup`, { username: 'alice', password: 'other' });
    assert.strictEqual(r2.status, 409, 'Duplicate signup should return 409');
    console.log('✓ Duplicate username rejected');

    // Test 3: Login with correct password succeeds and returns token + masterId
    const r3 = await post(`${base}/login`, { username: 'alice', password: 'secret123' });
    assert.strictEqual(r3.status, 200, 'Login should return 200');
    assert.strictEqual(r3.data.message, 'Login successful.');
    assert.ok(r3.data.token, 'Login should return a session token');
    assert.ok(r3.data.masterId, 'Login should return masterId');
    const userToken = r3.data.token;
    console.log('✓ Login with correct password succeeds and returns token');

    // Test 3b: Login records history entry
    const history = JSON.parse(fs.readFileSync(HISTORY_FILE, 'utf8'));
    assert.strictEqual(history.length, 1, 'Login should create a history entry');
    assert.ok(history[0].loginTime, 'History entry should have loginTime');
    assert.strictEqual(history[0].logoutTime, null, 'logoutTime should be null initially');
    console.log('✓ Login records history entry with loginTime');

    // Test 4: Login with wrong password fails
    const r4 = await post(`${base}/login`, { username: 'alice', password: 'wrongpass' });
    assert.strictEqual(r4.status, 401, 'Wrong password should return 401');
    console.log('✓ Login with wrong password rejected');

    // Test 5: Login with unknown username fails
    const r5 = await post(`${base}/login`, { username: 'bob', password: 'secret123' });
    assert.strictEqual(r5.status, 401, 'Unknown user should return 401');
    console.log('✓ Login with unknown username rejected');

    // Test 6: Missing fields return 400
    const r6 = await post(`${base}/signup`, { username: 'carol' });
    assert.strictEqual(r6.status, 400);
    const r7 = await post(`${base}/login`, { password: 'x' });
    assert.strictEqual(r7.status, 400);
    console.log('✓ Missing fields return 400');

    // Test 7: Reserved username "admin" cannot be used for signup
    const r8 = await post(`${base}/signup`, { username: 'admin', password: 'anything' });
    assert.strictEqual(r8.status, 400, 'Reserved username should return 400');
    console.log('✓ Reserved username "admin" rejected at signup');

    // Test 8: Admin login with correct credentials succeeds
    const r9 = await post(`${base}/login`, { username: 'admin', password: 'admin' });
    assert.strictEqual(r9.status, 200, 'Admin login should return 200');
    assert.strictEqual(r9.data.role, 'admin', 'Admin login should include role');
    console.log('✓ Admin login with correct credentials succeeds');

    // Test 9: Admin login with wrong password fails
    const r10 = await post(`${base}/login`, { username: 'admin', password: 'wrong' });
    assert.strictEqual(r10.status, 401, 'Admin wrong password should return 401');
    console.log('✓ Admin login with wrong password rejected');

    // Test 10: Freeze a user account via admin endpoint (by username for backward compat)
    const aliceMasterId = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'))[0].masterId;
    const r11 = await put(`${base}/admin/users/alice`, { adminPassword: 'admin', active: false });
    assert.strictEqual(r11.status, 200, 'Freeze user should return 200');
    const usersAfterFreeze = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    assert.strictEqual(usersAfterFreeze[0].active, false, 'User should be frozen');
    console.log('✓ Admin can freeze a user account');

    // Test 11: Frozen user cannot login
    const r12 = await post(`${base}/login`, { username: 'alice', password: 'secret123' });
    assert.strictEqual(r12.status, 403, 'Frozen user login should return 403');
    console.log('✓ Frozen user cannot login');

    // Test 12: Admin can reactivate a frozen user (by masterId)
    const r13 = await put(`${base}/admin/users/${aliceMasterId}`, { adminPassword: 'admin', active: true });
    assert.strictEqual(r13.status, 200, 'Activate user should return 200');
    const r14 = await post(`${base}/login`, { username: 'alice', password: 'secret123' });
    assert.strictEqual(r14.status, 200, 'Reactivated user should be able to login');
    console.log('✓ Admin can reactivate a frozen user');

    // Test 13: Admin endpoint rejects unauthorized access
    const r15 = await put(`${base}/admin/users/alice`, { adminPassword: 'wrong', active: false });
    assert.strictEqual(r15.status, 401, 'Unauthorized admin action should return 401');
    console.log('✓ Admin endpoint rejects unauthorized access');

    // Test 14: GET /admin/users with valid Basic auth returns user list (with masterId)
    const validBasic = 'Basic ' + Buffer.from('admin:admin').toString('base64');
    const r16 = await get(`${base}/admin/users`, validBasic);
    assert.strictEqual(r16.status, 200, 'GET /admin/users should return 200');
    assert.ok(Array.isArray(r16.data), 'Response should be an array');
    assert.ok(r16.data.some(u => u.username === 'alice'), 'User list should include alice');
    assert.ok(r16.data[0].masterId, 'User list entries should include masterId');
    console.log('✓ GET /admin/users with Basic auth returns user list with masterId');

    // Test 15: GET /admin/users without auth returns 401
    const r17 = await get(`${base}/admin/users`);
    assert.strictEqual(r17.status, 401, 'GET /admin/users without auth should return 401');
    console.log('✓ GET /admin/users without auth returns 401');

    // Test 16: Admin login returns Bearer token; use token for admin endpoints
    const adminLoginRes = await post(`${base}/login`, { username: 'admin', password: 'admin' });
    const adminToken = adminLoginRes.data.token;
    assert.ok(adminToken, 'Admin login should return a token');
    const r18 = await get(`${base}/admin/users`, 'Bearer ' + adminToken);
    assert.strictEqual(r18.status, 200, 'GET /admin/users with Bearer token should return 200');
    console.log('✓ Admin Bearer token works for /admin/users');

    // Test 17: GET /admin/stats returns user counts
    const statsRes = await get(`${base}/admin/stats`, 'Bearer ' + adminToken);
    assert.strictEqual(statsRes.status, 200, 'GET /admin/stats should return 200');
    assert.ok(typeof statsRes.data.total === 'number', 'stats.total should be a number');
    assert.ok(typeof statsRes.data.active === 'number', 'stats.active should be a number');
    assert.ok(typeof statsRes.data.frozen === 'number', 'stats.frozen should be a number');
    console.log('✓ GET /admin/stats returns user counts');

    // Test 18: Bulk import via POST /admin/users/bulk
    const bulkRes = await post(`${base}/admin/users/bulk`, {
        records: [
            { username: 'bob', password: 'pass1', fullName: 'Bob Jones', email: 'bob@example.com', contact: '555-0001' },
            { username: 'carol', password: 'pass2' },
            { username: 'alice', password: 'dupe' }  // should be skipped (duplicate)
        ]
    }, adminToken);
    assert.strictEqual(bulkRes.status, 200, 'Bulk import should return 200');
    assert.strictEqual(bulkRes.data.added, 2, 'Should add 2 new users');
    assert.strictEqual(bulkRes.data.skipped, 1, 'Should skip 1 duplicate');
    const usersAfterBulk = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    assert.strictEqual(usersAfterBulk.length, 3, 'Total should be 3 users after bulk import');
    assert.ok(usersAfterBulk.every(u => u.masterId), 'All bulk-imported users have a masterId');
    console.log('✓ Bulk import adds users and skips duplicates');

    // Test 19: Admin can update username via PUT /admin/users/:masterId
    const bobMasterId = usersAfterBulk.find(u => u.username === 'bob').masterId;
    const editRes = await put(`${base}/admin/users/${bobMasterId}`, { newUsername: 'bobby' }, adminToken);
    assert.strictEqual(editRes.status, 200, 'Edit username should return 200');
    const usersAfterEdit = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    assert.ok(usersAfterEdit.find(u => u.username === 'bobby'), 'Username should be updated to bobby');
    console.log('✓ Admin can change username via masterId');

    // Test 20: Admin can change password via PUT /admin/users/:masterId
    const carolMasterId = usersAfterBulk.find(u => u.username === 'carol').masterId;
    await put(`${base}/admin/users/${carolMasterId}`, { newPassword: 'newpass99' }, adminToken);
    const carolLogin = await post(`${base}/login`, { username: 'carol', password: 'newpass99' });
    assert.strictEqual(carolLogin.status, 200, 'Carol should login with new password');
    console.log('✓ Admin can change user password via masterId');

    // Test 21: GET /user/profile returns profile
    const aliceLogin2 = await post(`${base}/login`, { username: 'alice', password: 'secret123' });
    const aliceToken = aliceLogin2.data.token;
    const profileRes = await get(`${base}/user/profile`, 'Bearer ' + aliceToken);
    assert.strictEqual(profileRes.status, 200, 'GET /user/profile should return 200');
    assert.strictEqual(profileRes.data.username, 'alice', 'Profile should have correct username');
    assert.strictEqual(profileRes.data.fullName, 'Alice Smith', 'Profile should have fullName');
    console.log('✓ GET /user/profile returns correct profile');

    // Test 22: PUT /user/profile updates username
    const updateRes = await put(`${base}/user/profile`, { newUsername: 'alice2' }, aliceToken);
    assert.strictEqual(updateRes.status, 200, 'Update username should return 200');
    assert.strictEqual(updateRes.data.username, 'alice2', 'Updated username should be returned');
    console.log('✓ PUT /user/profile updates username');

    // Test 23: POST /logout records logoutTime
    await post(`${base}/logout`, {}, aliceToken);
    const historyAfterLogout = JSON.parse(fs.readFileSync(HISTORY_FILE, 'utf8'));
    const aliceEntries = historyAfterLogout.filter(h => h.masterId === aliceMasterId);
    // At least one entry should have logoutTime set
    assert.ok(aliceEntries.some(h => h.logoutTime !== null), 'Logout should record logoutTime');
    console.log('✓ POST /logout records logoutTime in history');

    // Test 24: GET /user/history returns user login history
    const aliceLogin3 = await post(`${base}/login`, { username: 'alice2', password: 'secret123' });
    const aliceToken3 = aliceLogin3.data.token;
    const histRes = await get(`${base}/user/history`, 'Bearer ' + aliceToken3);
    assert.strictEqual(histRes.status, 200, 'GET /user/history should return 200');
    assert.ok(Array.isArray(histRes.data), 'History should be an array');
    assert.ok(histRes.data.length >= 1, 'History should have at least one entry');
    console.log('✓ GET /user/history returns user login history');

    // Test 25: GET /admin/users/:masterId/history returns user history for admin
    const adminHistRes = await get(`${base}/admin/users/${aliceMasterId}/history`, 'Bearer ' + adminToken);
    assert.strictEqual(adminHistRes.status, 200, 'Admin GET history should return 200');
    assert.ok(Array.isArray(adminHistRes.data), 'Admin history should be an array');
    console.log('✓ Admin can view login history for a specific user');

    await new Promise(r => server.close(r));

    // Restore original data files
    fs.writeFileSync(USERS_FILE, originalData);
    fs.writeFileSync(HISTORY_FILE, originalHistory);
    console.log('\nAll tests passed!');
}

run().catch(err => {
    console.error('Test failed:', err.message);
    process.exit(1);
});
