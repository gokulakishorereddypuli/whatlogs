const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const USERS_FILE = path.join(__dirname, 'users.json');

function sha256(str) {
    return crypto.createHash('sha256').update(str).digest('hex');
}

// Save and restore users.json around tests
const originalData = fs.readFileSync(USERS_FILE, 'utf8');

async function run() {
    // Reset users.json
    fs.writeFileSync(USERS_FILE, '[]');

    const server = require('./server');
    await new Promise(r => server.listen(0, r));
    const { port } = server.address();
    const base = `http://localhost:${port}`;

    async function post(url, body) {
        const res = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        return { status: res.status, data: await res.json() };
    }

    async function put(url, body) {
        const res = await fetch(url, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
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

    // Test 1: Signup stores SHA-256 hashed password (not plain text)
    const r1 = await post(`${base}/signup`, { username: 'alice', password: 'secret123' });
    assert.strictEqual(r1.status, 201, 'Signup should return 201');
    assert.strictEqual(r1.data.message, 'Signup successful.');
    const users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    assert.strictEqual(users.length, 1, 'One user should be stored');
    assert.notStrictEqual(users[0].passwordHash, 'secret123', 'Password must not be stored in plain text');
    assert.ok(/^[a-fA-F0-9]{64}$/.test(users[0].passwordHash), 'Password should be a SHA-256 hex hash');
    assert.strictEqual(users[0].active, true, 'New user should be active by default');
    console.log('✓ Signup stores hashed password and active status');

    // Test 2: Duplicate signup rejected
    const r2 = await post(`${base}/signup`, { username: 'alice', password: 'other' });
    assert.strictEqual(r2.status, 409, 'Duplicate signup should return 409');
    console.log('✓ Duplicate username rejected');

    // Test 3: Login with correct password succeeds
    const r3 = await post(`${base}/login`, { username: 'alice', password: 'secret123' });
    assert.strictEqual(r3.status, 200, 'Login should return 200');
    assert.strictEqual(r3.data.message, 'Login successful.');
    console.log('✓ Login with correct password succeeds');

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

    // Test 10: Freeze a user account via admin endpoint
    const r11 = await put(`${base}/admin/users/alice`, { adminPassword: 'admin', active: false });
    assert.strictEqual(r11.status, 200, 'Freeze user should return 200');
    const usersAfterFreeze = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    assert.strictEqual(usersAfterFreeze[0].active, false, 'User should be frozen');
    console.log('✓ Admin can freeze a user account');

    // Test 11: Frozen user cannot login
    const r12 = await post(`${base}/login`, { username: 'alice', password: 'secret123' });
    assert.strictEqual(r12.status, 403, 'Frozen user login should return 403');
    console.log('✓ Frozen user cannot login');

    // Test 12: Admin can reactivate a frozen user
    const r13 = await put(`${base}/admin/users/alice`, { adminPassword: 'admin', active: true });
    assert.strictEqual(r13.status, 200, 'Activate user should return 200');
    const r14 = await post(`${base}/login`, { username: 'alice', password: 'secret123' });
    assert.strictEqual(r14.status, 200, 'Reactivated user should be able to login');
    console.log('✓ Admin can reactivate a frozen user');

    // Test 13: Admin endpoint rejects unauthorized access
    const r15 = await put(`${base}/admin/users/alice`, { adminPassword: 'wrong', active: false });
    assert.strictEqual(r15.status, 401, 'Unauthorized admin action should return 401');
    console.log('✓ Admin endpoint rejects unauthorized access');

    // Test 14: GET /admin/users with valid Basic auth returns user list
    const validBasic = 'Basic ' + Buffer.from('admin:admin').toString('base64');
    const r16 = await get(`${base}/admin/users`, validBasic);
    assert.strictEqual(r16.status, 200, 'GET /admin/users should return 200');
    assert.ok(Array.isArray(r16.data), 'Response should be an array');
    assert.ok(r16.data.some(u => u.username === 'alice'), 'User list should include alice');
    console.log('✓ GET /admin/users with Basic auth returns user list');

    // Test 15: GET /admin/users without auth returns 401
    const r17 = await get(`${base}/admin/users`);
    assert.strictEqual(r17.status, 401, 'GET /admin/users without auth should return 401');
    console.log('✓ GET /admin/users without auth returns 401');

    await new Promise(r => server.close(r));

    // Restore original users.json
    fs.writeFileSync(USERS_FILE, originalData);
    console.log('\nAll tests passed!');
}

run().catch(err => {
    console.error('Test failed:', err.message);
    process.exit(1);
});
