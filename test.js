const assert = require('assert');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');

const USERS_FILE = path.join(__dirname, 'users.json');

// Save and restore users.json around tests
const originalData = fs.readFileSync(USERS_FILE, 'utf8');

async function run() {
    // Reset users.json
    fs.writeFileSync(USERS_FILE, '[]');

    const app = require('./server');
    const http = require('http');
    const server = http.createServer(app);
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

    // Test 1: Signup stores hashed password (not plain text)
    const r1 = await post(`${base}/signup`, { username: 'alice', password: 'secret123' });
    assert.strictEqual(r1.status, 201, 'Signup should return 201');
    assert.strictEqual(r1.data.message, 'Signup successful.');
    const users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    assert.strictEqual(users.length, 1, 'One user should be stored');
    assert.notStrictEqual(users[0].password, 'secret123', 'Password must not be stored in plain text');
    assert.ok(users[0].password.startsWith('$2b$'), 'Password should be a bcrypt hash');
    console.log('✓ Signup stores hashed password');

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

    await new Promise(r => server.close(r));

    // Restore original users.json
    fs.writeFileSync(USERS_FILE, originalData);
    console.log('\nAll tests passed!');
}

run().catch(err => {
    console.error('Test failed:', err.message);
    process.exit(1);
});
