import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { verifyTotp } from './advancedFeatures.js';

test('TOTP verification accepts the RFC secret and rejects a wrong code', () => {
  const original = Date.now; Date.now = () => 59000;
  try { assert.equal(verifyTotp('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', '287082'), true); assert.equal(verifyTotp('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', '000000'), false); }
  finally { Date.now = original; }
});

test('advanced operations require authentication and return security headers', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'deltacare-features-')); const database = path.join(directory, 'db.json');
  await fs.writeFile(database, JSON.stringify({ users: [], settings: {} })); process.env.DB_PATH = database; process.env.NODE_ENV = 'test'; process.env.SMTP_HOST = ''; process.env.SMTP_FROM = '';
  const { default: app } = await import(`./index.js?advanced-test=${Date.now()}`); const server = app.listen(0); const address = server.address();
  try {
    const base = `http://127.0.0.1:${address.port}`; const response = await fetch(`${base}/api/admin/operations`); assert.equal(response.status, 401); assert.equal(response.headers.get('x-content-type-options'), 'nosniff'); assert.ok(response.headers.get('x-request-id'));
    const login = await fetch(`${base}/api/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'admin@deltacare.local', password: 'DeltaCare@00000' }) }); assert.equal(login.status, 200); const cookie = login.headers.get('set-cookie').split(';')[0];
    const createdResponse = await fetch(`${base}/api/lost-found`, { method: 'POST', headers: { 'content-type': 'application/json', cookie }, body: JSON.stringify({ kind: 'found', itemName: 'Test keys', description: 'Keys used for the local feature test', category: 'Keys', location: 'Student Services desk', eventDate: '2026-09-02' }) }); assert.equal(createdResponse.status, 201); const created = await createdResponse.json();
    const pickupResponse = await fetch(`${base}/api/lost-found/${created.record.id}/pickups`, { method: 'POST', headers: { 'content-type': 'application/json', cookie }, body: JSON.stringify({ scheduledAt: new Date(Date.now() + 86400000).toISOString(), location: 'Student Services desk' }) }); assert.equal(pickupResponse.status, 201); const pickup = await pickupResponse.json(); assert.match(pickup.code, /^\d{6}$/); assert.match(pickup.qr, /^data:image\/png;base64,/);
    const verify = await fetch(`${base}/api/admin/pickups/${pickup.pickup.id}/verify`, { method: 'POST', headers: { 'content-type': 'application/json', cookie }, body: JSON.stringify({ code: pickup.code }) }); assert.equal(verify.status, 200); assert.equal((await verify.json()).item.status, 'returned');
    const knowledge = await fetch(`${base}/api/knowledge?q=wifi`, { headers: { cookie } }); assert.equal(knowledge.status, 200); assert.ok((await knowledge.json()).articles.length >= 1);
    const search = await fetch(`${base}/api/search/advanced?q=keys&type=lostFound`, { headers: { cookie } }); assert.equal(search.status, 200); assert.ok((await search.json()).total >= 1);
  }
  finally { await new Promise((resolve) => server.close(resolve)); await fs.rm(directory, { recursive: true, force: true }); }
});
