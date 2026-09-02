import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import jwt from 'jsonwebtoken';

process.env.NODE_ENV = 'test';
process.env.DB_PATH = path.join(os.tmpdir(), `deltacare-vonage-test-${Date.now()}.json`);
process.env.VONAGE_APPLICATION_ID = 'aaaaaaaa-bbbb-cccc-dddd-0123456789ab';
process.env.VONAGE_API_KEY = 'test-api-key';
process.env.VONAGE_API_SECRET = 'test-api-secret';
process.env.VONAGE_SIGNATURE_SECRET = 'test-vonage-signature-secret-0123456789abcdef';
process.env.VONAGE_ALLOWED_RECIPIENTS = '918788083267';
process.env.VONAGE_WHATSAPP_FROM = '447700900111';
process.env.WEBHOOK_SECRET = 'test-webhook-secret';
const mockLog = [];

const mockServer = http.createServer((req, res) => {
  let raw = '';
  req.on('data', (chunk) => { raw += chunk; });
  req.on('end', () => {
    mockLog.push({ method: req.method, url: req.url, body: raw, auth: req.headers.authorization || '' });
    res.writeHead(202, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ message_uuid: 'aaaaaaaa-bbbb-cccc-dddd-0123456789ab', status: 'accepted' }));
  });
});
await new Promise((resolve) => mockServer.listen(0, '127.0.0.1', resolve));
process.env.VONAGE_MESSAGES_API_URL = `http://127.0.0.1:${mockServer.address().port}/v1/messages`;

const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const keyDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vonage-key-'));
const keyPath = path.join(keyDir, 'private.key');
await fs.writeFile(keyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }), 'utf8');
process.env.VONAGE_PRIVATE_KEY_PATH = keyPath;

await fs.writeFile(process.env.DB_PATH, '{}', 'utf8');

const { default: app } = await import('./index.js');
const server = app.listen(0);
await new Promise((resolve) => server.once('listening', resolve));
const baseUrl = `http://127.0.0.1:${server.address().port}`;
process.env.PUBLIC_BASE_URL = baseUrl;

const vonageToken = (body) => { const raw = typeof body === 'string' ? body : JSON.stringify(body); const payloadHash = crypto.createHash('sha256').update(raw).digest('hex'); return jwt.sign({ iat: Math.floor(Date.now() / 1000), jti: crypto.randomUUID(), iss: 'Vonage', payload_hash: payloadHash, api_key: 'ko9Vc7CFNX9B3jLh', application_id: process.env.VONAGE_APPLICATION_ID }, process.env.VONAGE_SIGNATURE_SECRET, { algorithm: 'HS256' }); };
const login = async () => { const res = await fetch(`${baseUrl}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: 'admin@deltacare.local', password: 'DeltaCare@00000' }) }); assert.equal(res.status, 200); return res.headers.get('set-cookie').split(';')[0]; };
const authed = (cookie) => ({ 'Content-Type': 'application/json', Cookie: cookie });

test('WhatsApp send: requires authentication', async () => {
  const res = await fetch(`${baseUrl}/api/send/whatsapp`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ to: '+918788083267', message: 'hi' }) });
  assert.equal(res.status, 401);
});

test('WhatsApp send: rejects non-E.164 numbers', async () => {
  const cookie = await login();
  const res = await fetch(`${baseUrl}/api/send/whatsapp`, { method: 'POST', headers: authed(cookie), body: JSON.stringify({ to: '9876543210', message: 'hi' }) });
  assert.equal(res.status, 400);
  assert.match((await res.json()).message, /E\.164/);
});

test('WhatsApp send: blocks non-allow-listed recipients', async () => {
  const cookie = await login();
  const res = await fetch(`${baseUrl}/api/send/whatsapp`, { method: 'POST', headers: authed(cookie), body: JSON.stringify({ to: '+919999999999', message: 'hi' }) });
  assert.equal(res.status, 403);
  assert.match((await res.json()).message, /allow-listed/);
});

test('WhatsApp send: enforces the maximum message length', async () => {
  const cookie = await login();
  const res = await fetch(`${baseUrl}/api/send/whatsapp`, { method: 'POST', headers: authed(cookie), body: JSON.stringify({ to: '+918788083267', message: 'x'.repeat(4097) }) });
  assert.equal(res.status, 400);
  assert.match((await res.json()).message, /character limit/);
});

test('WhatsApp send: requires an open 24-hour window (inbound from recipient)', async () => {
  const cookie = await login();
  const res = await fetch(`${baseUrl}/api/send/whatsapp`, { method: 'POST', headers: authed(cookie), body: JSON.stringify({ to: '+918788083267', message: 'Hello' }) });
  assert.equal(res.status, 403);
  assert.match((await res.json()).message, /24 hours/);
});

test('Inbound webhook: rejects missing/invalid signatures', async () => {
  const payload = { message_uuid: 'bbbbbbbb-cccc-dddd-eeee-0123456789ab', from: '918788083267', to: '447700900111', channel: 'whatsapp', message_type: 'text', text: 'Hello DeltaCare', timestamp: new Date().toISOString() };
  const raw = JSON.stringify(payload);
  const missing = await fetch(`${baseUrl}/api/vonage/inbound`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: raw });
  assert.equal(missing.status, 401);
  const bad = await fetch(`${baseUrl}/api/vonage/inbound`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer invalid.token.here' }, body: raw });
  assert.equal(bad.status, 403);
});

test('Inbound webhook: valid signature stores the message and opens the window; duplicate is idempotent', async () => {
  const payload = { message_uuid: 'bbbbbbbb-cccc-dddd-eeee-0123456789ab', from: '918788083267', to: '447700900111', channel: 'whatsapp', message_type: 'text', text: 'Hello DeltaCare', timestamp: new Date().toISOString() };
  const raw = JSON.stringify(payload);
  const headers = { 'Content-Type': 'application/json', Authorization: `Bearer ${vonageToken(raw)}` };
  const first = await fetch(`${baseUrl}/api/vonage/inbound`, { method: 'POST', headers, body: raw });
  assert.equal(first.status, 200);
  assert.deepEqual(await first.json(), { status: 'received' });
  const second = await fetch(`${baseUrl}/api/vonage/inbound`, { method: 'POST', headers, body: raw });
  assert.equal(second.status, 200);
});

test('WhatsApp send: valid message is submitted to the Vonage Sandbox (mock) and returns the expected shape', async () => {
  mockLog.length = 0;
  const cookie = await login();
  const res = await fetch(`${baseUrl}/api/send/whatsapp`, { method: 'POST', headers: authed(cookie), body: JSON.stringify({ to: '+918788083267', message: 'This is my custom WhatsApp message.' }) });
  assert.equal(res.status, 201);
  const data = await res.json();
  assert.deepEqual(data, { success: true, messageId: 'aaaaaaaa-bbbb-cccc-dddd-0123456789ab', channel: 'whatsapp', status: 'submitted', record: { id: data.record.id, status: 'submitted' } });
  assert.equal(mockLog.length, 1);
  const sent = JSON.parse(mockLog[0].body);
  assert.equal(sent.to, '918788083267');
  assert.equal(sent.from, '447700900111');
  assert.equal(sent.channel, 'whatsapp');
  assert.equal(sent.message_type, 'text');
  assert.equal(sent.text, 'This is my custom WhatsApp message.');
  assert.match(mockLog[0].auth, /^Bearer /);
});

test('Status webhook: valid signature updates the record with status/error info, idempotently', async () => {
  const payload = { message_uuid: 'aaaaaaaa-bbbb-cccc-dddd-0123456789ab', status: 'delivered', channel: 'whatsapp', timestamp: new Date().toISOString(), error_code: '1', error_reason: 'Undelivered' };
  const raw = JSON.stringify(payload);
  const headers = { 'Content-Type': 'application/json', Authorization: `Bearer ${vonageToken(raw)}` };
  const first = await fetch(`${baseUrl}/api/vonage/status`, { method: 'POST', headers, body: raw });
  assert.equal(first.status, 200);
  const second = await fetch(`${baseUrl}/api/vonage/status`, { method: 'POST', headers, body: raw });
  assert.equal(second.status, 200);
  const cookie = await login();
  const config = await (await fetch(`${baseUrl}/api/admin/config`, { headers: { Cookie: cookie } })).json();
  const record = config.vonageMessages.find((m) => m.messageUuid === 'aaaaaaaa-bbbb-cccc-dddd-0123456789ab');
  assert.ok(record, 'status-updated record should exist');
  assert.equal(record.status, 'delivered');
  assert.equal(record.errorCode, '1');
  assert.equal(record.errorReason, 'Undelivered');
});

test.after(() => new Promise((resolve) => { mockServer.close(() => server.close(resolve)); }));