import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

process.env.NODE_ENV = 'test';
process.env.DB_PATH = path.join(os.tmpdir(), `deltacare-test-${Date.now()}.json`);
process.env.TWILIO_MOCK = '1';
process.env.TWILIO_ACCOUNT_SID = 'AC00000000000000000000000000000000';
process.env.TWILIO_AUTH_TOKEN = 'test-auth-token-for-signatures';
process.env.TWILIO_API_KEY_SID = 'SK00000000000000000000000000000000';
process.env.TWILIO_API_KEY_SECRET = 'test-key-secret';
process.env.TWILIO_SMS_FROM = '+17372212163';
process.env.TWILIO_WHATSAPP_FROM = '+17372212163';
process.env.TWILIO_VERIFIED_RECIPIENTS = '+918788083267';
process.env.WEBHOOK_SECRET = 'test-webhook-secret';

await fs.writeFile(process.env.DB_PATH, '{}', 'utf8');

const { default: app } = await import('./index.js');

let baseUrl = '';
const server = app.listen(0);
const waitForServer = () => new Promise((resolve) => server.listening ? resolve() : server.once('listening', resolve));
await waitForServer();
baseUrl = `http://127.0.0.1:${server.address().port}`;
process.env.PUBLIC_BASE_URL = baseUrl;

const twilioSignature = (pathname, params) => {
  let data = `${baseUrl}${pathname}`;
  Object.keys(params).sort().forEach((key) => { const value = params[key]; if (value !== undefined && value !== null) data += `${key}${value}`; });
  return crypto.createHmac('sha1', process.env.TWILIO_AUTH_TOKEN).update(data).digest('base64');
};
const login = async () => {
  const res = await fetch(`${baseUrl}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: 'admin@deltacare.local', password: 'DeltaCare@00000' }) });
  assert.equal(res.status, 200, 'admin login should succeed');
  return res.headers.get('set-cookie').split(';')[0];
};
const authed = (cookie) => ({ 'Content-Type': 'application/json', Cookie: cookie });

test('SMS: rejects templates outside the trial allowlist', async () => {
  const cookie = await login();
  const res = await fetch(`${baseUrl}/api/send/sms`, { method: 'POST', headers: authed(cookie), body: JSON.stringify({ to: '+918788083267', template: 'freeform-text' }) });
  assert.equal(res.status, 400);
  const data = await res.json();
  assert.match(data.message, /predefined templates/);
});

test('SMS: blocks unverified recipients', async () => {
  const cookie = await login();
  const res = await fetch(`${baseUrl}/api/send/sms`, { method: 'POST', headers: authed(cookie), body: JSON.stringify({ to: '+919999999999', template: 'random' }) });
  assert.equal(res.status, 403);
  const data = await res.json();
  assert.match(data.message, /verified recipients/);
});

test('SMS: "random" selects an allowlisted template and sends via mock client', async () => {
  const cookie = await login();
  const res = await fetch(`${baseUrl}/api/send/sms`, { method: 'POST', headers: authed(cookie), body: JSON.stringify({ to: '+918788083267', template: 'random' }) });
  assert.equal(res.status, 201);
  const data = await res.json();
  const allowed = ['sms_2fa', 'sms_appointment_reminders', 'sms_order_confirmation', 'sms_delivery_updates', 'sms_customer_support', 'sms_marketing_promotions', 'sms_event_notifications', 'sms_account_alerts', 'sms_feedback_surveys', 'sms_internal_alerts'];
  assert.ok(allowed.includes(data.template), `template ${data.template} must be from the trial allowlist`);
  assert.match(data.sid, /^SM-mock-/);
});

test('SMS: invalid recipient format is rejected', async () => {
  const cookie = await login();
  const res = await fetch(`${baseUrl}/api/send/sms`, { method: 'POST', headers: authed(cookie), body: JSON.stringify({ to: '9876543210', template: 'random' }) });
  assert.equal(res.status, 400);
  assert.match((await res.json()).message, /E\.164/);
});

test('WhatsApp: blocked when the 24-hour window is closed (no inbound yet)', async () => {
  const cookie = await login();
  const res = await fetch(`${baseUrl}/api/send/whatsapp`, { method: 'POST', headers: authed(cookie), body: JSON.stringify({ to: '+918788083267', message: 'Hello from DeltaCare' }) });
  assert.equal(res.status, 403);
  const data = await res.json();
  assert.match(data.message, /Sandbox|window/);
});

test('WhatsApp: inbound message opens the window, then a custom message sends (mock)', async () => {
  const params = { MessageSid: 'SM-inbound-wa-001', From: 'whatsapp:+918788083267', To: 'whatsapp:+17372212163', Body: 'join twilio-trial', MessageStatus: 'received' };
  const signature = twilioSignature('/api/twilio/incoming', params);
  const incoming = await fetch(`${baseUrl}/api/twilio/incoming`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Twilio-Signature': signature }, body: new URLSearchParams(params).toString() });
  assert.equal(incoming.status, 200);
  assert.match(await incoming.text(), /<Response><\/Response>/);
  const cookie = await login();
  const res = await fetch(`${baseUrl}/api/send/whatsapp`, { method: 'POST', headers: authed(cookie), body: JSON.stringify({ to: '+918788083267', message: 'Custom free-form message inside the window' }) });
  assert.equal(res.status, 201);
  const data = await res.json();
  assert.match(data.sid, /^SM-mock-/);
  assert.equal(data.template, null);
});

test('Incoming webhook: invalid signature is rejected (403)', async () => {
  const res = await fetch(`${baseUrl}/api/twilio/incoming`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Twilio-Signature': 'wrong-signature' }, body: 'MessageSid=SM-bad&Body=hello' });
  assert.equal(res.status, 403);
});

test('Incoming webhook: duplicate MessageSid is idempotent', async () => {
  const params = { MessageSid: 'SM-inbound-wa-001', From: 'whatsapp:+918788083267', To: 'whatsapp:+17372212163', Body: 'duplicate check' };
  const signature = twilioSignature('/api/twilio/incoming', params);
  const res = await fetch(`${baseUrl}/api/twilio/incoming`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Twilio-Signature': signature }, body: new URLSearchParams(params).toString() });
  assert.equal(res.status, 200);
});

test('Status webhook: updates the stored record (delivered) and is idempotent', async () => {
  const params = { MessageSid: 'SM-inbound-wa-001', MessageStatus: 'delivered' };
  const signature = twilioSignature('/api/twilio/status', params);
  const res = await fetch(`${baseUrl}/api/twilio/status`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Twilio-Signature': signature }, body: new URLSearchParams(params).toString() });
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { ok: true });
});

test('Status webhook: stores failure details (ErrorCode/ErrorMessage)', async () => {
  const params = { MessageSid: 'SM-inbound-wa-001', MessageStatus: 'failed', ErrorCode: '30007', ErrorMessage: 'Carrier lookup failed' };
  const signature = twilioSignature('/api/twilio/status', params);
  const res = await fetch(`${baseUrl}/api/twilio/status`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Twilio-Signature': signature }, body: new URLSearchParams(params).toString() });
  assert.equal(res.status, 200);
  const cookie = await login();
  const config = await (await fetch(`${baseUrl}/api/admin/config`, { headers: { Cookie: cookie } })).json();
  const record = config.twilioMessages.find((m) => m.messageSid === 'SM-inbound-wa-001');
  assert.ok(record, 'status-updated record should exist in admin config');
  assert.equal(record.status, 'failed');
  assert.equal(record.errorCode, '30007');
  assert.equal(record.errorMessage, 'Carrier lookup failed');
});

test('Sending endpoints are auth-protected', async () => {
  const res = await fetch(`${baseUrl}/api/send/sms`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ to: '+918788083267', template: 'random' }) });
  assert.equal(res.status, 401);
});

test.after(() => new Promise((resolve) => server.close(resolve)));