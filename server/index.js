import express from 'express';
import 'dotenv/config';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import crypto from 'node:crypto';
import os from 'node:os';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');
const dbPath = process.env.DB_PATH ? path.resolve(process.env.DB_PATH) : path.join(root, 'data', 'db.json');
const JWT_SECRET = process.env.JWT_SECRET || 'deltacare-local-development-secret';
const PORT = process.env.PORT || 3001;
const app = express();

app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());

const rateBuckets = new Map();
const rateLimit = (windowMs, max) => (req, res, next) => { const key = `${req.ip}:${req.path}`; const current = rateBuckets.get(key); const time = Date.now(); if (!current || current.resetAt < time) { rateBuckets.set(key, { count: 1, resetAt: time + windowMs }); return next(); } current.count++; if (current.count > max) return res.status(429).json({ message: 'Too many requests. Please wait and try again.' }); next(); };
app.use('/api/auth', rateLimit(15 * 60000, 40));

let writeQueue = Promise.resolve();
const readDb = async () => { const db = JSON.parse(await fs.readFile(dbPath, 'utf8')); ensureCollections(db); return db; };
const mutateDb = (mutator) => {
  const operation = writeQueue.then(async () => {
    const db = await readDb();
    ensureCollections(db);
    const result = await mutator(db);
    const temp = `${dbPath}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
    await fs.writeFile(temp, JSON.stringify(db, null, 2));
    await fs.rename(temp, dbPath);
    return result;
  });
  writeQueue = operation.catch(() => {});
  return operation;
};

const publicUser = ({ passwordHash, ...user }) => user;
const auth = async (req, res, next) => {
  try {
    const token = req.cookies.deltacare_session;
    if (!token) return res.status(401).json({ message: 'Please sign in to continue.' });
    const payload = jwt.verify(token, JWT_SECRET);
    const db = await readDb();
    const session = db.sessions.find((item) => item.id === payload.sid && item.expiresAt > new Date().toISOString());
    const user = db.users.find((item) => item.id === payload.uid);
    if (!session || !user) return res.status(401).json({ message: 'Your session has expired.' });
    if (user.suspended) return res.status(403).json({ message: 'This account is suspended. Contact campus support.' });
    req.user = user;
    req.session = session;
    next();
  } catch {
    res.status(401).json({ message: 'Your session has expired.' });
  }
};

const adminOnly = (req, res, next) => req.user && staffAccess({ roles: ROLES }, req.user) ? next() : res.status(403).json({ message: 'Staff workspace access is required.' });
const requirePerm = (perm) => (req, res, next) => hasPerm({ roles: ROLES }, req.user, perm) ? next() : res.status(403).json({ message: `You need the ${perm} permission to do that.` });

const makeId = (prefix) => `${prefix}-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;
const addAudit = (db, action, userId, metadata = {}) => db.auditLogs.push({ id: makeId('AUD'), action, userId, metadata, createdAt: new Date().toISOString() });
const now = () => new Date().toISOString();

const PERMISSIONS = {
  'issues:read': 'View issues you are permitted to see', 'issues:read_all': 'View all campus issues', 'issues:create': 'Report issues', 'issues:update': 'Update issue fields', 'issues:transition': 'Move issues through the workflow', 'issues:assign': 'Assign issues to teams/people', 'issues:comment': 'Add public comments', 'issues:comment_internal': 'Add internal notes', 'issues:read_department': 'View issues for your department', 'issues:triage': 'Triage unclassified issues', 'issues:bulk': 'Perform bulk issue operations', 'issues:link': 'Merge/link duplicate issues', 'lostfound:read': 'View permitted lost & found records', 'lostfound:create': 'Report lost/found items', 'lostfound:manage': 'Operate lost & found records', 'matches:review': 'Accept/reject match candidates', 'inventory:manage': 'Manage storage bins and custody', 'claims:decide': 'Approve/reject ownership claims', 'sensitive:handle': 'Handle sensitive-item workflows', 'dashboard:view': 'View admin dashboards', 'dashboard:view_department': 'View department dashboard', 'analytics:view': 'View analytics', 'reports:view': 'View/export reports', 'users:manage': 'Manage user accounts', 'roles:manage': 'Manage roles and permissions', 'sla:manage': 'Manage SLA policies', 'escalation:manage': 'Manage escalation rules', 'integrations:manage': 'Manage connectors', 'audit:view': 'View audit history', 'data:manage': 'Import/export data', 'backup:manage': 'Create backups', 'backup:restore': 'Restore backups', 'system:view': 'View system health', 'system:manage': 'Manage global configuration', 'templates:manage': 'Manage notification templates', 'retention:manage': 'Manage data retention',
};
const ROLES = [
  { id: 'ROLE-USER', name: 'user', permissions: ['issues:create', 'issues:comment', 'lostfound:create', 'lostfound:read'] },
  { id: 'ROLE-TECH', name: 'technician', permissions: ['issues:read_department', 'issues:update', 'issues:transition', 'issues:comment', 'issues:comment_internal', 'lostfound:read', 'dashboard:view_department', 'workspace:access'] },
  { id: 'ROLE-DMGR', name: 'department_manager', permissions: ['issues:read_all', 'issues:update', 'issues:transition', 'issues:assign', 'issues:comment_internal', 'issues:triage', 'issues:bulk', 'issues:link', 'analytics:view', 'dashboard:view', 'workspace:access'] },
  { id: 'ROLE-LF', name: 'lost_found_staff', permissions: ['lostfound:manage', 'matches:review', 'inventory:manage', 'claims:decide', 'lostfound:read', 'dashboard:view', 'workspace:access'] },
  { id: 'ROLE-SEC', name: 'security_staff', permissions: ['lostfound:manage', 'sensitive:handle', 'inventory:manage', 'matches:review', 'claims:decide', 'audit:view', 'dashboard:view', 'workspace:access'] },
  { id: 'ROLE-ADMIN', name: 'admin', permissions: ['issues:read_all', 'issues:update', 'issues:transition', 'issues:assign', 'issues:triage', 'issues:bulk', 'issues:link', 'lostfound:manage', 'matches:review', 'inventory:manage', 'claims:decide', 'sensitive:handle', 'dashboard:view', 'analytics:view', 'reports:view', 'users:manage', 'roles:manage', 'sla:manage', 'escalation:manage', 'integrations:manage', 'audit:view', 'data:manage', 'backup:manage', 'system:view', 'system:manage', 'templates:manage', 'retention:manage', 'issues:comment_internal', 'workspace:access'] },
  { id: 'ROLE-SUPER', name: 'super_admin', permissions: [...Object.keys(PERMISSIONS), 'backup:restore', 'workspace:access'] },
];
const permsOf = (db, user) => { const set = new Set(); (user.roleIds || []).forEach((id) => { const r = (db.roles || ROLES).find((x) => x.id === id); r?.permissions?.forEach((p) => set.add(p)); }); if (user.role === 'staff') ['issues:read_department', 'issues:update', 'issues:transition', 'issues:comment', 'issues:comment_internal', 'dashboard:view_department', 'workspace:access'].forEach((p) => set.add(p)); if (user.role === 'admin' || user.role === 'super_admin' || set.has('roles:manage') || user.roleIds?.includes('ROLE-SUPER')) Object.keys(PERMISSIONS).forEach((p) => set.add(p)); return set; };
const hasPerm = (db, user, perm) => permsOf(db, user).has(perm) || user.role === 'admin' || user.role === 'super_admin';
const staffAccess = (db, user) => permsOf(db, user).has('workspace:access') || user.role === 'admin';
const departments = [
  { id: 'DEPT-MAINT', name: 'Campus Maintenance', categories: ['Maintenance', 'Plumbing', 'Cleanliness', 'Accessibility'], active: true },
  { id: 'DEPT-ELEC', name: 'Electrical Services', categories: ['Electrical'], active: true },
  { id: 'DEPT-IT', name: 'IT & Network Services', categories: ['IT & network'], active: true },
  { id: 'DEPT-SAFE', name: 'Campus Safety', categories: ['Safety'], active: true },
  { id: 'DEPT-GEN', name: 'Student Services', categories: ['Other'], active: true },
];
const ensureCollections = (db) => {
  const arrays = ['users', 'sessions', 'passwordResets', 'issues', 'lostFound', 'auditLogs', 'notifications', 'comments', 'claims', 'matches', 'custodyEvents', 'jobs', 'savedViews', 'backups', 'escalations', 'moderationReports', 'feedback', 'communications', 'messages'];
  arrays.forEach((key) => { if (!Array.isArray(db[key])) db[key] = []; });
  if (!Array.isArray(db.roles) || !db.roles.length) db.roles = ROLES;
  if (!Array.isArray(db.departments) || !db.departments.length) db.departments = departments;
  const bins = ['INTAKE', 'ELECTRONICS-A1', 'PERSONAL-B2', 'CLOTHING-C3', 'KEYS-D4', 'DOCUMENTS-E5', 'SECURE-B07', 'MISC-F6'];
  if (!Array.isArray(db.storageBins) || !db.storageBins.length) db.storageBins = bins.map((code) => ({ code, active: true }));
  if (!db.settings) db.settings = { slaHours: { critical: 2, high: 8, medium: 24, low: 72 }, matchingThreshold: 35, retentionDays: 365, language: 'en' };
  const s = db.settings;
  if (!s.priorityMatrix) s.priorityMatrix = { low: { low: 'low', medium: 'low', high: 'medium' }, medium: { low: 'low', medium: 'medium', high: 'high' }, high: { low: 'medium', medium: 'high', high: 'critical' } };
  if (!s.workingHours) s.workingHours = { enabled: false, start: '09:00', end: '18:00', days: [1, 2, 3, 4, 5] };
  if (!s.aiThresholds) s.aiThresholds = { duplicate: 0.6 };
  if (!Array.isArray(s.escalationRules) || !s.escalationRules.length) s.escalationRules = [{ id: makeId('ESC-R'), name: 'Critical after 90 min', priority: 'critical', afterMinutes: 90, action: 'notify_manager', enabled: true }, { id: makeId('ESC-R'), name: 'High after 4 hours', priority: 'high', afterMinutes: 240, action: 'notify_manager', enabled: true }];
  const defaultTemplates = { issue_created: 'Hello {user.name}, your report {issue.id} — {issue.name} — was routed to {department}.', issue_fixed: 'Hello {user.name}, we have fixed “{issue.name}”. Your report {issue.id} is now resolved.', issue_in_progress: 'Hello {user.name}, work is continuing on “{issue.name}”. Current status: {status}.', issue_closed: 'Hello {user.name}, your issue “{issue.name}” has been closed.', lost_match_found: 'Hello {user.name}, we found a possible match for “{product.name}” ({product.id}). Please open DeltaCare to review it.', found_item_logged: 'Hello {user.name}, the found item “{product.name}” has been safely logged at {location}.', item_returned: 'Hello {user.name}, “{product.name}” has been returned successfully.', item_not_found: 'Hello {user.name}, we have not found “{product.name}” yet. We will keep its report active.', claim_submitted: 'Your claim for {product.name} is awaiting review.', match_found: 'We found a likely match for {product.name}.' };
  s.templates = { ...defaultTemplates, ...(s.templates || {}) };
  db.users.forEach((user) => { if (!user.roleIds || !user.roleIds.length) user.roleIds = user.role === 'admin' ? ['ROLE-ADMIN', 'ROLE-SUPER'] : user.role === 'staff' ? ['ROLE-TECH'] : ['ROLE-USER']; if (!user.preferences) user.preferences = { email: true, sms: false, whatsapp: false, language: 'en', locationConsent: false }; });
};
const notify = (db, userId, title, message, entityType, entityId) => db.notifications.unshift({ id: makeId('NTF'), userId, title, message, entityType, entityId, read: false, createdAt: now() });
const threadAccess = (db, type, id, user) => {
  if (type === 'issue') {
    const issue = db.issues.find((x) => x.id === id);
    if (!issue) return null;
    const staff = ['admin', 'staff'].includes(user.role) || hasPerm(db, user, 'issues:comment_internal') || hasPerm(db, user, 'issues:comment');
    if (!staff && issue.reporterId !== user.id) return null;
    return issue;
  }
  if (type === 'lostFound') {
    const item = db.lostFound.find((x) => x.id === id);
    if (!item) return null;
    const staff = ['admin', 'staff'].includes(user.role) || hasPerm(db, user, 'lostfound:manage') || hasPerm(db, user, 'lostfound:read');
    if (!staff && item.reporterId !== user.id) return null;
    return item;
  }
  return null;
};
const normalizePhone = (value) => { const phone = String(value || '').trim().replace(/[\s()-]/g, ''); return /^\+[1-9]\d{7,14}$/.test(phone) ? phone : null; };
const renderTemplate = (template, context) => String(template || '').replace(/\{([a-z]+(?:\.[a-z]+)?)\}/gi, (_match, key) => { const value = key.split('.').reduce((current, part) => current?.[part], context); return value === undefined || value === null ? '' : String(value); });
const sendTwilioMessage = async ({ channel, to, body }) => { const accountSid = process.env.TWILIO_ACCOUNT_SID; const authToken = process.env.TWILIO_AUTH_TOKEN; const keySid = process.env.TWILIO_API_KEY_SID; const keySecret = process.env.TWILIO_API_KEY_SECRET; const authUser = authToken ? accountSid : keySid; const authPass = authToken || keySecret; const from = channel === 'whatsapp' ? process.env.TWILIO_WHATSAPP_FROM : process.env.TWILIO_SMS_FROM; if (!accountSid || !authPass || !from) return { status: 'not_configured', detail: `Missing Twilio ${channel} environment configuration (SID, secret/token, or From number).` }; const form = new URLSearchParams({ Body: body, From: channel === 'whatsapp' && !from.startsWith('whatsapp:') ? `whatsapp:${from}` : from, To: channel === 'whatsapp' ? `whatsapp:${to}` : to }); const response = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${accountSid}/Messages.json`, { method: 'POST', headers: { Authorization: `Basic ${Buffer.from(`${authUser}:${authPass}`).toString('base64')}`, 'Content-Type': 'application/x-www-form-urlencoded' }, body: form }); const result = await response.json().catch(() => ({})); if (!response.ok) return { status: 'failed', detail: result.message || `Twilio returned ${response.status}.`, providerCode: result.code }; return { status: result.status || 'queued', providerId: result.sid } };
const sendEmailMessage = async ({ to, subject, body }) => { if (!process.env.SMTP_HOST || !process.env.SMTP_FROM) return { status: 'not_configured', detail: 'SMTP environment configuration is missing.' }; try { const transport = nodemailer.createTransport({ host: process.env.SMTP_HOST, port: Number(process.env.SMTP_PORT || 587), secure: String(process.env.SMTP_SECURE).toLowerCase() === 'true', auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASSWORD } : undefined }); const result = await transport.sendMail({ from: process.env.SMTP_FROM, to, subject, text: body }); return { status: 'sent', providerId: result.messageId }; } catch (error) { return { status: 'failed', detail: error.message }; } };
const tokenize = (value) => new Set(String(value || '').toLowerCase().replace(/[^a-z0-9 ]/g, ' ').split(/\s+/).filter((word) => word.length > 2));
const similarity = (a, b) => { const left = tokenize(a); const right = tokenize(b); if (!left.size || !right.size) return 0; const common = [...left].filter((word) => right.has(word)).length; return Math.round((common / new Set([...left, ...right]).size) * 100); };
const cleanAttachments = (attachments) => (Array.isArray(attachments) ? attachments : []).slice(0, 5).filter((file) => ['image/jpeg', 'image/png', 'image/webp'].includes(file.type) && Number(file.size) <= 2 * 1024 * 1024 && String(file.data || '').startsWith('data:image/')).map((file) => ({ id: makeId('ATT'), name: path.basename(String(file.name || 'image')), type: file.type, size: Number(file.size), sha256: crypto.createHash('sha256').update(String(file.data)).digest('hex'), data: file.data, ocr: { status: 'queued', text: '' } }));
const classify = (text, requestedCategory, requestedPriority) => {
  const value = text.toLowerCase();
  const rules = [
    ['Safety', ['fire', 'smoke', 'gas', 'injury', 'unsafe', 'security']], ['Electrical', ['wire', 'electric', 'light', 'power', 'socket']],
    ['Plumbing', ['water', 'leak', 'tap', 'toilet', 'pipe']], ['IT & network', ['wifi', 'internet', 'computer', 'projector', 'network']],
    ['Cleanliness', ['dirty', 'waste', 'garbage', 'clean', 'spill']], ['Accessibility', ['wheelchair', 'ramp', 'lift', 'accessible']],
  ];
  const matched = rules.find(([, words]) => words.some((word) => value.includes(word)));
  const category = requestedCategory && requestedCategory !== 'Other' ? requestedCategory : matched?.[0] || 'Other';
  const critical = ['fire', 'smoke', 'gas leak', 'exposed wire', 'injury', 'active flooding'].some((word) => value.includes(word));
  const high = critical || ['unsafe', 'flood', 'sparking', 'security'].some((word) => value.includes(word));
  const priority = critical ? 'critical' : requestedPriority === 'high' || high ? 'high' : requestedPriority || 'medium';
  return { category, priority, confidence: matched ? 0.88 : 0.54, factors: matched ? [`Matched ${matched[0].toLowerCase()} keywords`] : ['No strong category keywords'], safetyRuleApplied: critical };
};
const departmentFor = (db, category) => (db.departments.find((dept) => dept.active && dept.categories.includes(category)) || db.departments.find((dept) => dept.id === 'DEPT-GEN'));
const addHours = (date, hours) => new Date(new Date(date).getTime() + hours * 3600000).toISOString();
const businessDue = (db, date, hours) => {
  const wh = db.settings?.workingHours || { enabled: false, start: '09:00', end: '18:00', days: [1, 2, 3, 4, 5] };
  if (!wh.enabled) return addHours(date, hours);
  const start = new Date(date); const minutesLeft = hours * 60; const [sh, sm] = (wh.start || '09:00').split(':').map(Number); const [eh, em] = (wh.end || '18:00').split(':').map(Number);
  const dayStart = (d) => new Date(d.getFullYear(), d.getMonth(), d.getDate(), sh, sm); const dayEnd = (d) => new Date(d.getFullYear(), d.getMonth(), d.getDate(), eh, em); const isWorkday = (d) => (wh.days || [1, 2, 3, 4, 5]).includes(d.getDay());
  let cursor = new Date(start); let remaining = minutesLeft;
  while (remaining > 0) { if (!isWorkday(cursor)) { cursor.setDate(cursor.getDate() + 1); cursor.setHours(sh, sm, 0, 0); continue; } const segStart = new Date(Math.max(cursor.getTime(), dayStart(cursor).getTime())); let segEnd = dayEnd(cursor); if (segStart >= segEnd) { cursor.setDate(cursor.getDate() + 1); cursor.setHours(sh, sm, 0, 0); continue; } const avail = (segEnd - segStart) / 60000; if (remaining <= avail) { segEnd = new Date(segStart.getTime() + remaining * 60000); remaining = 0; } else { remaining -= avail; cursor.setDate(cursor.getDate() + 1); cursor.setHours(sh, sm, 0, 0); } }
  return segEnd.toISOString();
};
const priorityFromMatrix = (db, impact, urgency) => { const m = db.settings?.priorityMatrix; if (!m) return 'medium'; const i = ['low', 'medium', 'high'].includes(impact) ? impact : 'medium'; const u = ['low', 'medium', 'high'].includes(urgency) ? urgency : 'medium'; return (m[i] || {})[u] || 'medium'; };
const evaluateEscalations = (db) => {
  const rules = (db.settings?.escalationRules || []).filter((r) => r.enabled);
  const activeKeys = new Set(); db.escalations.filter((entry) => entry.status === 'active').sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).forEach((entry) => { const key = `${entry.issueId}:${entry.ruleId}`; if (activeKeys.has(key)) { entry.status = 'superseded'; entry.closedAt = now(); } else activeKeys.add(key); });
  db.issues.forEach((issue) => {
    if (!issue.sla || ['resolved', 'closed'].includes(issue.status)) { db.escalations.filter((entry) => entry.issueId === issue.id && entry.status === 'active').forEach((entry) => { entry.status = 'closed'; entry.closedAt = now(); }); return; }
    const minutesOpen = (new Date() - new Date(issue.sla.startedAt || issue.createdAt)) / 60000;
    const rule = rules.find((r) => r.priority === issue.priority && minutesOpen >= r.afterMinutes && !db.escalations.some((entry) => entry.issueId === issue.id && entry.ruleId === r.id && entry.status === 'active'));
    if (rule) { const ev = { id: makeId('ESC'), ruleId: rule.id, ruleName: rule.name, issueId: issue.id, priority: issue.priority, afterMinutes: rule.afterMinutes, action: rule.action, status: 'active', createdAt: now() }; db.escalations.push(ev); issue.escalationIds = issue.escalationIds || []; issue.escalationIds.push(ev.id); addAudit(db, 'issue.escalated', 'SYSTEM', { issueId: issue.id, ruleId: rule.id, action: rule.action }); }
  });
};
const workloadOf = (db, userId) => db.issues.filter((item) => item.assigneeId === userId && !['resolved', 'closed'].includes(item.status)).length;
const recommendAssignee = (db, deptId) => { const candidates = db.users.filter((u) => u.role !== 'admin' && u.departmentId === deptId && !u.suspended); if (!candidates.length) return null; return [...candidates].sort((a, b) => workloadOf(db, a.id) - workloadOf(db, b.id))[0]; };
const getIssueForUser = (db, id, user) => { const issue = db.issues.find((item) => item.id === id); return issue && (issue.reporterId === user.id || ['admin', 'staff'].includes(user.role)) ? issue : null; };

app.post('/api/auth/register', async (req, res) => {
  const { name, email, password, role = 'student', campusId = '', phone, smsConsent = false, whatsappConsent = false } = req.body; const normalizedPhone = normalizePhone(phone);
  if (!name?.trim() || !email?.trim() || !password || password.length < 8 || !normalizedPhone) return res.status(400).json({ message: 'Enter your name, campus email, phone in international format (for example +919876543210), and a password of at least 8 characters.' });
  const normalizedEmail = email.trim().toLowerCase();
  try {
    const user = await mutateDb(async (db) => {
      if (db.users.some((item) => item.email === normalizedEmail)) throw new Error('An account with this email already exists.');
      if (db.users.some((item) => item.phone === normalizedPhone)) throw new Error('An account with this phone number already exists.');
      const created = { id: makeId('USR'), name: name.trim(), email: normalizedEmail, campusId: campusId.trim(), phone: normalizedPhone, role: ['student', 'staff'].includes(role) ? role : 'student', passwordHash: await bcrypt.hash(password, 12), verified: true, preferences: { email: true, sms: Boolean(smsConsent), whatsapp: Boolean(whatsappConsent), language: 'en', locationConsent: false }, createdAt: new Date().toISOString() };
      db.users.push(created);
      addAudit(db, 'account.created', created.id, { role: created.role });
      return publicUser(created);
    });
    res.status(201).json({ user, message: 'Your DeltaCare account is ready.' });
  } catch (error) { res.status(409).json({ message: error.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const db = await readDb();
  const user = db.users.find((item) => item.email === String(email || '').trim().toLowerCase());
  if (!user || !(await bcrypt.compare(password || '', user.passwordHash))) return res.status(401).json({ message: 'Email or password is incorrect.' });
  if (user.suspended) return res.status(403).json({ message: 'This account is suspended. Contact campus support.' });
  const session = { id: makeId('SES'), userId: user.id, createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 7 * 86400000).toISOString() };
  await mutateDb((latest) => { latest.sessions.push(session); addAudit(latest, 'session.created', user.id); });
  const token = jwt.sign({ uid: user.id, sid: session.id }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('deltacare_session', token, { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 7 * 86400000 });
  res.json({ user: publicUser(user) });
});

app.post('/api/auth/forgot', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const db = await readDb();
  const user = db.users.find((item) => item.email === email);
  if (user) await mutateDb((latest) => { latest.passwordResets = latest.passwordResets.filter((item) => item.userId !== user.id); latest.passwordResets.push({ id: makeId('RST'), userId: user.id, otp: '00000', expiresAt: new Date(Date.now() + 10 * 60000).toISOString(), used: false }); addAudit(latest, 'password.reset_requested', user.id); });
  res.json({ message: 'If that account exists, a verification code is ready.', testingOtp: '00000' });
});

app.post('/api/auth/verify-otp', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const db = await readDb();
  const user = db.users.find((item) => item.email === email);
  const reset = user && [...db.passwordResets].reverse().find((item) => item.userId === user.id && !item.used && item.expiresAt > new Date().toISOString());
  if (!reset || req.body.otp !== '00000') return res.status(400).json({ message: 'That code is invalid or has expired.' });
  res.json({ resetId: reset.id, message: 'Code verified.' });
});

app.post('/api/auth/reset-password', async (req, res) => {
  const { resetId, password } = req.body;
  if (!password || password.length < 8) return res.status(400).json({ message: 'Use at least 8 characters.' });
  try {
    await mutateDb(async (db) => {
      const reset = db.passwordResets.find((item) => item.id === resetId && !item.used && item.expiresAt > new Date().toISOString());
      if (!reset) throw new Error('This reset request is invalid or expired.');
      const user = db.users.find((item) => item.id === reset.userId);
      user.passwordHash = await bcrypt.hash(password, 12); reset.used = true;
      db.sessions = db.sessions.filter((item) => item.userId !== user.id);
      addAudit(db, 'password.changed', user.id);
    });
    res.json({ message: 'Password updated. You can sign in now.' });
  } catch (error) { res.status(400).json({ message: error.message }); }
});

app.get('/api/auth/me', auth, (req, res) => res.json({ user: publicUser(req.user) }));
app.post('/api/auth/logout', auth, async (req, res) => { await mutateDb((db) => { db.sessions = db.sessions.filter((item) => item.id !== req.session.id); }); res.clearCookie('deltacare_session'); res.json({ message: 'Signed out.' }); });

app.get('/api/thread/:type/:id/messages', auth, async (req, res) => { const db = await readDb(); const entity = threadAccess(db, req.params.type, req.params.id, req.user); if (!entity) return res.status(404).json({ message: 'Thread not found.' }); res.json({ messages: db.messages.filter((m) => m.threadType === req.params.type && m.threadId === req.params.id) }); });

app.post('/api/thread/:type/:id/messages', auth, async (req, res) => { const body = String(req.body.message || '').trim(); if (!body) return res.status(400).json({ message: 'Message cannot be empty.' }); try { const message = await mutateDb((db) => { const entity = threadAccess(db, req.params.type, req.params.id, req.user); if (!entity) throw new Error('Thread not found.'); const item = { id: makeId('MSG'), threadType: req.params.type, threadId: entity.id, authorId: req.user.id, authorName: req.user.name, message: body, createdAt: now() }; db.messages.push(item); const otherId = entity.reporterId !== req.user.id ? entity.reporterId : null; if (otherId) notify(db, otherId, `New message on ${req.params.type === 'issue' ? 'your issue' : 'your item'}`, `${req.user.name}: ${body}`, req.params.type, entity.id); addAudit(db, 'thread.message_added', req.user.id, { threadType: req.params.type, threadId: entity.id }); return item; }); res.status(201).json({ message }); } catch (error) { res.status(404).json({ message: error.message }); } });

app.post('/api/admin/lost-found/:id/send-match', auth, requirePerm('lostfound:manage'), async (req, res) => { const foundIds = Array.isArray(req.body.foundItemIds) ? req.body.foundItemIds.filter((x) => x) : []; try { const result = await mutateDb((db) => { const lost = db.lostFound.find((x) => x.id === req.params.id); if (!lost || lost.kind !== 'lost') throw new Error('Select a lost item record.'); const foundItems = db.lostFound.filter((x) => foundIds.includes(x.id) && x.kind === 'found'); if (!foundItems.length) throw new Error('Select at least one found item.'); const created = []; foundItems.forEach((found) => { const exists = db.matches.some((m) => m.lostItemId === lost.id && m.foundItemId === found.id); if (exists) return; const match = { id: makeId('MCH'), lostItemId: lost.id, foundItemId: found.id, sourceItemId: found.id, candidateItemId: lost.id, score: 100, overallScore: 100, components: { text: 100, image: 0, ocr: 0, attributes: 100, location: 100, time: 100 }, explanation: ['Manually paired by staff', 'Sent to the lost-item reporter for review'], status: 'accepted', createdBy: req.user.id, createdAt: now() }; db.matches.push(match); created.push({ match, found }); }); if (!created.length) throw new Error('Those items are already matched.'); lost.status = 'possible_match'; lost.updatedAt = now(); foundItems.forEach((found) => { found.status = 'possible_match'; found.updatedAt = now(); }); const victim = db.users.find((u) => u.id === lost.reporterId); if (victim) { notify(db, victim.id, 'Possible match for your lost item', `We paired your ${lost.itemName} with found item(s): ${foundItems.map((f) => f.itemName).join(', ')}. Review the chat to arrange return.`, 'lostFound', lost.id); db.messages.push({ id: makeId('MSG'), threadType: 'lostFound', threadId: lost.id, authorId: 'SYSTEM', authorName: 'DeltaCare Staff', message: `We matched your ${lost.itemName} with found item(s): ${foundItems.map((f) => f.itemName).join(', ')}. Reply here to arrange return.`, createdAt: now() }); } addAudit(db, 'lost_found.match_sent_to_victim', req.user.id, { lostItemId: lost.id, foundItemIds: foundItems.map((f) => f.id) }); return { lost, found: foundItems, matches: created.map((c) => c.match) }; }); res.json({ result }); } catch (error) { res.status(400).json({ message: error.message }); } });

app.get('/api/overview', auth, async (req, res) => {
  const db = await readDb();
  const ownIssues = db.issues.filter((item) => item.reporterId === req.user.id);
  const ownItems = db.lostFound.filter((item) => item.reporterId === req.user.id);
  res.json({ issues: ownIssues, lostFound: ownItems, stats: { active: ownIssues.filter((item) => !['resolved', 'closed'].includes(item.status)).length, resolved: ownIssues.filter((item) => item.status === 'resolved').length, items: ownItems.length } });
});

app.post('/api/issues', auth, async (req, res) => {
  const { title, description, category, location, priority = 'medium', coordinates = null, attachments = [], impact = 'medium', urgency = 'medium', anonymous = false } = req.body;
  if (!title?.trim() || !description?.trim() || !location?.trim()) return res.status(400).json({ message: 'Title, details, and location are required.' });
  const issue = await mutateDb((db) => {
    const createdAt = now(); const matrixPriority = priorityFromMatrix(db, impact, urgency); const ai = classify(`${title} ${description}`, category, matrixPriority); ai.matrixPriority = matrixPriority; ai.requestedPriority = priority; const dept = departmentFor(db, ai.category);
    const duplicates = db.issues.map((candidate) => ({ id: candidate.id, title: candidate.title, score: similarity(`${title} ${description} ${location}`, `${candidate.title} ${candidate.description} ${candidate.location}`) })).filter((candidate) => candidate.score >= 28).sort((a, b) => b.score - a.score).slice(0, 3);
    const slaHours = db.settings.slaHours[ai.priority] || 24;
    const item = { id: makeId('ISS'), version: 1, reporterId: anonymous ? 'ANONYMOUS' : req.user.id, anonymous: Boolean(anonymous), title: title.trim(), description: description.trim(), category: ai.category, location: location.trim(), coordinates, attachments: cleanAttachments(attachments), priority: ai.priority, impact, urgency, status: 'submitted', departmentId: dept?.id, assigneeId: null, ai: { category: ai.category, priority: ai.priority, matrixPriority, confidence: ai.confidence, factors: ai.factors, safetyRuleApplied: ai.safetyRuleApplied }, duplicateCandidates: duplicates, parentIssueId: null, sla: { policy: `${ai.priority} priority`, startedAt: createdAt, dueAt: businessDue(db, createdAt, slaHours), breached: false, paused: false }, statusHistory: [{ status: 'submitted', actorId: anonymous ? 'ANONYMOUS' : req.user.id, at: createdAt }], feedback: null, createdAt, updatedAt: createdAt };
    db.issues.unshift(item); item.attachments.forEach((attachment) => db.jobs.push({ id: makeId('JOB'), type: 'ocr', entityId: item.id, attachmentId: attachment.id, status: 'queued', retryCount: 0, createdAt })); notify(db, req.user.id, 'Report received', `${item.id} was routed to ${dept?.name || 'Student Services'}.`, 'issue', item.id); addAudit(db, 'issue.created', req.user.id, { issueId: item.id, ai: item.ai }); return item;
  });
  res.status(201).json({ issue });
});

app.post('/api/lost-found', auth, async (req, res) => {
  const { kind, itemName, description, category, location, eventDate, color = '', brand = '', privateAttributes = '', attachments = [], coordinates = null, storageBin = null, sensitive = false } = req.body;
  if (!['lost', 'found'].includes(kind) || !itemName?.trim() || !description?.trim() || !location?.trim()) return res.status(400).json({ message: 'Please complete the item, description, and location fields.' });
  const record = await mutateDb((db) => {
    const createdAt = now();
    const sensitiveCategory = sensitive || ['ID, card or wallet', 'Keys', 'Personal item'].includes(category);
    const item = { id: makeId(kind === 'lost' ? 'LST' : 'FND'), version: 1, reporterId: req.user.id, kind, itemName: itemName.trim(), description: description.trim(), category: category || 'Other', color, brand, privateAttributes, publicAttributes: { color, brand }, attachments: cleanAttachments(attachments), coordinates, location: location.trim(), eventDate: eventDate || createdAt.slice(0, 10), status: 'matching', sensitive: sensitiveCategory, inventory: kind === 'found' ? { tag: makeId('TAG'), storageBin: storageBin || 'INTAKE', custodianId: req.user.id, checkedInAt: createdAt } : null, createdAt, updatedAt: createdAt };
    const candidates = db.lostFound.filter((candidate) => candidate.kind !== kind && !['returned', 'closed'].includes(candidate.status)).map((candidate) => { const text = similarity(`${item.itemName} ${item.description} ${color} ${brand}`, `${candidate.itemName} ${candidate.description} ${candidate.color || ''} ${candidate.brand || ''}`); const locationScore = similarity(item.location, candidate.location); const categoryScore = item.category === candidate.category ? 100 : 0; const timeDays = Math.abs(new Date(item.eventDate) - new Date(candidate.eventDate)) / 86400000; const timeScore = Math.max(0, Math.round(100 - timeDays * 8)); const itemImage = item.attachments[0]; const candidateImage = candidate.attachments?.[0]; const imageScore = itemImage && candidateImage ? Math.max(0, Math.round(100 - Math.abs(itemImage.size - candidateImage.size) / Math.max(itemImage.size, candidateImage.size) * 100)) : 0; const score = Math.round(text * .45 + imageScore * .2 + locationScore * .1 + categoryScore * .15 + timeScore * .1); return { id: makeId('MCH'), sourceItemId: item.id, candidateItemId: candidate.id, score, components: { text, image: imageScore, ocr: 0, attributes: categoryScore, location: locationScore, time: timeScore }, explanation: [`${text}% description similarity`, item.category === candidate.category ? 'Same category' : 'Related category', `${locationScore}% location similarity`, `${timeScore}% time plausibility`], status: 'suggested', createdAt }; }).filter((match) => match.score >= db.settings.matchingThreshold).sort((a, b) => b.score - a.score).slice(0, 10);
    db.lostFound.unshift(item); item.attachments.forEach((attachment) => db.jobs.push({ id: makeId('JOB'), type: 'ocr_and_image_features', entityId: item.id, attachmentId: attachment.id, status: 'queued', retryCount: 0, createdAt })); db.matches.push(...candidates); candidates.forEach((match) => { const candidate = db.lostFound.find((entry) => entry.id === match.candidateItemId); if (candidate) { notify(db, item.reporterId, 'Possible item match', `We found a ${match.score}% match for ${item.itemName}.`, 'lostFound', item.id); notify(db, candidate.reporterId, 'Possible item match', `A new report may match ${candidate.itemName}.`, 'lostFound', candidate.id); } }); if (item.inventory) db.custodyEvents.push({ id: makeId('CST'), itemId: item.id, action: 'checked_in', from: 'Finder', to: 'INTAKE', actorId: req.user.id, createdAt }); addAudit(db, `lost_found.${kind}_created`, req.user.id, { recordId: item.id, matches: candidates.length }); return item;
  });
  res.status(201).json({ record });
});

app.get('/api/issues', auth, async (req, res) => {
  const db = await readDb(); let issues = req.user.role === 'admin' ? db.issues : db.issues.filter((item) => item.reporterId === req.user.id || (req.user.role === 'staff' && item.departmentId === req.user.departmentId));
  const q = String(req.query.q || '').toLowerCase(); if (q) issues = issues.filter((item) => `${item.id} ${item.title} ${item.description} ${item.location}`.toLowerCase().includes(q));
  if (req.query.status) issues = issues.filter((item) => item.status === req.query.status); if (req.query.category) issues = issues.filter((item) => item.category === req.query.category);
  res.json({ issues });
});

app.get('/api/issues/:id', auth, async (req, res) => {
  const db = await readDb(); const issue = getIssueForUser(db, req.params.id, req.user); if (!issue) return res.status(404).json({ message: 'Issue not found.' });
  const comments = db.comments.filter((item) => item.issueId === issue.id && (!item.internal || ['admin', 'staff'].includes(req.user.role)));
  res.json({ issue, comments, department: db.departments.find((item) => item.id === issue.departmentId) || null });
});

app.post('/api/issues/:id/comments', auth, async (req, res) => {
  if (!String(req.body.message || '').trim()) return res.status(400).json({ message: 'Comment cannot be empty.' });
  try { const comment = await mutateDb((db) => { const issue = getIssueForUser(db, req.params.id, req.user); if (!issue) throw new Error('Issue not found.'); const internal = Boolean(req.body.internal) && ['admin', 'staff'].includes(req.user.role); const item = { id: makeId('COM'), issueId: issue.id, authorId: req.user.id, authorName: req.user.name, message: req.body.message.trim(), internal, createdAt: now() }; db.comments.push(item); if (req.user.id !== issue.reporterId && !internal) notify(db, issue.reporterId, 'New update on your report', `${req.user.name} commented on ${issue.id}.`, 'issue', issue.id); addAudit(db, internal ? 'issue.internal_note_added' : 'issue.comment_added', req.user.id, { issueId: issue.id }); return item; }); res.status(201).json({ comment }); } catch (error) { res.status(404).json({ message: error.message }); }
});

app.post('/api/issues/:id/action', auth, async (req, res) => {
  const allowed = ['reopen', 'confirm', 'feedback'];
  if (!allowed.includes(req.body.action)) return res.status(400).json({ message: 'Invalid issue action.' });
  try { const issue = await mutateDb((db) => { const item = db.issues.find((entry) => entry.id === req.params.id && entry.reporterId === req.user.id); if (!item) throw new Error('Issue not found.'); if (req.body.action === 'reopen') { if (!['resolved', 'closed'].includes(item.status)) throw new Error('Only resolved issues can be reopened.'); item.status = 'submitted'; item.reopenReason = String(req.body.reason || '').trim(); item.statusHistory.push({ status: 'submitted', actorId: req.user.id, at: now(), reason: item.reopenReason }); } if (req.body.action === 'confirm') { item.status = 'closed'; item.statusHistory.push({ status: 'closed', actorId: req.user.id, at: now(), reason: 'Reporter confirmed resolution' }); } if (req.body.action === 'feedback') item.feedback = { rating: Math.max(1, Math.min(5, Number(req.body.rating) || 5)), comment: String(req.body.comment || ''), createdAt: now() }; item.updatedAt = now(); addAudit(db, `issue.${req.body.action}`, req.user.id, { issueId: item.id }); return item; }); res.json({ issue }); } catch (error) { res.status(400).json({ message: error.message }); }
});

app.get('/api/lost-found', auth, async (req, res) => { const db = await readDb(); const items = db.lostFound.filter((item) => item.kind === 'found' || item.reporterId === req.user.id || ['admin', 'staff'].includes(req.user.role)).map((item) => { const privileged = item.reporterId === req.user.id || ['admin', 'staff'].includes(req.user.role); return { ...item, privateAttributes: privileged ? item.privateAttributes : undefined, inventory: privileged ? item.inventory : item.inventory ? { tag: item.inventory.tag } : null, reporterId: privileged ? item.reporterId : undefined, matches: privileged ? db.matches.filter((match) => match.sourceItemId === item.id || match.candidateItemId === item.id) : [] }; }); res.json({ items }); });
app.get('/api/lost-found/:id', auth, async (req, res) => { const db = await readDb(); const item = db.lostFound.find((entry) => entry.id === req.params.id); if (!item || (item.reporterId !== req.user.id && !['admin', 'staff'].includes(req.user.role))) return res.status(404).json({ message: 'Item record not found.' }); res.json({ item, matches: db.matches.filter((match) => match.sourceItemId === item.id || match.candidateItemId === item.id), claims: db.claims.filter((claim) => claim.itemId === item.id && (claim.claimantId === req.user.id || ['admin', 'staff'].includes(req.user.role))), custody: ['admin', 'staff'].includes(req.user.role) ? db.custodyEvents.filter((event) => event.itemId === item.id) : [] }); });
app.post('/api/lost-found/:id/claims', auth, async (req, res) => { if (!String(req.body.evidence || '').trim()) return res.status(400).json({ message: 'Describe how you can verify ownership.' }); try { const claim = await mutateDb((db) => { const item = db.lostFound.find((entry) => entry.id === req.params.id); if (!item) throw new Error('Item record not found.'); const created = { id: makeId('CLM'), itemId: item.id, claimantId: req.user.id, evidence: req.body.evidence.trim(), status: 'pending', decisionReason: null, createdAt: now() }; db.claims.push(created); notify(db, req.user.id, 'Claim submitted', `Your claim for ${item.itemName} is awaiting staff review.`, 'lostFound', item.id); addAudit(db, 'claim.created', req.user.id, { claimId: created.id, itemId: item.id }); return created; }); res.status(201).json({ claim }); } catch (error) { res.status(404).json({ message: error.message }); } });

app.get('/api/notifications', auth, async (req, res) => { const db = await readDb(); res.json({ notifications: db.notifications.filter((item) => item.userId === req.user.id).slice(0, 100) }); });
app.patch('/api/notifications/:id/read', auth, async (req, res) => { await mutateDb((db) => { const item = db.notifications.find((entry) => entry.id === req.params.id && entry.userId === req.user.id); if (item) item.read = true; }); res.json({ message: 'Notification updated.' }); });
app.patch('/api/profile', auth, async (req, res) => { try { const user = await mutateDb((db) => { const item = db.users.find((entry) => entry.id === req.user.id); const name = req.body.name === undefined ? item.name : String(req.body.name).trim(); const email = req.body.email === undefined ? item.email : String(req.body.email).trim().toLowerCase(); const campusId = req.body.campusId === undefined ? item.campusId : String(req.body.campusId).trim(); const requestedPhone = req.body.phone === undefined ? item.phone : String(req.body.phone).trim(); const phone = requestedPhone ? normalizePhone(requestedPhone) : ''; if (!name || !email || !email.includes('@')) throw new Error('Enter a valid name and email address.'); if (requestedPhone && !phone) throw new Error('Use international phone format, for example +919876543210.'); if (db.users.some((entry) => entry.id !== item.id && entry.email === email)) throw new Error('That email address is already in use.'); if (campusId && db.users.some((entry) => entry.id !== item.id && entry.campusId === campusId)) throw new Error('That campus ID is already in use.'); if (phone && db.users.some((entry) => entry.id !== item.id && entry.phone === phone)) throw new Error('That phone number is already in use.'); item.name = name; item.email = email; item.campusId = campusId; item.phone = phone; if (req.body.preferences) item.preferences = { ...item.preferences, ...req.body.preferences }; addAudit(db, 'profile.updated', item.id, { fields: Object.keys(req.body).filter((key) => key !== 'preferences'), preferencesUpdated: Boolean(req.body.preferences) }); return publicUser(item); }); res.json({ user }); } catch (error) { res.status(400).json({ message: error.message }); } });
app.get('/api/privacy/export', auth, async (req, res) => { const db = await readDb(); res.json({ exportedAt: now(), profile: publicUser(req.user), issues: db.issues.filter((item) => item.reporterId === req.user.id), lostFound: db.lostFound.filter((item) => item.reporterId === req.user.id), notifications: db.notifications.filter((item) => item.userId === req.user.id) }); });
app.get('/api/search', auth, async (req, res) => { const db = await readDb(); const q = String(req.query.q || '').trim().toLowerCase(); if (!q) return res.json({ results: [] }); const allowedIssues = db.issues.filter((item) => item.reporterId === req.user.id || ['admin', 'staff'].includes(req.user.role)); const allowedItems = db.lostFound.filter((item) => item.reporterId === req.user.id || ['admin', 'staff'].includes(req.user.role)); const results = [...allowedIssues.filter((item) => JSON.stringify(item).toLowerCase().includes(q)).map((item) => ({ type: 'issue', id: item.id, title: item.title, subtitle: item.location, status: item.status })), ...allowedItems.filter((item) => `${item.id} ${item.itemName} ${item.description} ${item.location}`.toLowerCase().includes(q)).map((item) => ({ type: 'lostFound', id: item.id, title: item.itemName, subtitle: item.location, status: item.status }))].slice(0, 50); res.json({ results }); });

app.get('/api/admin/overview', auth, adminOnly, async (_req, res) => {
  const db = await readDb();
  db.issues.forEach((item) => { if (item.sla) item.sla.breached = new Date(item.sla.dueAt) < new Date() && !['resolved', 'closed'].includes(item.status); });
  evaluateEscalations(db);
  const users = db.users.map(publicUser);
  res.json({
    issues: db.issues,
    lostFound: db.lostFound,
    users,
    departments: db.departments,
    claims: db.claims,
    escalations: db.escalations.filter((item) => item.status === 'active'),
    matches: db.matches,
    roles: db.roles,
    storageBins: db.storageBins,
    settings: db.settings,
    stats: {
      openIssues: db.issues.filter((item) => !['resolved', 'closed'].includes(item.status)).length,
      resolvedIssues: db.issues.filter((item) => ['resolved', 'closed'].includes(item.status)).length,
      matchingItems: db.lostFound.filter((item) => item.status === 'matching').length,
      users: users.filter((item) => item.role !== 'admin').length,
    },
  });
});

app.patch('/api/admin/issues/:id', auth, adminOnly, async (req, res) => {
  const allowed = ['submitted', 'triaged', 'assigned', 'in_progress', 'resolved', 'closed'];
  if (!allowed.includes(req.body.status)) return res.status(400).json({ message: 'Invalid issue status.' });
  try {
    const issue = await mutateDb((db) => {
      const item = db.issues.find((entry) => entry.id === req.params.id);
      if (!item) throw new Error('Issue not found.');
      item.status = req.body.status; item.updatedAt = now(); if (!Array.isArray(item.statusHistory)) item.statusHistory = []; item.statusHistory.push({ status: item.status, actorId: req.user.id, at: item.updatedAt }); if (item.sla) item.sla.breached = new Date(item.sla.dueAt) < new Date() && !['resolved', 'closed'].includes(item.status); notify(db, item.reporterId, `Issue ${item.status.replace('_', ' ')}`, `${item.id} is now ${item.status.replace('_', ' ')}.`, 'issue', item.id);
      addAudit(db, 'issue.status_changed', req.user.id, { issueId: item.id, status: item.status });
      return item;
    });
    res.json({ issue });
  } catch (error) { res.status(404).json({ message: error.message }); }
});

app.patch('/api/admin/lost-found/:id', auth, adminOnly, async (req, res) => {
  const allowed = ['matching', 'possible_match', 'claim_review', 'returned', 'closed'];
  if (!allowed.includes(req.body.status)) return res.status(400).json({ message: 'Invalid item status.' });
  try {
    const record = await mutateDb((db) => {
      const item = db.lostFound.find((entry) => entry.id === req.params.id);
      if (!item) throw new Error('Item record not found.');
      item.status = req.body.status; item.updatedAt = now(); notify(db, item.reporterId, `Item status: ${item.status.replace('_', ' ')}`, `${item.id} is now ${item.status.replace('_', ' ')}.`, 'lostFound', item.id);
      addAudit(db, 'lost_found.status_changed', req.user.id, { recordId: item.id, status: item.status });
      return item;
    });
    res.json({ record });
  } catch (error) { res.status(404).json({ message: error.message }); }
});

app.patch('/api/admin/issues/:id/link', auth, adminOnly, async (req, res) => { try { const issue = await mutateDb((db) => { const item = db.issues.find((entry) => entry.id === req.params.id); const parent = db.issues.find((entry) => entry.id === req.body.parentIssueId); if (!item || !parent || item.id === parent.id) throw new Error('Select two valid issues.'); item.parentIssueId = parent.id; item.duplicate = item.duplicate || {}; item.duplicate.duplicateOf = parent.id; addAudit(db, 'issue.duplicate_linked', req.user.id, { issueId: item.id, parentIssueId: parent.id }); return item; }); res.json({ issue }); } catch (error) { res.status(400).json({ message: error.message }); } });
app.patch('/api/admin/claims/:id', auth, adminOnly, async (req, res) => { if (!['approved', 'rejected'].includes(req.body.status)) return res.status(400).json({ message: 'Invalid claim decision.' }); try { const claim = await mutateDb((db) => { const item = db.claims.find((entry) => entry.id === req.params.id); if (!item) throw new Error('Claim not found.'); item.status = req.body.status; item.decisionReason = String(req.body.reason || '').trim(); item.decidedBy = req.user.id; item.decidedAt = now(); const lostItem = db.lostFound.find((entry) => entry.id === item.itemId); if (lostItem && item.status === 'approved') { lostItem.status = 'returned'; db.custodyEvents.push({ id: makeId('CST'), itemId: lostItem.id, action: 'checked_out', from: lostItem.inventory?.storageBin || 'INTAKE', to: 'Claimant', actorId: req.user.id, recipientId: item.claimantId, createdAt: now() }); } notify(db, item.claimantId, `Claim ${item.status}`, `Your ownership claim has been ${item.status}.`, 'lostFound', item.itemId); addAudit(db, `claim.${item.status}`, req.user.id, { claimId: item.id, reason: item.decisionReason }); return item; }); res.json({ claim }); } catch (error) { res.status(404).json({ message: error.message }); } });

app.get('/api/admin/analytics', auth, adminOnly, async (_req, res) => { const db = await readDb(); const by = (items, key) => Object.entries(items.reduce((acc, item) => { const value = item[key] || 'Unknown'; acc[value] = (acc[value] || 0) + 1; return acc; }, {})).map(([label, value]) => ({ label, value })); const breached = db.issues.filter((item) => new Date(item.sla?.dueAt || 0) < new Date() && !['resolved', 'closed'].includes(item.status)).length; res.json({ issuesByCategory: by(db.issues, 'category'), issuesByStatus: by(db.issues, 'status'), issuesByLocation: by(db.issues, 'location'), itemsByStatus: by(db.lostFound, 'status'), sla: { breached, compliant: db.issues.length - breached, rate: db.issues.length ? Math.round(((db.issues.length - breached) / db.issues.length) * 100) : 100 }, returnRate: db.lostFound.length ? Math.round((db.lostFound.filter((item) => item.status === 'returned').length / db.lostFound.length) * 100) : 0 }); });
app.get('/api/admin/audit', auth, adminOnly, async (req, res) => { const db = await readDb(); const q = String(req.query.q || '').toLowerCase(); const logs = db.auditLogs.filter((item) => !q || JSON.stringify(item).toLowerCase().includes(q)).slice().reverse().slice(0, 250); res.json({ logs }); });
app.get('/api/admin/config', auth, adminOnly, async (_req, res) => { const db = await readDb(); res.json({ departments: db.departments, settings: db.settings, claims: db.claims, jobs: db.jobs, backups: db.backups, roles: db.roles, storageBins: db.storageBins, escalations: db.escalations.filter((item) => item.status === 'active'), feedback: db.feedback, matches: db.matches }); });

app.get('/api/admin/assignments', auth, adminOnly, async (_req, res) => { const db = await readDb(); const unassigned = db.issues.filter((item) => !item.assigneeId && !['resolved', 'closed'].includes(item.status)); const staff = db.users.filter((u) => u.role !== 'admin' && u.role !== 'student'); const byDept = (id) => db.issues.filter((item) => item.departmentId === id && !['resolved', 'closed'].includes(item.status)).length; res.json({ unassigned: unassigned.map((item) => ({ ...item, recommended: recommendAssignee(db, item.departmentId) })), staff: staff.map((u) => ({ user: publicUser(u), workload: workloadOf(db, u.id), department: db.departments.find((d) => d.id === u.departmentId)?.name || 'Unassigned' })), departments: db.departments.map((d) => ({ ...d, open: byDept(d.id) })) }); });
app.post('/api/admin/issues/:id/assign', auth, requirePerm('issues:assign'), async (req, res) => { try { const issue = await mutateDb((db) => { const item = db.issues.find((entry) => entry.id === req.params.id); if (!item) throw new Error('Issue not found.'); if (req.body.departmentId && !db.departments.some((dept) => dept.id === req.body.departmentId)) throw new Error('Department not found.'); item.departmentId = req.body.departmentId || item.departmentId; item.assigneeId = req.body.assigneeId || null; item.status = item.assigneeId ? 'assigned' : item.status; item.updatedAt = now(); item.statusHistory.push({ status: item.status, actorId: req.user.id, at: now(), reason: 'Assignment updated' }); notify(db, item.reporterId, 'Team assignment updated', `${item.id} has been assigned to a campus team.`, 'issue', item.id); addAudit(db, 'issue.assigned', req.user.id, { issueId: item.id, departmentId: item.departmentId, assigneeId: item.assigneeId }); return item; }); res.json({ issue }); } catch (error) { res.status(400).json({ message: error.message }); } });

app.post('/api/admin/matches/:id', auth, requirePerm('matches:review'), async (req, res) => { if (!['accepted', 'rejected'].includes(req.body.status)) return res.status(400).json({ message: 'Invalid match decision.' }); try { const match = await mutateDb((db) => { const item = db.matches.find((entry) => entry.id === req.params.id); if (!item) throw new Error('Match not found.'); item.status = req.body.status; item.reviewedBy = req.user.id; item.reviewedAt = now(); item.reviewNote = String(req.body.reason || '').trim(); addAudit(db, `match.${item.status}`, req.user.id, { matchId: item.id, lostItemId: item.lostItemId, foundItemId: item.foundItemId }); return item; }); res.json({ match }); } catch (error) { res.status(404).json({ message: error.message }); } });

app.post('/api/admin/inventory/:id', auth, requirePerm('inventory:manage'), async (req, res) => { try { const record = await mutateDb((db) => { const item = db.lostFound.find((entry) => entry.id === req.params.id); if (!item || item.kind !== 'found') throw new Error('Found-item record not found.'); if (req.body.storageBin) { item.inventory.storageBin = req.body.storageBin; db.custodyEvents.push({ id: makeId('CST'), itemId: item.id, action: 'moved', from: item.inventory.storageBin, to: req.body.storageBin, actorId: req.user.id, createdAt: now() }); } if (req.body.custodianId) item.inventory.custodianId = req.body.custodianId; item.updatedAt = now(); addAudit(db, 'inventory.moved', req.user.id, { itemId: item.id, storageBin: item.inventory.storageBin }); return item; }); res.json({ record }); } catch (error) { res.status(404).json({ message: error.message }); } });
app.post('/api/admin/storage-bins', auth, requirePerm('inventory:manage'), async (req, res) => { if (!String(req.body.code || '').trim()) return res.status(400).json({ message: 'Bin code is required.' }); const bin = await mutateDb((db) => { const item = { code: req.body.code.trim().toUpperCase(), active: true }; db.storageBins.push(item); addAudit(db, 'inventory.bin_created', req.user.id, { code: item.code }); return item; }); res.status(201).json({ bin }); });
app.post('/api/admin/lost-found/:id/dispose', auth, requirePerm('lostfound:manage'), async (req, res) => { try { const record = await mutateDb((db) => { const item = db.lostFound.find((entry) => entry.id === req.params.id); if (!item) throw new Error('Item record not found.'); item.status = 'closed'; item.disposed = { action: req.body.action || 'donated', reason: String(req.body.reason || '').trim(), by: req.user.id, at: now() }; db.custodyEvents.push({ id: makeId('CST'), itemId: item.id, action: 'disposed', from: item.inventory?.storageBin || 'INTAKE', to: item.disposed.action, actorId: req.user.id, createdAt: now() }); addAudit(db, 'lost_found.disposed', req.user.id, { recordId: item.id, action: item.disposed.action }); return item; }); res.json({ record }); } catch (error) { res.status(404).json({ message: error.message }); } });

app.get('/api/admin/retention', auth, requirePerm('retention:manage'), async (_req, res) => { const db = await readDb(); const days = db.settings.retentionDays || 365; const cutoff = new Date(Date.now() - days * 86400000).toISOString(); const expiring = (arr, statuses) => arr.filter((item) => statuses.includes(item.status) && new Date(item.updatedAt || item.createdAt) < new Date(cutoff)); const issues = expiring(db.issues, ['closed']); const items = expiring(db.lostFound, ['returned', 'closed']); res.json({ retentionDays: days, cutoff, issues, items }); });
app.post('/api/admin/retention/purge', auth, requirePerm('retention:manage'), async (req, res) => { const result = await mutateDb((db) => { const days = db.settings.retentionDays || 365; const cutoff = new Date(Date.now() - days * 86400000).toISOString(); const keep = (arr) => arr.filter((item) => !(['closed'].includes(item.status) && new Date(item.updatedAt || item.createdAt) < new Date(cutoff))); const keepItems = (arr) => arr.filter((item) => !(['returned', 'closed'].includes(item.status) && new Date(item.updatedAt || item.createdAt) < new Date(cutoff))); const beforeIssues = db.issues.length; const beforeItems = db.lostFound.length; db.issues = keep(db.issues); db.lostFound = keepItems(db.lostFound); const removed = { issues: beforeIssues - db.issues.length, items: beforeItems - db.lostFound.length }; addAudit(db, 'retention.purged', req.user.id, { removed }); return removed; }); res.json({ removed: result }); });

app.get('/api/admin/templates', auth, requirePerm('templates:manage'), async (_req, res) => { const db = await readDb(); res.json({ templates: db.settings.templates || {} }); });
app.patch('/api/admin/templates', auth, requirePerm('templates:manage'), async (req, res) => { const templates = await mutateDb((db) => { db.settings.templates = { ...(db.settings.templates || {}), ...req.body.templates }; addAudit(db, 'system.templates_updated', req.user.id, { keys: Object.keys(req.body.templates || {}) }); return db.settings.templates; }); res.json({ templates }); });
app.get('/api/admin/communications/config', auth, requirePerm('templates:manage'), async (_req, res) => { const twAuth = Boolean(process.env.TWILIO_ACCOUNT_SID && (process.env.TWILIO_AUTH_TOKEN || (process.env.TWILIO_API_KEY_SID && process.env.TWILIO_API_KEY_SECRET))); res.json({ providers: { sms: Boolean(twAuth && process.env.TWILIO_SMS_FROM), whatsapp: Boolean(twAuth && process.env.TWILIO_WHATSAPP_FROM), email: Boolean(process.env.SMTP_HOST && process.env.SMTP_FROM), in_app: true } }); });
app.post('/api/admin/communications/send', auth, requirePerm('templates:manage'), async (req, res) => {
  const entityType = req.body.entityType === 'issue' ? 'issue' : req.body.entityType === 'lostFound' ? 'lostFound' : null; const channels = [...new Set(Array.isArray(req.body.channels) ? req.body.channels : [])].filter((channel) => ['in_app', 'email', 'sms', 'whatsapp'].includes(channel));
  if (!entityType || !req.body.entityId || !req.body.templateKey || !channels.length) return res.status(400).json({ message: 'Choose a record, template, and at least one channel.' });
  const db = await readDb(); const entity = entityType === 'issue' ? db.issues.find((item) => item.id === req.body.entityId) : db.lostFound.find((item) => item.id === req.body.entityId); if (!entity) return res.status(404).json({ message: 'The selected record no longer exists.' }); const recipient = db.users.find((item) => item.id === entity.reporterId); if (!recipient) return res.status(400).json({ message: 'This record does not have a contactable reporter.' }); const template = db.settings.templates?.[req.body.templateKey]; if (!template) return res.status(400).json({ message: 'The selected template does not exist.' });
  const department = db.departments.find((item) => item.id === entity.departmentId)?.name || 'DeltaCare team'; const context = { user: { name: recipient.name, email: recipient.email, phone: recipient.phone || '' }, issue: { id: entity.id, name: entity.title || '', status: entity.status || '' }, product: { id: entity.id, name: entity.itemName || '', status: entity.status || '' }, status: req.body.outcome || entity.status, department, location: entity.location || '' }; const body = renderTemplate(template, context); const subject = entityType === 'issue' ? `DeltaCare update: ${entity.title}` : `DeltaCare item update: ${entity.itemName}`; const deliveries = [];
  for (const channel of channels) { if (channel !== 'in_app' && recipient.preferences?.[channel] === false) { deliveries.push({ channel, status: 'opted_out', detail: `${recipient.name} has disabled ${channel} notifications.` }); continue; } if (channel === 'in_app') deliveries.push({ channel, status: 'sent' }); else if (channel === 'email') deliveries.push({ channel, ...(await sendEmailMessage({ to: recipient.email, subject, body })) }); else { const phone = normalizePhone(recipient.phone); deliveries.push(phone ? { channel, ...(await sendTwilioMessage({ channel, to: phone, body })) } : { channel, status: 'unavailable', detail: 'The user does not have a valid phone number.' }); } }
  const outcomeStatus = { issue_fixed: 'resolved', issue_in_progress: 'in_progress', issue_closed: 'closed', lost_match_found: 'possible_match', found_item_logged: 'matching', item_returned: 'returned', item_not_found: 'matching' }[req.body.templateKey]; const communication = await mutateDb((latest) => { const latestEntity = entityType === 'issue' ? latest.issues.find((item) => item.id === entity.id) : latest.lostFound.find((item) => item.id === entity.id); if (outcomeStatus && latestEntity) { latestEntity.status = outcomeStatus; latestEntity.updatedAt = now(); if (entityType === 'issue') { latestEntity.statusHistory = latestEntity.statusHistory || []; latestEntity.statusHistory.push({ status: outcomeStatus, actorId: req.user.id, at: latestEntity.updatedAt, reason: `Notification sent using ${req.body.templateKey}` }); } } if (channels.includes('in_app')) notify(latest, recipient.id, subject, body, entityType, entity.id); const record = { id: makeId('MSG'), entityType, entityId: entity.id, recipientId: recipient.id, templateKey: req.body.templateKey, channels, deliveries, subject, body, sentBy: req.user.id, createdAt: now() }; latest.communications.unshift(record); addAudit(latest, 'communication.sent', req.user.id, { communicationId: record.id, entityType, entityId: entity.id, channels, deliveries: deliveries.map(({ channel, status }) => ({ channel, status })) }); return record; });
  res.status(201).json({ communication, updatedStatus: outcomeStatus || entity.status });
});

app.post('/api/admin/communications/test', auth, requirePerm('templates:manage'), async (req, res) => {
  const channel = req.body.channel; const to = String(req.body.to || '').trim();
  if (!['sms', 'whatsapp', 'email'].includes(channel)) return res.status(400).json({ message: 'Choose sms, whatsapp or email.' });
  if (channel === 'email') { if (!to.includes('@')) return res.status(400).json({ message: 'Enter a valid email address to test.' }); const result = await sendEmailMessage({ to, subject: 'DeltaCare test message', body: 'This is a test message from DeltaCare. Your email channel is working.' }); return res.json({ channel, to, result }); }
  const phone = normalizePhone(to); if (!phone) return res.status(400).json({ message: 'Enter a valid phone number with country code, e.g. +14155551234.' });
  const result = await sendTwilioMessage({ channel, to: phone, body: `This is a test message from DeltaCare. Your ${channel} channel is working.` });
  res.json({ channel, to: phone, result });
});
app.patch('/api/admin/roles/:id', auth, requirePerm('roles:manage'), async (req, res) => { try { const role = await mutateDb((db) => { const item = db.roles.find((entry) => entry.id === req.params.id); if (!item) throw new Error('Role not found.'); if (req.body.permissions) item.permissions = req.body.permissions; if (req.body.name) item.name = req.body.name; addAudit(db, 'role.updated', req.user.id, { roleId: item.id, permissions: item.permissions }); return item; }); res.json({ role }); } catch (error) { res.status(404).json({ message: error.message }); } });
app.post('/api/admin/users/:id/roles', auth, requirePerm('roles:manage'), async (req, res) => { try { const user = await mutateDb((db) => { const item = db.users.find((entry) => entry.id === req.params.id); if (!item) throw new Error('User not found.'); if (Array.isArray(req.body.roleIds)) item.roleIds = req.body.roleIds; addAudit(db, 'user.roles_updated', req.user.id, { targetUserId: item.id, roleIds: item.roleIds }); return publicUser(item); }); res.json({ user }); } catch (error) { res.status(404).json({ message: error.message }); } });

app.post('/api/admin/issues/:id/feedback', auth, adminOnly, async (req, res) => { try { const feedback = await mutateDb((db) => { const item = db.issues.find((entry) => entry.id === req.params.id); if (!item) throw new Error('Issue not found.'); const record = { id: makeId('FB'), issueId: item.id, aiSuggestion: item.ai || {}, finalCategory: req.body.finalCategory || item.category, finalPriority: req.body.finalPriority || item.priority, note: String(req.body.note || ''), by: req.user.id, createdAt: now() }; db.feedback.push(record); addAudit(db, 'ai.feedback_recorded', req.user.id, { issueId: item.id }); return record; }); res.status(201).json({ feedback }); } catch (error) { res.status(404).json({ message: error.message }); } });

app.post('/api/admin/issues/:id/moderation', auth, requirePerm('issues:update'), async (req, res) => { try { const issue = await mutateDb((db) => { const item = db.issues.find((entry) => entry.id === req.params.id); if (!item) throw new Error('Issue not found.'); item.moderation = { status: req.body.status === 'flag' ? 'flagged' : 'normal', reason: String(req.body.reason || '').trim(), by: req.user.id, at: now() }; db.moderationReports.push({ id: makeId('MOD'), issueId: item.id, status: item.moderation.status, reason: item.moderation.reason, by: req.user.id, createdAt: now() }); addAudit(db, 'issue.moderation_updated', req.user.id, { issueId: item.id, status: item.moderation.status }); return item; }); res.json({ issue }); } catch (error) { res.status(404).json({ message: error.message }); } });
app.get('/api/admin/escalations', auth, requirePerm('escalation:manage'), async (_req, res) => { const db = await readDb(); evaluateEscalations(db); res.json({ escalations: db.escalations, rules: db.settings.escalationRules || [] }); });
app.post('/api/admin/escalations', auth, requirePerm('escalation:manage'), async (req, res) => { if (!req.body.name || !req.body.priority || !req.body.afterMinutes) return res.status(400).json({ message: 'Rule name, priority, and time are required.' }); const rule = await mutateDb((db) => { const item = { id: makeId('ESC-R'), name: req.body.name, priority: req.body.priority, afterMinutes: Number(req.body.afterMinutes), action: req.body.action || 'notify_manager', enabled: true }; db.settings.escalationRules = db.settings.escalationRules || []; db.settings.escalationRules.push(item); addAudit(db, 'escalation.rule_created', req.user.id, { ruleId: item.id }); return item; }); res.status(201).json({ rule }); });
app.patch('/api/admin/escalations/:id', auth, requirePerm('escalation:manage'), async (req, res) => { const rule = await mutateDb((db) => { const item = (db.settings.escalationRules || []).find((entry) => entry.id === req.params.id); if (!item) throw new Error('Rule not found.'); Object.assign(item, req.body); return item; }); res.json({ rule }); });
app.patch('/api/admin/config', auth, adminOnly, async (req, res) => { const settings = await mutateDb((db) => { db.settings = { ...db.settings, ...req.body, slaHours: { ...db.settings.slaHours, ...(req.body.slaHours || {}) } }; addAudit(db, 'system.config_updated', req.user.id, { keys: Object.keys(req.body) }); return db.settings; }); res.json({ settings }); });
app.post('/api/admin/departments', auth, adminOnly, async (req, res) => { if (!String(req.body.name || '').trim()) return res.status(400).json({ message: 'Department name is required.' }); const department = await mutateDb((db) => { const item = { id: makeId('DEPT'), name: req.body.name.trim(), categories: Array.isArray(req.body.categories) ? req.body.categories : [], active: true }; db.departments.push(item); addAudit(db, 'department.created', req.user.id, { departmentId: item.id }); return item; }); res.status(201).json({ department }); });
app.patch('/api/admin/users/:id', auth, requirePerm('users:manage'), async (req, res) => { try { const user = await mutateDb((db) => { const item = db.users.find((entry) => entry.id === req.params.id); if (!item || item.id === req.user.id) throw new Error('Your own access must be changed by another administrator.'); if (req.body.role && ['student', 'staff', 'admin', 'super_admin'].includes(req.body.role)) { if (['admin', 'super_admin'].includes(item.role) && !['admin', 'super_admin'].includes(req.body.role) && db.users.filter((entry) => ['admin', 'super_admin'].includes(entry.role) && !entry.suspended).length <= 1) throw new Error('DeltaCare must keep at least one active administrator.'); item.role = req.body.role; item.roleIds = item.role === 'super_admin' ? ['ROLE-SUPER'] : item.role === 'admin' ? ['ROLE-ADMIN'] : item.role === 'staff' ? ['ROLE-TECH'] : ['ROLE-USER']; } if (typeof req.body.suspended === 'boolean') { if (['admin', 'super_admin'].includes(item.role) && req.body.suspended && db.users.filter((entry) => ['admin', 'super_admin'].includes(entry.role) && !entry.suspended).length <= 1) throw new Error('The final active administrator cannot be suspended.'); item.suspended = req.body.suspended; } addAudit(db, 'user.access_updated', req.user.id, { targetUserId: item.id, role: item.role, suspended: item.suspended }); return publicUser(item); }); res.json({ user }); } catch (error) { res.status(400).json({ message: error.message }); } });
app.post('/api/admin/users', auth, requirePerm('users:manage'), async (req, res) => {
  const name = String(req.body.name || '').trim(); const email = String(req.body.email || '').trim().toLowerCase(); const campusId = String(req.body.campusId || '').trim(); const password = String(req.body.password || '');
  if (!name || !email || !campusId || password.length < 8) return res.status(400).json({ message: 'Name, email, campus ID, and a password of at least 8 characters are required.' });
  try { const passwordHash = await bcrypt.hash(password, 12); const user = await mutateDb((db) => { if (db.users.some((item) => item.email === email || item.campusId === campusId)) throw new Error('That email or campus ID is already registered.'); const item = { id: makeId('ADM'), name, email, campusId, role: 'admin', roleIds: ['ROLE-ADMIN'], passwordHash, verified: true, suspended: false, preferences: { email: true, sms: false, whatsapp: false, language: 'en', locationConsent: false }, createdAt: now() }; db.users.push(item); addAudit(db, 'admin.created', req.user.id, { targetUserId: item.id }); return publicUser(item); }); res.status(201).json({ user }); } catch (error) { res.status(400).json({ message: error.message }); }
});

app.delete('/api/admin/issues/:id', auth, requirePerm('issues:update'), async (req, res) => { try { const removed = await mutateDb((db) => { const index = db.issues.findIndex((item) => item.id === req.params.id); if (index < 0) throw new Error('Issue not found.'); const [item] = db.issues.splice(index, 1); db.comments = db.comments.filter((entry) => entry.issueId !== item.id); db.notifications = db.notifications.filter((entry) => !(entry.entityType === 'issue' && entry.entityId === item.id)); db.escalations = db.escalations.filter((entry) => entry.issueId !== item.id); db.feedback = db.feedback.filter((entry) => entry.issueId !== item.id); db.moderationReports = db.moderationReports.filter((entry) => entry.issueId !== item.id); db.issues.forEach((entry) => { if (entry.parentIssueId === item.id) entry.parentIssueId = null; }); addAudit(db, 'issue.deleted', req.user.id, { issueId: item.id, title: item.title }); return item.id; }); res.json({ removed }); } catch (error) { res.status(404).json({ message: error.message }); } });
app.delete('/api/admin/lost-found/:id', auth, requirePerm('lostfound:manage'), async (req, res) => { try { const removed = await mutateDb((db) => { const index = db.lostFound.findIndex((item) => item.id === req.params.id); if (index < 0) throw new Error('Lost-and-found record not found.'); const [item] = db.lostFound.splice(index, 1); db.matches = db.matches.filter((entry) => ![entry.sourceItemId, entry.candidateItemId, entry.lostItemId, entry.foundItemId].includes(item.id)); db.claims = db.claims.filter((entry) => entry.itemId !== item.id && entry.lostFoundId !== item.id); db.custodyEvents = db.custodyEvents.filter((entry) => entry.itemId !== item.id); db.notifications = db.notifications.filter((entry) => !(entry.entityType === 'lostFound' && entry.entityId === item.id)); addAudit(db, 'lost_found.deleted', req.user.id, { recordId: item.id, itemName: item.itemName }); return item.id; }); res.json({ removed }); } catch (error) { res.status(404).json({ message: error.message }); } });

app.post('/api/admin/demo-data', auth, requirePerm('data:manage'), async (req, res) => {
  const demoPasswordHash = await bcrypt.hash('Demo@12345', 10);
  const result = await mutateDb((db) => {
    const batch = 'DELTACARE-DEMO-1'; if (db.issues.some((item) => item.demoBatch === batch)) return { added: false, issues: 0, items: 0, users: 0 };
    const createdAt = now(); const hoursAgo = (hours) => new Date(Date.now() - hours * 3600000).toISOString();
    const demoUsers = [
      { id: 'DEMO-USR-AANYA', name: 'Aanya Kapoor', email: 'aanya.demo@deltacare.local', campusId: 'DEMO-STU-101', role: 'student', roleIds: ['ROLE-USER'] },
      { id: 'DEMO-USR-ROHAN', name: 'Rohan Mehta', email: 'rohan.demo@deltacare.local', campusId: 'DEMO-TECH-201', role: 'staff', roleIds: ['ROLE-TECH'], departmentId: 'DEPT-IT' },
      { id: 'DEMO-USR-MAYA', name: 'Maya Singh', email: 'maya.demo@deltacare.local', campusId: 'DEMO-STAFF-301', role: 'staff', roleIds: ['ROLE-LF'] },
    ].filter((user) => !db.users.some((item) => item.id === user.id)).map((user) => ({ ...user, passwordHash: demoPasswordHash, verified: true, suspended: false, demoBatch: batch, preferences: { email: true, sms: false, whatsapp: false, language: 'en', locationConsent: false }, createdAt }));
    db.users.push(...demoUsers);
    const issueSpecs = [
      ['DEMO-ISS-001', 'Exposed wire near laboratory entrance', 'A damaged cable is sparking beside the physics lab door.', 'Electrical', 'Science Block · Ground floor', 'critical', 'in_progress', 'DEPT-ELEC', 5],
      ['DEMO-ISS-002', 'Library Wi-Fi drops frequently', 'Students cannot stay connected in the east reading wing.', 'IT & network', 'Central Library · East wing', 'high', 'assigned', 'DEPT-IT', 14],
      ['DEMO-ISS-003', 'Water leak in washroom', 'A tap is leaking continuously and the floor is becoming slippery.', 'Plumbing', 'Hostel B · Level 2', 'high', 'triaged', 'DEPT-MAINT', 9],
      ['DEMO-ISS-004', 'Broken pathway light', 'The pathway is dark after sunset near the south gate.', 'Electrical', 'South Gate pathway', 'medium', 'submitted', 'DEPT-ELEC', 28],
      ['DEMO-ISS-005', 'Projector image flickering', 'The classroom projector flickers during lectures.', 'IT & network', 'Academic Block C · Room 204', 'medium', 'resolved', 'DEPT-IT', 48],
      ['DEMO-ISS-006', 'Overflowing recycling station', 'The recycling bins require collection.', 'Cleanliness', 'Student Centre · Cafeteria', 'low', 'closed', 'DEPT-MAINT', 72],
    ];
    const issues = issueSpecs.map(([id, title, description, category, location, priority, status, departmentId, age]) => { const at = hoursAgo(age); return { id, version: 1, reporterId: 'DEMO-USR-AANYA', anonymous: false, title, description, category, location, coordinates: null, attachments: [], priority, impact: priority === 'critical' ? 'high' : 'medium', urgency: ['critical', 'high'].includes(priority) ? 'high' : 'medium', status, departmentId, assigneeId: departmentId === 'DEPT-IT' ? 'DEMO-USR-ROHAN' : null, ai: { category, priority, matrixPriority: priority, confidence: .89, factors: [`Matched ${category.toLowerCase()} keywords`], safetyRuleApplied: priority === 'critical' }, duplicateCandidates: [], parentIssueId: null, sla: { policy: `${priority} priority`, startedAt: at, dueAt: businessDue(db, at, db.settings.slaHours[priority] || 24), breached: false, paused: false }, statusHistory: [{ status: 'submitted', actorId: 'DEMO-USR-AANYA', at }, ...(status !== 'submitted' ? [{ status, actorId: req.user.id, at: hoursAgo(Math.max(1, age - 2)), reason: 'Demo workflow update' }] : [])], feedback: status === 'closed' ? { rating: 5, comment: 'Handled quickly', createdAt } : null, demoBatch: batch, createdAt: at, updatedAt: hoursAgo(Math.max(0, age - 2)) }; });
    db.issues.unshift(...issues);
    const itemSpecs = [
      ['DEMO-LST-001', 'lost', 'Blue insulated water bottle', 'Blue metal bottle with a mountain sticker', 'Personal item', 'Central Library', 'blue', 'HydroPeak', 'matching', 18],
      ['DEMO-FND-001', 'found', 'Blue metal water bottle', 'Blue bottle with outdoor sticker found under desk', 'Personal item', 'Central Library', 'blue', 'HydroPeak', 'possible_match', 16],
      ['DEMO-LST-002', 'lost', 'Black wireless earbuds', 'Black earbuds in a square charging case', 'Electronics', 'Student Centre', 'black', 'SoundBeat', 'claim_review', 30],
      ['DEMO-FND-002', 'found', 'Wireless earbuds case', 'Black charging case handed to security desk', 'Electronics', 'Student Centre', 'black', 'SoundBeat', 'matching', 27],
      ['DEMO-FND-003', 'found', 'Student identity card', 'University ID card secured by campus safety', 'ID, card or wallet', 'North Gate', 'white', 'Delta University', 'matching', 4],
    ];
    const items = itemSpecs.map(([id, kind, itemName, description, category, location, color, brand, status, age], index) => { const at = hoursAgo(age); return { id, version: 1, reporterId: index % 2 ? 'DEMO-USR-MAYA' : 'DEMO-USR-AANYA', kind, itemName, description, category, color, brand, privateAttributes: 'Demo verification detail', publicAttributes: { color, brand }, attachments: [], coordinates: null, location, eventDate: at.slice(0, 10), status, sensitive: category === 'ID, card or wallet', inventory: kind === 'found' ? { tag: `DEMO-TAG-${index + 1}`, storageBin: category === 'Electronics' ? 'ELECTRONICS-A1' : category === 'ID, card or wallet' ? 'SECURE-B07' : 'PERSONAL-B2', custodianId: 'DEMO-USR-MAYA', checkedInAt: at } : null, demoBatch: batch, createdAt: at, updatedAt: at }; });
    db.lostFound.unshift(...items);
    db.matches.push({ id: 'DEMO-MCH-001', sourceItemId: 'DEMO-FND-001', candidateItemId: 'DEMO-LST-001', score: 92, components: { text: 94, image: 0, ocr: 0, attributes: 100, location: 100, time: 96 }, explanation: ['Strong description match', 'Same category and location', 'Plausible reporting time'], status: 'suggested', demoBatch: batch, createdAt }, { id: 'DEMO-MCH-002', sourceItemId: 'DEMO-FND-002', candidateItemId: 'DEMO-LST-002', score: 87, components: { text: 91, image: 0, ocr: 0, attributes: 100, location: 100, time: 90 }, explanation: ['Matching brand and colour', 'Same campus location'], status: 'suggested', demoBatch: batch, createdAt });
    addAudit(db, 'demo_data.loaded', req.user.id, { issues: issues.length, items: items.length, users: demoUsers.length });
    return { added: true, issues: issues.length, items: items.length, users: demoUsers.length, demoPassword: 'Demo@12345' };
  });
  res.status(result.added ? 201 : 200).json(result);
});
app.get('/api/admin/export', auth, adminOnly, async (_req, res) => { const db = await readDb(); res.setHeader('Content-Disposition', `attachment; filename="deltacare-export-${new Date().toISOString().slice(0, 10)}.json"`); res.json({ exportedAt: now(), schemaVersion: 2, data: { users: db.users.map(publicUser), issues: db.issues, lostFound: db.lostFound, departments: db.departments, claims: db.claims, auditLogs: db.auditLogs } }); });
app.post('/api/admin/import', auth, adminOnly, async (req, res) => { const incoming = req.body?.data; if (!incoming || !Array.isArray(incoming.issues) || !Array.isArray(incoming.lostFound)) return res.status(400).json({ message: 'Import must contain data.issues and data.lostFound arrays.' }); const result = await mutateDb((db) => { let issues = 0; let items = 0; incoming.issues.forEach((item) => { if (item.id && !db.issues.some((existing) => existing.id === item.id)) { db.issues.push(item); issues++; } }); incoming.lostFound.forEach((item) => { if (item.id && !db.lostFound.some((existing) => existing.id === item.id)) { db.lostFound.push(item); items++; } }); addAudit(db, 'data.imported', req.user.id, { issues, items }); return { issues, items }; }); res.json({ imported: result }); });
app.post('/api/admin/backups', auth, adminOnly, async (req, res) => { const db = await readDb(); await fs.mkdir(path.join(root, 'backups'), { recursive: true }); const id = `BKP-${new Date().toISOString().replace(/[:.]/g, '-')}`; const filename = `${id}.json`; const snapshot = { ...db, sessions: [], passwordResets: [], backups: [] }; await fs.writeFile(path.join(root, 'backups', filename), JSON.stringify(snapshot, null, 2)); const backup = await mutateDb((latest) => { const item = { id, filename, createdBy: req.user.id, size: JSON.stringify(snapshot).length, createdAt: now() }; latest.backups.unshift(item); addAudit(latest, 'backup.created', req.user.id, { backupId: id }); return item; }); res.status(201).json({ backup }); });
app.get('/api/admin/health', auth, adminOnly, async (_req, res) => { const db = await readDb(); res.json({ status: 'healthy', checkedAt: now(), components: [{ name: 'JSON database', status: 'operational', detail: `${db.users.length} users, ${db.issues.length} issues` }, { name: 'AI suggestion engine', status: 'operational', detail: 'Local heuristic prototype' }, { name: 'Notification queue', status: 'operational', detail: `${db.notifications.length} in-app notifications` }, { name: 'Email / WhatsApp / SMS', status: 'not_configured', detail: 'Provider credentials required' }], jobs: db.jobs }); });
app.post('/api/admin/issues/bulk', auth, adminOnly, async (req, res) => { const ids = Array.isArray(req.body.ids) ? req.body.ids : []; if (!ids.length || ids.length > 100) return res.status(400).json({ message: 'Choose between 1 and 100 issues.' }); const allowed = ['triaged', 'assigned', 'in_progress', 'resolved', 'closed']; if (req.body.status && !allowed.includes(req.body.status)) return res.status(400).json({ message: 'Invalid bulk status.' }); const updated = await mutateDb((db) => { const items = db.issues.filter((item) => ids.includes(item.id)); items.forEach((item) => { if (req.body.status) item.status = req.body.status; if (req.body.departmentId) item.departmentId = req.body.departmentId; item.version = (item.version || 1) + 1; item.updatedAt = now(); item.statusHistory.push({ status: item.status, actorId: req.user.id, at: item.updatedAt, reason: 'Bulk operation' }); }); addAudit(db, 'issues.bulk_updated', req.user.id, { ids, status: req.body.status, departmentId: req.body.departmentId }); return items.length; }); res.json({ updated }); });
app.get('/api/scan/:tag', auth, async (req, res) => { const db = await readDb(); const item = db.lostFound.find((entry) => entry.inventory?.tag === req.params.tag); if (item) return res.json({ type: 'lostFound', id: item.id, title: item.itemName, status: item.status }); const issue = db.issues.find((entry) => entry.assetTag === req.params.tag); if (issue) return res.json({ type: 'issue', id: issue.id, title: issue.title, status: issue.status }); res.status(404).json({ message: 'No campus record matches that tag.' }); });
app.get('/api/saved-views', auth, async (req, res) => { const db = await readDb(); res.json({ views: db.savedViews.filter((item) => item.userId === req.user.id) }); });
app.post('/api/saved-views', auth, async (req, res) => { if (!String(req.body.name || '').trim()) return res.status(400).json({ message: 'View name is required.' }); const view = await mutateDb((db) => { const item = { id: makeId('VIEW'), userId: req.user.id, name: req.body.name.trim(), filters: req.body.filters || {}, createdAt: now() }; db.savedViews.push(item); return item; }); res.status(201).json({ view }); });
app.post('/api/ai/classify-issue', auth, (req, res) => res.json({ suggestion: classify(`${req.body.title || ''} ${req.body.description || ''}`, req.body.category, req.body.priority) }));
app.post('/api/admin/jobs/:id/retry', auth, adminOnly, async (req, res) => { try { const job = await mutateDb((db) => { const item = db.jobs.find((entry) => entry.id === req.params.id); if (!item) throw new Error('Job not found.'); item.status = 'queued'; item.retryCount = (item.retryCount || 0) + 1; item.updatedAt = now(); addAudit(db, 'job.retried', req.user.id, { jobId: item.id }); return item; }); res.json({ job }); } catch (error) { res.status(404).json({ message: error.message }); } });
app.post('/api/admin/backups/:id/restore', auth, adminOnly, async (req, res) => { const current = await readDb(); const backup = current.backups.find((item) => item.id === req.params.id); if (!backup || path.basename(backup.filename) !== backup.filename) return res.status(404).json({ message: 'Backup not found.' }); try { const snapshot = JSON.parse(await fs.readFile(path.join(root, 'backups', backup.filename), 'utf8')); const preRestore = path.join(root, 'backups', `PRE-RESTORE-${Date.now()}.json`); await fs.writeFile(preRestore, JSON.stringify(current, null, 2)); await writeQueue; const temp = `${dbPath}.tmp`; await fs.writeFile(temp, JSON.stringify(snapshot, null, 2)); await fs.rename(temp, dbPath); res.json({ message: 'Backup restored. Existing sessions were invalidated.' }); } catch { res.status(400).json({ message: 'Backup validation or restore failed.' }); } });
app.post('/api/webhooks/:provider', rateLimit(60000, 120), async (req, res) => { const expected = process.env.WEBHOOK_SECRET; if (!expected || req.headers['x-deltacare-signature'] !== expected) return res.status(401).json({ message: 'Webhook signature verification failed.' }); const provider = req.params.provider; if (!['whatsapp', 'sms', 'email'].includes(provider)) return res.status(404).json({ message: 'Unknown provider.' }); await mutateDb((db) => { db.jobs.push({ id: makeId('JOB'), type: `${provider}_webhook`, payload: req.body, status: 'queued', retryCount: 0, createdAt: now() }); addAudit(db, `webhook.${provider}_received`, 'SYSTEM'); }); res.status(202).json({ accepted: true }); });

app.use('/api/v1', (req, res) => res.redirect(307, `/api${req.url}`));

const ensureAdmin = async () => {
  await mutateDb(async (db) => {
    if (db.users.some((user) => user.role === 'admin')) return;
    const admin = {
      id: makeId('ADM'),
      name: 'DeltaCare Admin',
      email: process.env.ADMIN_EMAIL || 'admin@deltacare.local',
      campusId: 'ADMIN-001',
      role: 'admin',
      passwordHash: await bcrypt.hash(process.env.ADMIN_PASSWORD || 'DeltaCare@00000', 12),
      verified: true,
      createdAt: new Date().toISOString(),
    };
    db.users.push(admin);
    addAudit(db, 'admin.seeded', admin.id);
  });
};

if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(root, 'dist')));
  app.use((req, res, next) => {
    if (req.method !== 'GET' || req.path.startsWith('/api/')) return next();
    res.sendFile(path.join(root, 'dist', 'index.html'));
  });
}

await ensureAdmin();
const localIPs = () => { const nets = os.networkInterfaces(); const ips = new Set(); for (const name of Object.keys(nets)) for (const net of nets[name] || []) if (net.family === 'IPv4' && !net.internal) ips.add(net.address); return [...ips]; };
app.listen(PORT, () => {
  const ports = { 'Desktop app': 5173, 'Mobile PWA': 8080, 'API': PORT };
  const ips = localIPs();
  console.log('');
  console.log('  =========================================================');
  console.log('   DeltaCare  -  Campus Care & Lost & Found');
  console.log('  =========================================================');
  for (const [name, port] of Object.entries(ports)) {
    const kind = port === PORT ? 'API' : port === 8080 ? 'Mobile PWA' : 'Desktop app';
    console.log(`   [${kind}]  http://localhost:${port}`);
    for (const ip of ips) console.log(`            http://${ip}:${port}   (${name.toLowerCase()} on LAN)`);
  }
  if (!ips.length) console.log('   (no LAN interfaces detected - share the localhost URL above)');
  console.log('');
});
