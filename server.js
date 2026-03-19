const path = require('path');
const fs = require('fs');
const express = require('express');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const {
  computeRisk,
  getClientIp,
  getHeader,
  randomId,
  sha256,
  verifySignedValue,
  setSignedCookie,
  clearCookie,
  trackRequest,
  blockIpLocal,
  getLocalBlock,
  geoblock,
  buildKey,
  REQUEST_REPEAT_LIMIT,
  REQUEST_BLOCK_MS
} = require('./lib/security');
const { readDb, updateDb } = require('./lib/store');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const APP_URL = process.env.APP_URL || `http://localhost:${PORT}`;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@example.com';

app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));
app.use(express.json({ limit: '128kb' }));
app.use(express.urlencoded({ extended: false, limit: '128kb' }));
app.use(cookieParser());

function jsonError(res, status, message, extra = {}) {
  return res.status(status).json({ ok: false, message, ...extra });
}

function parseSession(req) {
  return verifySignedValue(req.cookies.aso_session || '');
}

function parseAdminSession(req) {
  return verifySignedValue(req.cookies.aso_admin || '');
}

function getUserFromSession(req) {
  const session = parseSession(req);
  if (!session?.email) return null;
  const db = readDb();
  const user = db.users.find(u => u.email === session.email);
  return user || null;
}

function requireUser(req, res, next) {
  const user = getUserFromSession(req);
  if (!user) return jsonError(res, 401, 'Não autenticado.');
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  const admin = parseAdminSession(req);
  if (!admin?.email) return jsonError(res, 401, 'Admin não autenticado.');
  if (admin.email !== ADMIN_EMAIL) return jsonError(res, 403, 'Acesso negado.');
  req.admin = admin;
  next();
}

function sanitizeText(input, max = 200) {
  return String(input || '')
    .trim()
    .replace(/[\u0000-\u001f<>]/g, '')
    .slice(0, max);
}

function validateEmail(email) {
  const v = String(email || '').trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) throw new Error('E-mail inválido.');
  return v;
}

function validatePassword(password) {
  const v = String(password || '');
  if (v.length < 8 || v.length > 128) throw new Error('Senha inválida.');
  return v;
}

function maskIp(ip) {
  const p = String(ip || '').split('.');
  if (p.length === 4) return `${p[0]}.${p[1]}.${p[2]}.***`;
  return ip;
}

function registerEvent(payload) {
  updateDb(db => {
    db.events.unshift({ id: randomId('evt', 8), createdAt: Date.now(), ...payload });
    db.events = db.events.slice(0, 500);
    return db;
  });
}

function registerBlockedIp(payload) {
  updateDb(db => {
    db.blockedIps.unshift({ id: randomId('blk', 8), createdAt: Date.now(), ...payload });
    db.blockedIps = db.blockedIps.filter(item => item.until > Date.now()).slice(0, 200);
    return db;
  });
}

app.use((req, res, next) => {
  const ip = getClientIp(req);
  const route = req.path || '/';

  const netBlock = geoblock(req);
  if (netBlock.blocked) {
    registerEvent({
      email: '',
      ip,
      ipMasked: maskIp(ip),
      route,
      decision: 'block',
      score: 0.05,
      reason: `network-block:${netBlock.reason}`,
      keyId: ''
    });
    return jsonError(res, 403, 'Origem bloqueada.', { reason: netBlock.reason });
  }

  const local = getLocalBlock(ip);
  if (local) {
    registerEvent({
      email: '',
      ip,
      ipMasked: maskIp(ip),
      route,
      decision: 'block',
      score: 0.05,
      reason: `local-block:${local.reason}`,
      keyId: ''
    });
    return jsonError(res, 429, 'IP bloqueado temporariamente.', {
      retryAfterSeconds: Math.max(1, Math.floor((local.until - Date.now()) / 1000))
    });
  }

  const repeatCount = trackRequest(ip, route);
  if (repeatCount >= REQUEST_REPEAT_LIMIT) {
    blockIpLocal(ip, 'repeat-pattern');
    registerBlockedIp({
      ip,
      ipMasked: maskIp(ip),
      until: Date.now() + REQUEST_BLOCK_MS,
      reason: 'Requisições repetidas'
    });
    registerEvent({
      email: '',
      ip,
      ipMasked: maskIp(ip),
      route,
      decision: 'block',
      score: 0.04,
      reason: 'repeat-pattern',
      keyId: ''
    });
    return jsonError(res, 429, 'Padrão repetitivo detectado. IP bloqueado por alguns minutos.');
  }

  const risk = computeRisk(req);
  req.risk = risk;
  req.clientIp = ip;

  if (risk.decision === 'block') {
    blockIpLocal(ip, risk.flags.join(',') || 'payload-risk');
    registerBlockedIp({
      ip,
      ipMasked: maskIp(ip),
      until: Date.now() + REQUEST_BLOCK_MS,
      reason: `Sinal crítico: ${risk.flags.join(',') || 'payload-risk'}`
    });
    registerEvent({
      email: '',
      ip,
      ipMasked: maskIp(ip),
      route,
      decision: 'block',
      score: Math.max(0.01, 1 - (risk.score / 10)),
      reason: risk.flags.join(','),
      keyId: ''
    });
    return jsonError(res, 403, 'Requisição bloqueada por política de segurança.');
  }

  next();
});

app.use(express.static(path.join(__dirname, 'public'), {
  extensions: ['html']
}));

app.get('/asopartedeadm', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'asopartedeadm.html'));
});

app.get('/api/health', (req, res) => {
  res.json({ ok: true, app: 'asoprotection-platform', now: Date.now() });
});

app.get('/api/me', (req, res) => {
  const user = getUserFromSession(req);
  if (!user) return res.json({ ok: false });
  res.json({
    ok: true,
    user: {
      email: user.email,
      trialEndsAt: user.trialEndsAt,
      plan: user.plan
    }
  });
});

app.get('/api/admin/me', (req, res) => {
  const admin = parseAdminSession(req);
  if (!admin) return res.json({ ok: false });
  res.json({ ok: true, admin: { email: admin.email } });
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const email = validateEmail(req.body.email);
    const password = validatePassword(req.body.password);

    const db = readDb();
    if (db.users.some(u => u.email === email)) {
      return jsonError(res, 409, 'E-mail já cadastrado.');
    }

    const hash = await bcrypt.hash(password, 12);
    const user = {
      id: randomId('usr', 8),
      email,
      passwordHash: hash,
      createdAt: Date.now(),
      trialEndsAt: Date.now() + 10 * 24 * 60 * 60 * 1000,
      plan: 'trial'
    };

    updateDb(db2 => {
      db2.users.push(user);
      db2.adminAudit.unshift({
        id: randomId('audit', 8),
        createdAt: Date.now(),
        type: 'register',
        email
      });
      db2.adminAudit = db2.adminAudit.slice(0, 300);
      return db2;
    });

    setSignedCookie(res, 'aso_session', { email }, 7 * 24 * 60 * 60 * 1000);

    registerEvent({
      email,
      ip: req.clientIp,
      ipMasked: maskIp(req.clientIp),
      route: '/api/auth/register',
      decision: 'allow',
      score: 0.88,
      reason: 'register-ok',
      keyId: ''
    });

    res.json({
      ok: true,
      user: { email, trialEndsAt: user.trialEndsAt, plan: user.plan }
    });
  } catch (err) {
    jsonError(res, 400, err.message || 'Falha ao criar conta.');
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const email = validateEmail(req.body.email);
    const password = validatePassword(req.body.password);

    const db = readDb();
    const user = db.users.find(u => u.email === email);
    if (!user) return jsonError(res, 401, 'Credenciais inválidas.');

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return jsonError(res, 401, 'Credenciais inválidas.');

    setSignedCookie(res, 'aso_session', { email }, 7 * 24 * 60 * 60 * 1000);

    registerEvent({
      email,
      ip: req.clientIp,
      ipMasked: maskIp(req.clientIp),
      route: '/api/auth/login',
      decision: 'allow',
      score: 0.9,
      reason: 'login-ok',
      keyId: ''
    });

    res.json({
      ok: true,
      user: { email, trialEndsAt: user.trialEndsAt, plan: user.plan }
    });
  } catch (err) {
    jsonError(res, 400, err.message || 'Falha ao entrar.');
  }
});

app.post('/api/auth/logout', (req, res) => {
  clearCookie(res, 'aso_session');
  res.json({ ok: true });
});

app.post('/api/admin/login', (req, res) => {
  const password = String(req.body.password || '');
  if (!ADMIN_PASSWORD) return jsonError(res, 500, 'ADMIN_PASSWORD não configurada no host.');
  if (password !== ADMIN_PASSWORD) return jsonError(res, 403, 'Acesso negado.');

  setSignedCookie(res, 'aso_admin', { email: ADMIN_EMAIL }, 12 * 60 * 60 * 1000);

  updateDb(db => {
    db.adminAudit.unshift({
      id: randomId('audit', 8),
      createdAt: Date.now(),
      type: 'admin-login',
      email: ADMIN_EMAIL
    });
    db.adminAudit = db.adminAudit.slice(0, 300);
    return db;
  });

  res.json({ ok: true, admin: { email: ADMIN_EMAIL } });
});

app.post('/api/admin/logout', (req, res) => {
  clearCookie(res, 'aso_admin');
  res.json({ ok: true });
});

app.get('/api/dashboard', requireUser, (req, res) => {
  const db = readDb();
  const keys = db.keys.filter(k => k.email === req.user.email);
  const keyIds = new Set(keys.map(k => k.id));
  const events = db.events.filter(e => !e.keyId || keyIds.has(e.keyId)).slice(0, 100);
  const blocked = db.blockedIps.filter(b => b.until > Date.now()).slice(0, 50);

  const requestCount = keys.reduce((a, k) => a + (k.requestCount || 0), 0);
  const blockedCount = keys.reduce((a, k) => a + (k.blockedCount || 0), 0);
  const avgScore = events.length
    ? events.reduce((a, e) => a + Number(e.score || 0.5), 0) / events.length
    : 0.5;

  res.json({
    ok: true,
    metrics: {
      requestCount,
      blockedCount,
      avgScore: Number(avgScore.toFixed(2)),
      keyCount: keys.length
    },
    keys: keys.map(k => ({
      id: k.id,
      project: k.project,
      domain: k.domain,
      siteKey: k.siteKey,
      secretKeyPreview: k.secretKey.slice(0, 10) + '…',
      requestCount: k.requestCount || 0,
      blockedCount: k.blockedCount || 0,
      plan: k.plan || 'pro'
    })),
    events,
    blocked
  });
});

app.post('/api/keys/create', requireUser, (req, res) => {
  const project = sanitizeText(req.body.project, 80);
  const domain = sanitizeText(req.body.domain, 120);
  const captchaToken = String(req.body.captchaToken || '');

  if (!project || !domain) return jsonError(res, 400, 'Projeto e domínio são obrigatórios.');
  const captcha = verifySignedValue(captchaToken);
  if (!captcha || captcha.type !== 'captcha' || captcha.email !== req.user.email) {
    return jsonError(res, 403, 'Verificação CAPTCHA inválida ou ausente.');
  }

  const siteKey = buildKey('pk_live', 18);
  const secretKey = buildKey('sk_live', 36);
  const keyRecord = {
    id: randomId('key', 8),
    email: req.user.email,
    project,
    domain,
    siteKey,
    secretKey,
    secretHash: sha256(secretKey),
    createdAt: Date.now(),
    requestCount: 0,
    blockedCount: 0,
    plan: Date.now() < req.user.trialEndsAt ? 'pro-trial' : 'free'
  };

  updateDb(db => {
    db.keys.unshift(keyRecord);
    db.adminAudit.unshift({
      id: randomId('audit', 8),
      createdAt: Date.now(),
      type: 'key-create',
      email: req.user.email,
      project,
      domain
    });
    db.adminAudit = db.adminAudit.slice(0, 300);
    return db;
  });

  registerEvent({
    email: req.user.email,
    ip: req.clientIp,
    ipMasked: maskIp(req.clientIp),
    route: '/api/keys/create',
    decision: 'allow',
    score: 0.91,
    reason: 'key-create',
    keyId: keyRecord.id
  });

  res.json({
    ok: true,
    key: {
      id: keyRecord.id,
      project,
      domain,
      siteKey,
      secretKey
    }
  });
});

app.post('/api/admin/keys/create', requireAdmin, (req, res) => {
  const email = validateEmail(req.body.email || '');
  const project = sanitizeText(req.body.project, 80);
  const domain = sanitizeText(req.body.domain, 120);
  if (!project || !domain) return jsonError(res, 400, 'Projeto e domínio são obrigatórios.');

  const db = readDb();
  const user = db.users.find(u => u.email === email);
  if (!user) return jsonError(res, 404, 'Usuário não encontrado.');

  const siteKey = buildKey('pk_live', 18);
  const secretKey = buildKey('sk_live', 36);
  const keyRecord = {
    id: randomId('key', 8),
    email,
    project,
    domain,
    siteKey,
    secretKey,
    secretHash: sha256(secretKey),
    createdAt: Date.now(),
    requestCount: 0,
    blockedCount: 0,
    plan: 'pro'
  };

  updateDb(db2 => {
    db2.keys.unshift(keyRecord);
    db2.adminAudit.unshift({
      id: randomId('audit', 8),
      createdAt: Date.now(),
      type: 'admin-key-create',
      email,
      project,
      domain,
      by: ADMIN_EMAIL
    });
    db2.adminAudit = db2.adminAudit.slice(0, 300);
    return db2;
  });

  res.json({ ok: true, key: keyRecord });
});

app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const db = readDb();
  res.json({
    ok: true,
    users: db.users.map(u => ({
      email: u.email,
      plan: Date.now() < u.trialEndsAt ? 'trial-pro' : u.plan,
      trialEndsAt: u.trialEndsAt,
      createdAt: u.createdAt
    })),
    keys: db.keys.slice(0, 50),
    blocked: db.blockedIps.filter(b => b.until > Date.now()).slice(0, 50),
    audit: db.adminAudit.slice(0, 50)
  });
});

app.post('/api/captcha/verify', requireUser, (req, res) => {
  const challengeType = String(req.body.challengeType || '');
  const answer = String(req.body.answer || '').trim().toUpperCase();
  const expected = String(req.body.expected || '').trim().toUpperCase();

  if (!challengeType || !answer || !expected) return jsonError(res, 400, 'Dados do desafio incompletos.');
  if (answer !== expected) return jsonError(res, 403, 'Resposta incorreta.');

  const token = {
    type: 'captcha',
    email: req.user.email,
    challengeType,
    id: randomId('cap', 8)
  };
  const signed = require('./lib/security').signValue({ ...token, exp: Date.now() + 10 * 60 * 1000 });
  res.json({ ok: true, captchaToken: signed });
});

app.get('/api/widget.js', (req, res) => {
  res.type('application/javascript').send(fs.readFileSync(path.join(__dirname, 'public', 'widget.js'), 'utf8'));
});

app.post('/api/intake', (req, res) => {
  const siteKey = String(req.body.siteKey || '');
  const route = sanitizeText(req.body.route || '/', 120);
  const action = sanitizeText(req.body.action || 'pageview', 40);
  const webdriver = !!req.body.webdriver;
  const mouseMoves = Number(req.body.mouseMoves || 0);
  const dwellMs = Number(req.body.dwellMs || 0);
  const scrollDepth = Number(req.body.scrollDepth || 0);
  const avgTypingMs = Number(req.body.avgTypingMs || 0);

  const db = readDb();
  const key = db.keys.find(k => k.siteKey === siteKey);
  if (!key) return jsonError(res, 401, 'siteKey inválida.');

  let botScore = 50;
  const flags = [];
  const userAgent = getHeader(req, 'user-agent');
  if (/headless|puppeteer|selenium|playwright|phantomjs/i.test(userAgent)) { botScore += 30; flags.push('automation-ua'); }
  if (webdriver) { botScore += 30; flags.push('webdriver'); }
  if (mouseMoves < 5) { botScore += 10; flags.push('low-mouse'); }
  if (dwellMs < 1500) { botScore += 8; flags.push('fast-dwell'); }
  if (avgTypingMs > 0 && avgTypingMs < 25) { botScore += 8; flags.push('typing-too-fast'); }
  if (scrollDepth < 2) { botScore += 4; flags.push('low-scroll'); }

  botScore = Math.max(0, Math.min(100, botScore));
  let decision = 'allow';
  if (botScore >= 80) decision = 'block';
  else if (botScore >= 62) decision = 'challenge';

  updateDb(next => {
    const target = next.keys.find(k => k.id === key.id);
    if (target) {
      target.requestCount = (target.requestCount || 0) + 1;
      if (decision === 'block') target.blockedCount = (target.blockedCount || 0) + 1;
    }
    return next;
  });

  registerEvent({
    email: key.email,
    ip: req.clientIp,
    ipMasked: maskIp(req.clientIp),
    route,
    decision: decision === 'allow' ? 'Liberado' : decision === 'challenge' ? 'Desafio' : 'Bloqueado',
    score: Number((1 - botScore / 100).toFixed(2)),
    reason: flags.join(',') || 'ok',
    keyId: key.id
  });

  if (decision === 'block') {
    registerBlockedIp({
      ip: req.clientIp,
      ipMasked: maskIp(req.clientIp),
      until: Date.now() + REQUEST_BLOCK_MS,
      reason: `bot-score:${botScore}`
    });
  }

  res.json({
    ok: true,
    decision,
    botScore,
    flags
  });
});

app.post('/api/verify', (req, res) => {
  const siteKey = String(req.body.siteKey || '');
  const secretKey = String(req.body.secretKey || '');
  const route = sanitizeText(req.body.route || '/', 120);
  const token = String(req.body.token || '');

  const db = readDb();
  const key = db.keys.find(k => k.siteKey === siteKey);
  if (!key) return jsonError(res, 401, 'Chave inválida.');
  if (sha256(secretKey) !== key.secretHash) return jsonError(res, 401, 'Segredo inválido.');

  const local = getLocalBlock(req.clientIp);
  if (local) return jsonError(res, 429, 'IP bloqueado.', { retryAfterSeconds: Math.max(1, Math.floor((local.until - Date.now()) / 1000)) });

  const tokenLooksValid = token.length > 12;
  if (!tokenLooksValid) return jsonError(res, 403, 'Token ausente ou inválido.', { decision: 'challenge' });

  registerEvent({
    email: key.email,
    ip: req.clientIp,
    ipMasked: maskIp(req.clientIp),
    route,
    decision: 'Liberado',
    score: 0.92,
    reason: 'verify-ok',
    keyId: key.id
  });

  res.json({ ok: true, decision: 'allow' });
});

app.listen(PORT, () => {
  console.log(`Aso Protection running on ${APP_URL}`);
});
