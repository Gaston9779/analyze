const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const multer = require('multer');
const pdfParse = require('pdf-parse');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const app = express();
app.set('trust proxy', 1);
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(express.json({ limit: '2mb' }));

const port = process.env.PORT || 8787;
const NODE_ENV = process.env.NODE_ENV || 'development';
const HF_TOKEN = process.env.HF_TOKEN || '';
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const USERS_FILE = process.env.USERS_FILE || path.join(__dirname, 'data', 'users.json');
const MAX_UPLOAD_BYTES = Number(process.env.MAX_UPLOAD_BYTES || 5 * 1024 * 1024);
const HF_TIMEOUT_MS = Number(process.env.HF_TIMEOUT_MS || 45000);
const ALLOW_ONRENDER_WILDCARD =
  process.env.CORS_ALLOW_ONRENDER_WILDCARD == null
    ? NODE_ENV === 'production'
    : String(process.env.CORS_ALLOW_ONRENDER_WILDCARD).toLowerCase() === 'true';

const CORS_ORIGINS = (process.env.CORS_ORIGIN || '')
  .split(',')
  .map((origin) => normalizeOrigin(origin))
  .filter(Boolean);
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_UPLOAD_BYTES },
});

if (NODE_ENV === 'production' && (!HF_TOKEN || !JWT_SECRET || JWT_SECRET === 'dev_secret_change_me')) {
  console.error('Missing secure production configuration. Set HF_TOKEN and JWT_SECRET.');
  process.exit(1);
}

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || isOriginAllowed(origin)) {
        callback(null, true);
        return;
      }
      callback(new Error('Origin not allowed by CORS'));
    },
  }),
);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many authentication attempts. Try again later.' },
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 45,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Slow down and retry shortly.' },
});

app.use('/auth', authLimiter);
app.use(['/extract-pdf', '/ocr', '/analyze'], apiLimiter);

const ensureUsersFile = () => {
  const dir = path.dirname(USERS_FILE);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  if (!fs.existsSync(USERS_FILE)) {
    fs.writeFileSync(USERS_FILE, JSON.stringify([]), 'utf-8');
  }
};

const loadUsers = () => {
  ensureUsersFile();
  const raw = fs.readFileSync(USERS_FILE, 'utf-8');
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
};

const saveUsers = (users) => {
  ensureUsersFile();
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf-8');
};

const authMiddleware = (req, res, next) => {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token) {
    return res.status(401).json({ error: 'Missing auth token.' });
  }
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    return next();
  } catch {
    return res.status(401).json({ error: 'Invalid auth token.' });
  }
};

app.get('/health', (_req, res) => {
  res.json({
    ok: true,
    env: NODE_ENV,
    timestamp: new Date().toISOString(),
  });
});

app.post('/auth/register', async (req, res) => {
  try {
    const email = String(req.body?.email || '')
      .trim()
      .toLowerCase();
    const password = String(req.body?.password || '');
    if (!email || !password) {
      return res.status(400).json({ error: 'Missing email or password.' });
    }
    if (!email.includes('@')) {
      return res.status(400).json({ error: 'Invalid email format.' });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    }
    const users = loadUsers();
    if (users.find((user) => user.email === email)) {
      return res.status(409).json({ error: 'Email already registered.' });
    }
    const hashed = await bcrypt.hash(password, 10);
    users.push({ email, password: hashed });
    saveUsers(users);
    const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '30d' });
    return res.json({ token });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return res.status(500).json({ error: message });
  }
});

app.post('/auth/login', async (req, res) => {
  try {
    const email = String(req.body?.email || '')
      .trim()
      .toLowerCase();
    const password = String(req.body?.password || '');
    if (!email || !password) {
      return res.status(400).json({ error: 'Missing email or password.' });
    }
    const users = loadUsers();
    const user = users.find((item) => item.email === email);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }
    const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '30d' });
    return res.json({ token });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return res.status(500).json({ error: message });
  }
});

app.post('/extract-pdf', authMiddleware, upload.single('file'), async (req, res) => {
  try {
    const file = req.file;
    if (!file || !file.buffer) {
      return res.status(400).json({ error: 'Missing PDF file.' });
    }
    if (file.mimetype !== 'application/pdf') {
      return res.status(415).json({ error: 'Unsupported file type. Please upload a PDF.' });
    }

    const parsed = await pdfParse(file.buffer);
    const text = (parsed.text || '').trim();

    if (!text) {
      return res.status(422).json({ error: 'No text extracted from PDF.' });
    }

    return res.json({ text });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return res.status(500).json({ error: message });
  }
});

app.post('/analyze', authMiddleware, async (req, res) => {
  try {
    const text = String(req.body?.text || '').trim();
    if (!text) {
      return res.status(400).json({ error: 'Missing text.' });
    }
    if (text.length > 30000) {
      return res.status(413).json({ error: 'Text is too long. Please shorten the input.' });
    }
    if (!HF_TOKEN) {
      const fallbackSummary = postProcessSummary(buildLocalSummary(text), text);
      return res.json({ summary: fallbackSummary, mode: 'fallback_no_hf_token' });
    }

    const response = await fetchWithTimeout('https://router.huggingface.co/hf-inference/models/facebook/bart-large-cnn', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${HF_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        inputs: text,
        parameters: { min_length: 40, max_length: 220 },
      }),
    });

    if (!response.ok) {
      const detail = await response.text();
      console.error(`HF analyze failed with status ${response.status}: ${detail.slice(0, 240)}`);
      const fallbackSummary = postProcessSummary(buildLocalSummary(text), text);
      return res.json({ summary: fallbackSummary, mode: 'fallback_hf_error' });
    }

    const decoded = await response.json();
    const rawSummary = Array.isArray(decoded) ? decoded[0]?.summary_text : decoded?.summary_text;
    const summary = postProcessSummary(rawSummary || buildLocalSummary(text), text);
    return res.json({ summary });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`Analyze fallback after error: ${message}`);
    const text = String(req.body?.text || '').trim();
    const fallbackSummary = postProcessSummary(buildLocalSummary(text), text);
    return res.json({ summary: fallbackSummary, mode: 'fallback_exception' });
  }
});

app.post('/ocr', authMiddleware, upload.single('file'), async (req, res) => {
  try {
    const file = req.file;
    if (!file || !file.buffer) {
      return res.status(400).json({ error: 'Missing image file.' });
    }
    if (!String(file.mimetype || '').startsWith('image/')) {
      return res.status(415).json({ error: 'Unsupported file type. Please upload an image.' });
    }
    if (!HF_TOKEN) {
      return res.status(500).json({ error: 'HF_TOKEN not configured on server.' });
    }

    const response = await fetchWithTimeout('https://router.huggingface.co/hf-inference/models/microsoft/trocr-base-printed', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${HF_TOKEN}`,
        'Content-Type': 'application/octet-stream',
      },
      body: file.buffer,
    });

    if (!response.ok) {
      const detail = await response.text();
      return res.status(response.status).json({ error: detail });
    }

    const decoded = await response.json();
    const text = Array.isArray(decoded) ? decoded[0]?.generated_text : decoded?.generated_text;
    return res.json({ text });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return res.status(500).json({ error: message });
  }
});

app.use((error, _req, res, _next) => {
  if (error?.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({ error: `File too large. Max allowed is ${MAX_UPLOAD_BYTES} bytes.` });
  }
  if (error?.message === 'Origin not allowed by CORS') {
    return res.status(403).json({ error: 'Origin not allowed.' });
  }
  return res.status(500).json({ error: 'Internal server error.' });
});

app.listen(port, () => {
  console.log(
    `CORS configured with ${CORS_ORIGINS.length} explicit origin(s). Wildcard *.onrender.com: ${ALLOW_ONRENDER_WILDCARD}`,
  );
  console.log(`API server listening on http://0.0.0.0:${port}`);
});

function normalizeOrigin(origin) {
  const value = String(origin || '').trim();
  if (!value) return '';
  if (value.startsWith('http://') || value.startsWith('https://')) {
    return value.replace(/\/+$/, '');
  }
  return `https://${value.replace(/\/+$/, '')}`;
}

function isRenderOrigin(origin) {
  try {
    const parsed = new URL(origin);
    return parsed.protocol === 'https:' && (parsed.hostname === 'onrender.com' || parsed.hostname.endsWith('.onrender.com'));
  } catch {
    return false;
  }
}

function isOriginAllowed(origin) {
  const normalized = normalizeOrigin(origin);
  if (!normalized) return true;
  if (CORS_ORIGINS.length === 0) return true;
  if (CORS_ORIGINS.includes(normalized)) return true;
  if (ALLOW_ONRENDER_WILDCARD && isRenderOrigin(normalized)) return true;
  return false;
}

async function fetchWithTimeout(url, options) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), HF_TIMEOUT_MS);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } catch (error) {
    if (error?.name === 'AbortError') {
      throw new Error(`HF request timeout after ${HF_TIMEOUT_MS}ms`);
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

function postProcessSummary(rawSummary, sourceText) {
  const base = String(rawSummary || '').replace(/\r/g, '\n').trim();
  if (!base) return '';

  const cleaned = base
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);

  let bullets = cleaned.map((line) => (line.startsWith('- ') ? line : `- ${line.replace(/^[-*•]\s*/, '')}`));
  const hasActionInSource = /(firmare|inviare|trasmettere|pagare|versare|contattare|sottoscrivere)/i.test(sourceText);
  const hasActionInSummary = /(firmare|inviare|trasmettere|pagare|versare|contattare|sottoscrivere|azione|da fare)/i.test(
    bullets.join(' '),
  );

  if (hasActionInSource && !hasActionInSummary) {
    bullets.push('- Azioni operative: completare le attivita richieste nel documento entro le scadenze indicate.');
  }

  bullets = bullets.slice(0, 5);
  return bullets.join('\n');
}

function buildLocalSummary(sourceText) {
  const normalized = String(sourceText || '').trim();
  if (!normalized) return '';

  const sentences = normalized
    .replace(/\n+/g, ' ')
    .split(/(?<=[.!?])\s+/)
    .map((line) => line.trim())
    .filter(Boolean);

  const points = [];
  const summarySentences = sentences.slice(0, 3);
  for (const sentence of summarySentences) {
    points.push(sentence);
  }

  if (/(firmare|inviare|trasmettere|pagare|versare|contattare|sottoscrivere)/i.test(normalized)) {
    points.push('Azioni operative presenti nel documento: eseguire e verificare le attivita richieste.');
  }

  return points.slice(0, 5).map((line) => `- ${line}`).join('\n');
}
