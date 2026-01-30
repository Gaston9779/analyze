const express = require('express');
const cors = require('cors');
const multer = require('multer');
const pdfParse = require('pdf-parse');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json({ limit: '2mb' }));

const upload = multer({ storage: multer.memoryStorage() });
const port = process.env.PORT || 8787;
const HF_TOKEN = process.env.HF_TOKEN || '';
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const USERS_FILE = process.env.USERS_FILE || path.join(__dirname, 'data', 'users.json');

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
  res.json({ ok: true });
});

app.post('/auth/register', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: 'Missing email or password.' });
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
    const { email, password } = req.body || {};
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
    const { text } = req.body || {};
    if (!text) {
      return res.status(400).json({ error: 'Missing text.' });
    }
    if (!HF_TOKEN) {
      return res.status(500).json({ error: 'HF_TOKEN not configured on server.' });
    }

    const response = await fetch('https://router.huggingface.co/hf-inference/models/facebook/bart-large-cnn', {
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
      return res.status(response.status).json({ error: detail });
    }

    const decoded = await response.json();
    const summary = Array.isArray(decoded) ? decoded[0]?.summary_text : decoded?.summary_text;
    return res.json({ summary });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return res.status(500).json({ error: message });
  }
});

app.post('/ocr', authMiddleware, upload.single('file'), async (req, res) => {
  try {
    const file = req.file;
    if (!file || !file.buffer) {
      return res.status(400).json({ error: 'Missing image file.' });
    }
    if (!HF_TOKEN) {
      return res.status(500).json({ error: 'HF_TOKEN not configured on server.' });
    }

    const response = await fetch('https://router.huggingface.co/hf-inference/models/microsoft/trocr-base-printed', {
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

app.listen(port, () => {
  console.log(`API server listening on http://0.0.0.0:${port}`);
});
