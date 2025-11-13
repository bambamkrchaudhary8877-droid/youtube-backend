/**
 * Deploy-ready backend (Express + lowdb)
 */
import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import multer from 'multer';
import { Low } from 'lowdb';
import { JSONFile } from 'lowdb/node';
import { nanoid } from 'nanoid';
import fs from 'fs';
import path from 'path';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';

dotenv.config();

const PORT = process.env.PORT || 4000;
const app = express();
app.use(cors());
app.use(bodyParser.json({ limit: '20mb' }));

// lowdb setup
const dbFile = path.join(process.cwd(), 'db.json');
const adapter = new JSONFile(dbFile);
const db = new Low(adapter);

await db.read();
db.data = db.data || { users: [], videos: [] };
await db.write();

const SECRET = process.env.JWT_SECRET || 'dev_jwt_secret_change';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'kumayan7488@gmail.com';
const ADMIN_PASS = process.env.ADMIN_PASS || 'Aryankr7488';
const ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET || 'admin_jwt_secret_change';

const UPLOAD_DIR = path.join(process.cwd(), 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) =>
    cb(null, Date.now() + '_' + file.originalname.replace(/\s+/g, '_')),
});
const upload = multer({ storage });

let s3client = null;
if (process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY && process.env.S3_BUCKET) {
  s3client = new S3Client({ region: process.env.AWS_REGION || 'ap-south-1' });
  console.log('S3 configured for bucket', process.env.S3_BUCKET);
}

function genToken(user) {
  return jwt.sign({ id: user.id, email: user.email }, SECRET, { expiresIn: '7d' });
}
function genAdminToken() {
  return jwt.sign({ admin: true, email: ADMIN_EMAIL }, ADMIN_JWT_SECRET, { expiresIn: '7d' });
}

async function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'No token' });
  const token = header.split(' ')[1];
  try {
    const payload = jwt.verify(token, SECRET);
    await db.read();
    const user = db.data.users.find((u) => u.id === payload.id);
    if (!user) return res.status(401).json({ error: 'Invalid token' });
    req.user = user;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function adminAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'No admin token' });
  const token = header.split(' ')[1];
  try {
    const payload = jwt.verify(token, ADMIN_JWT_SECRET);
    if (!payload || !payload.admin) return res.status(401).json({ error: 'Invalid admin token' });
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid admin token' });
  }
}

// Auth routes
app.post('/auth/signup', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Missing email or password' });
  await db.read();
  if (db.data.users.find((u) => u.email === email)) return res.status(400).json({ error: 'Email exists' });
  const hash = await bcrypt.hash(password, 10);
  const user = { id: nanoid(), email, password_hash: hash, created_at: new Date().toISOString() };
  db.data.users.push(user);
  await db.write();
  const token = genToken(user);
  res.json({ user: { id: user.id, email: user.email }, token });
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Missing' });
  await db.read();
  const user = db.data.users.find((u) => u.email === email);
  if (!user) return res.status(400).json({ error: 'User not found' });
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(400).json({ error: 'Invalid password' });
  res.json({ user: { id: user.id, email: user.email }, token: genToken(user) });
});

// Admin login
app.post('/admin/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Missing' });
  if (email === ADMIN_EMAIL && password === ADMIN_PASS) {
    const token = genAdminToken();
    return res.json({ token });
  } else {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
});

// Presign and local upload endpoints
app.post('/upload-url', async (req, res) => {
  const { filename, contentType } = req.body || {};
  if (!filename || !contentType) return res.status(400).json({ error: 'Missing' });
  if (!s3client) return res.status(400).json({ error: 'S3 not configured' });
  const key = 'uploads/' + Date.now() + '_' + filename.replace(/\s+/g, '_');
  const cmd = new PutObjectCommand({ Bucket: process.env.S3_BUCKET, Key: key, ContentType: contentType });
  try {
    const url = await getSignedUrl(s3client, cmd, { expiresIn: 3600 });
    const publicUrl = `https://${process.env.S3_BUCKET}.s3.${process.env.AWS_REGION}.amazonaws.com/${key}`;
    res.json({ uploadUrl: url, key, publicUrl });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Presign failed' });
  }
});

app.post('/upload-local', upload.single('video'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  const url = req.protocol + '://' + req.get('host') + '/uploads/' + req.file.filename;
  res.json({ url, filename: req.file.filename });
});

// Create video metadata
app.post('/videos', authMiddleware, async (req, res) => {
  const { title, description, videoUrl, thumbnailUrl, s3_key, duration } = req.body;
  if (!videoUrl) return res.status(400).json({ error: 'videoUrl required' });
  await db.read();
  const video = {
    id: nanoid(),
    user_id: req.user.id,
    userEmail: req.user.email,
    title: title || 'Untitled',
    description: description || '',
    url: videoUrl,
    s3_key: s3_key || null,
    thumbnail: thumbnailUrl || null,
    duration: duration || null,
    likes: [],
    comments: [],
    views: 0,
    hidden: false,
    created_at: new Date().toISOString(),
  };
  db.data.videos.unshift(video);
  await db.write();
  res.json({ video });
});

app.get('/videos', async (req, res) => {
  await db.read();
  res.json(db.data.videos || []);
});

app.post('/videos/:id/view', async (req, res) => {
  await db.read();
  const v = db.data.videos.find((x) => x.id === req.params.id);
  if (!v) return res.status(404).json({ error: 'Not found' });
  v.views = (v.views || 0) + 1;
  await db.write();
  res.json({ views: v.views });
});

app.post('/videos/:id/like', authMiddleware, async (req, res) => {
  await db.read();
  const v = db.data.videos.find((x) => x.id === req.params.id);
  if (!v) return res.status(404).json({ error: 'Not found' });
  const idx = v.likes.indexOf(req.user.id);
  if (idx === -1) v.likes.push(req.user.id);
  else v.likes.splice(idx, 1);
  await db.write();
  res.json({ likes: v.likes.length });
});

app.post('/videos/:id/comments', authMiddleware, async (req, res) => {
  const text = req.body.text;
  if (!text) return res.status(400).json({ error: 'No text' });
  await db.read();
  const v = db.data.videos.find((x) => x.id === req.params.id);
  if (!v) return res.status(404).json({ error: 'Not found' });
  const comment = { id: nanoid(), user_id: req.user.id, userEmail: req.user.email, text, created_at: new Date().toISOString() };
  v.comments.push(comment);
  await db.write();
  res.json({ comment });
});

app.delete('/videos/:id', adminAuth, async (req, res) => {
  await db.read();
  const idx = (db.data.videos || []).findIndex((v) => v.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Video not found' });
  const [video] = db.data.videos.splice(idx, 1);
  await db.write();
  if (video && video.url && video.url.includes('/uploads/')) {
    const filename = video.url.split('/uploads/').pop();
    const filePath = path.join(UPLOAD_DIR, filename);
    if (fs.existsSync(filePath)) {
      try { fs.unlinkSync(filePath); } catch(e){ console.warn('file delete failed', e); }
    }
  }
  res.json({ success: true });
});

app.patch('/videos/:id', adminAuth, async (req, res) => {
  const { hidden } = req.body;
  await db.read();
  const v = db.data.videos.find((x) => x.id === req.params.id);
  if (!v) return res.status(404).json({ error: 'Not found' });
  v.hidden = !!hidden;
  await db.write();
  res.json({ video: v });
});

app.get('/users', adminAuth, async (req, res) => {
  await db.read();
  const users = (db.data.users || []).map((u) => {
    const uploadCount = (db.data.videos || []).filter((v) => v.user_id === u.id).length;
    return { id: u.id, email: u.email, created_at: u.created_at, uploadCount };
  });
  res.json(users);
});

app.delete('/users/:id', adminAuth, async (req, res) => {
  await db.read();
  const idx = (db.data.users || []).findIndex((u) => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'User not found' });
  db.data.users.splice(idx, 1);
  await db.write();
  res.json({ success: true });
});

app.use('/uploads', express.static(UPLOAD_DIR));

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
