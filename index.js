const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static('frontend'));
app.use('/uploads', express.static('uploads'));

const users = [];
const videos = [];
const JWT_SECRET = process.env.JWT_SECRET || 'nvme_live_secret_key';

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = 'uploads/';
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, {recursive:true});
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + Math.round(Math.random()*1E9) + path.extname(file.originalname));
  }
});
const upload = multer({ storage });

const validateUser = (req, res, next) => {
  const { username, email, password } = req.body;
  if (!username || username.length < 3) return res.status(400).json({ error: 'Username must be at least 3 characters' });
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Valid email required' });
  if (!password || password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  next();
};

app.post('/api/auth/register', validateUser, async (req, res) => {
  try {
    const { username, email, password, phone } = req.body;
    if (users.find(u => u.email === email || u.username === username)) return res.status(400).json({ error: 'User already exists' });
    const hashed = await bcrypt.hash(password, 10);
    const user = { id: Date.now().toString(), username, email, phone: phone||'', password: hashed, avatar:'', bio:'', followers:[], following:[], createdAt: new Date() };
    users.push(user);
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ message:'User created successfully', token, user:{id:user.id,username:user.username,email:user.email,avatar:user.avatar} });
  } catch(e) { res.status(500).json({ error:'Server error' }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = users.find(u => u.email === email);
    if (!user) return res.status(400).json({ error:'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ error:'Invalid credentials' });
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ message:'Login successful', token, user:{id:user.id,username:user.username,email:user.email,avatar:user.avatar} });
  } catch(e) { res.status(500).json({ error:'Server error' }); }
});

app.get('/api/user/profile', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error:'No token' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = users.find(u => u.id === decoded.userId);
    if (!user) return res.status(404).json({ error:'User not found' });
    res.json({ id:user.id, username:user.username, email:user.email, phone:user.phone, avatar:user.avatar, bio:user.bio, followers:user.followers.length, following:user.following.length });
  } catch(e) { res.status(401).json({ error:'Invalid token' }); }
});

app.post('/api/videos/upload', upload.single('video'), async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error:'No token' });
    const decoded = jwt.verify(token, JWT_SECRET);
    if (!req.file) return res.status(400).json({ error:'No video file' });
    const video = { id:Date.now().toString(), userId:decoded.userId, videoPath:req.file.filename, description:req.body.description||'', hashtags:req.body.hashtags?req.body.hashtags.split(','):[], likes:[], comments:[], views:0, createdAt:new Date() };
    videos.push(video);
    res.status(201).json({ message:'Video uploaded', video:{id:video.id,description:video.description,videoUrl:'/uploads/'+video.videoPath} });
  } catch(e) { res.status(500).json({ error:'Server error' }); }
});

app.get('/api/videos/feed', (req, res) => {
  const page = parseInt(req.query.page)||1, limit = parseInt(req.query.limit)||10;
  const start = (page-1)*limit;
  const feed = videos.sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt)).slice(start,start+limit).map(v=>{
    const u=users.find(x=>x.id===v.userId)||{id:'0',username:'unknown',avatar:''};
    return {id:v.id,description:v.description,hashtags:v.hashtags,videoUrl:'/uploads/'+v.videoPath,likes:v.likes.length,comments:v.comments.length,views:v.views,createdAt:v.createdAt,user:{id:u.id,username:u.username,avatar:u.avatar}};
  });
  res.json({ videos: feed });
});

app.listen(PORT, () => console.log('NVME.live running on port '+PORT));
