const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('uploads'));

// In-memory database (replace with actual database in production)
const users = [];
const videos = [];

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'nvme_live_secret_key';

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = 'uploads/';
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir);
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname));
  }
});

const upload = multer({ storage: storage });

// Validation middleware
const validateUser = (req, res, next) => {
  const { username, email, password } = req.body;
  if (!username || username.length < 3) {
    return res.status(400).json({ error: 'Username must be at least 3 characters' });
  }
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Valid email required' });
  }
  if (!password || password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }
  next();
};

// User Registration
app.post('/api/auth/register', validateUser, async (req, res) => {
  try {
    const { username, email, password, phone } = req.body;
    const existingUser = users.find(u => u.email === email || u.username === username);
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = {
      id: Date.now().toString(),
      username,
      email,
      phone: phone || '',
      password: hashedPassword,
      avatar: '',
      bio: '',
      followers: [],
      following: [],
      createdAt: new Date()
    };
    users.push(user);
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({
      message: 'User created successfully',
      token,
      user: { id: user.id, username: user.username, email: user.email, avatar: user.avatar }
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// User Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = users.find(u => u.email === email);
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({
      message: 'Login successful',
      token,
      user: { id: user.id, username: user.username, email: user.email, avatar: user.avatar }
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user profile
app.get('/api/user/profile', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = users.find(u => u.id === decoded.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({
      id: user.id, username: user.username, email: user.email,
      phone: user.phone, avatar: user.avatar, bio: user.bio,
      followers: user.followers.length, following: user.following.length
    });
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Upload video
app.post('/api/videos/upload', upload.single('video'), async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }
    const decoded = jwt.verify(token, JWT_SECRET);
    const { description, hashtags } = req.body;
    if (!req.file) {
      return res.status(400).json({ error: 'No video file provided' });
    }
    const video = {
      id: Date.now().toString(),
      userId: decoded.userId,
      videoPath: req.file.filename,
      description: description || '',
      hashtags: hashtags ? hashtags.split(',') : [],
      likes: [], comments: [], views: 0,
      createdAt: new Date()
    };
    videos.push(video);
    res.status(201).json({
      message: 'Video uploaded successfully',
      video: { id: video.id, description: video.description, hashtags: video.hashtags, videoUrl: '/uploads/' + video.videoPath }
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get feed videos (TikTok-like)
app.get('/api/videos/feed', (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const startIndex = (page - 1) * limit;
  const feedVideos = videos
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    .slice(startIndex, startIndex + limit)
    .map(video => {
      const user = users.find(u => u.id === video.userId);
      return {
        id: video.id, description: video.description, hashtags: video.hashtags,
        videoUrl: '/uploads/' + video.videoPath,
        likes: video.likes.length, comments: video.comments.length,
        views: video.views, createdAt: video.createdAt,
        user: { id: user.id, username: user.username, avatar: user.avatar }
      };
    });
  res.json({ videos: feedVideos });
});

app.listen(PORT, () => {
  console.log('NVME.live backend running on port ' + PORT);
});
