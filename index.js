const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, { cors: { origin: "*" } });

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'nvme_live_ecosystem_secret';

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static('frontend'));
app.use('/uploads', express.static('uploads'));

const users = new Map();
const videos = new Map();
const posts = new Map();
const messages = new Map();
const liveStreams = new Map();
const wallets = new Map();

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = `uploads/${file.fieldname}s`;
    if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => cb(null, `${uuidv4()}-${file.originalname}`),
});
const upload = multer({ storage });

const validateUser = (req, res, next) => {
  const { username, email, password } = req.body;
  if (!username || username.length < 3) return res.status(400).json({ error: 'Username required (min 3 chars).' });
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Valid email required.' });
  if (!password || password.length < 6) return res.status(400).json({ error: 'Password required (min 6 chars).' });
  next();
};

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// == AUTHENTICATION ==
app.post('/api/auth/register', validateUser, async (req, res) => {
  const { username, email, password } = req.body;
  if (users.has(email)) return res.status(400).json({ error: 'User already exists.' });
  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = {
    id: uuidv4(), username, email, password: hashedPassword,
    avatar: '', bio: '', followers: [], following: [],
    subscriptionTier: 'free', createdAt: new Date()
  };
  users.set(email, newUser);
  wallets.set(newUser.id, { balance: 100, transactions: [] });
  const token = jwt.sign({ userId: newUser.id, email }, JWT_SECRET, { expiresIn: '7d' });
  res.status(201).json({ message: 'User created', token, user: { id: newUser.id, username, email, tier: newUser.subscriptionTier } });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = users.get(email);
  if (!user || !(await bcrypt.compare(password, user.password))) return res.status(400).json({ error: 'Invalid credentials.' });
  const token = jwt.sign({ userId: user.id, email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ message: 'Login successful', token, user: { id: user.id, username: user.username, tier: user.subscriptionTier } });
});

app.get('/api/user/profile', authenticateToken, (req, res) => {
  const user = users.get(req.user.email);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const wallet = wallets.get(user.id) || { balance: 0 };
  res.json({ id: user.id, username: user.username, email: user.email, avatar: user.avatar, bio: user.bio, followers: user.followers.length, following: user.following.length, tier: user.subscriptionTier, coins: wallet.balance });
});

app.put('/api/user/profile', authenticateToken, upload.single('avatar'), (req, res) => {
  const user = users.get(req.user.email);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (req.body.username) user.username = req.body.username;
  if (req.body.bio) user.bio = req.body.bio;
  if (req.file) user.avatar = `/uploads/avatars/${req.file.filename}`;
  res.json({ message: 'Profile updated', user: { id: user.id, username: user.username, avatar: user.avatar, bio: user.bio } });
});

// == TIKTOK/CLAPPER - VIDEO FEED ==
app.post('/api/videos/upload', authenticateToken, upload.single('video'), (req, res) => {
  const { description, hashtags, isPremium, price } = req.body;
  const user = users.get(req.user.email);
  if (!req.file) return res.status(400).json({ error: 'No video file' });
  const newVideo = {
    id: uuidv4(), userId: user.id, username: user.username,
    videoUrl: `/uploads/videos/${req.file.filename}`,
    description: description || '', hashtags: hashtags ? hashtags.split(',') : [],
    isPremium: isPremium === 'true', price: parseFloat(price) || 0,
    likes: [], comments: [], views: 0, shares: 0, createdAt: new Date()
  };
  videos.set(newVideo.id, newVideo);
  res.status(201).json({ message: 'Video uploaded', video: newVideo });
});

app.get('/api/videos/feed', (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const feed = Array.from(videos.values()).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).slice((page - 1) * limit, page * limit);
  res.json({ videos: feed });
});

app.get('/api/feed/tiktok', (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = 10;
  const feed = Array.from(videos.values()).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).slice((page - 1) * limit, page * limit);
  res.json({ videos: feed });
});

app.post('/api/videos/:id/like', authenticateToken, (req, res) => {
  const video = videos.get(req.params.id);
  if (!video) return res.status(404).json({ error: 'Video not found' });
  const user = users.get(req.user.email);
  const idx = video.likes.indexOf(user.id);
  if (idx === -1) video.likes.push(user.id); else video.likes.splice(idx, 1);
  res.json({ likes: video.likes.length, liked: idx === -1 });
});

app.post('/api/videos/:id/comment', authenticateToken, (req, res) => {
  const video = videos.get(req.params.id);
  if (!video) return res.status(404).json({ error: 'Video not found' });
  const user = users.get(req.user.email);
  const comment = { id: uuidv4(), userId: user.id, username: user.username, text: req.body.text, createdAt: new Date() };
  video.comments.push(comment);
  res.status(201).json({ comment });
});

// == INSTAGRAM - POSTS ==
app.post('/api/posts/upload', authenticateToken, upload.array('media', 10), (req, res) => {
  const { caption } = req.body;
  const user = users.get(req.user.email);
  const mediaUrls = req.files ? req.files.map(f => `/uploads/medias/${f.filename}`) : [];
  const newPost = { id: uuidv4(), userId: user.id, username: user.username, mediaUrls, caption: caption || '', likes: [], comments: [], createdAt: new Date() };
  posts.set(newPost.id, newPost);
  res.status(201).json({ message: 'Post created', post: newPost });
});

app.get('/api/feed/instagram', (req, res) => {
  const feed = Array.from(posts.values()).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ posts: feed });
});

// == WHATSAPP - MESSAGING ==
app.post('/api/messages/send', authenticateToken, (req, res) => {
  const { recipientId, content, type } = req.body;
  const user = users.get(req.user.email);
  const chatId = [user.id, recipientId].sort().join('-');
  if (!messages.has(chatId)) messages.set(chatId, []);
  const newMessage = { id: uuidv4(), senderId: user.id, senderName: user.username, content, type: type || 'text', timestamp: new Date() };
  messages.get(chatId).push(newMessage);
  io.to(chatId).emit('newMessage', newMessage);
  res.status(201).json({ message: 'Message sent', data: newMessage });
});

app.get('/api/messages/:chatId', authenticateToken, (req, res) => {
  res.json({ messages: messages.get(req.params.chatId) || [] });
});

app.get('/api/conversations', authenticateToken, (req, res) => {
  const user = users.get(req.user.email);
  const convos = [];
  messages.forEach((msgs, chatId) => {
    if (chatId.includes(user.id) && msgs.length > 0) {
      convos.push({ chatId, lastMessage: msgs[msgs.length - 1], messageCount: msgs.length });
    }
  });
  res.json({ conversations: convos });
});

// == YOUTUBE - LIVE STREAMING ==
app.post('/api/stream/start', authenticateToken, (req, res) => {
  const { title, description } = req.body;
  const user = users.get(req.user.email);
  const streamKey = uuidv4();
  const stream = { id: uuidv4(), userId: user.id, username: user.username, title: title || 'Live Stream', description: description || '', streamKey, isLive: true, viewers: 0, startedAt: new Date() };
  liveStreams.set(streamKey, stream);
  res.status(201).json({ message: 'Stream started', stream });
});

app.post('/api/stream/stop', authenticateToken, (req, res) => {
  const { streamKey } = req.body;
  const stream = liveStreams.get(streamKey);
  if (!stream) return res.status(404).json({ error: 'Stream not found' });
  stream.isLive = false;
  stream.endedAt = new Date();
  res.json({ message: 'Stream ended', stream });
});

app.get('/api/streams/live', (req, res) => {
  const live = Array.from(liveStreams.values()).filter(s => s.isLive);
  res.json({ streams: live });
});

// == WALLET & COINS ==
app.get('/api/wallet', authenticateToken, (req, res) => {
  const user = users.get(req.user.email);
  const wallet = wallets.get(user.id) || { balance: 0, transactions: [] };
  res.json({ wallet });
});

app.post('/api/wallet/send', authenticateToken, (req, res) => {
  const { recipientId, amount } = req.body;
  const user = users.get(req.user.email);
  const senderWallet = wallets.get(user.id);
  const recipientWallet = wallets.get(recipientId);
  if (!senderWallet || !recipientWallet) return res.status(404).json({ error: 'Wallet not found' });
  if (senderWallet.balance < amount) return res.status(400).json({ error: 'Insufficient balance' });
  senderWallet.balance -= amount;
  recipientWallet.balance += amount;
  const tx = { id: uuidv4(), from: user.id, to: recipientId, amount, timestamp: new Date() };
  senderWallet.transactions.push(tx);
  recipientWallet.transactions.push(tx);
  res.json({ message: 'Transfer complete', balance: senderWallet.balance });
});

// == FOLLOW/UNFOLLOW ==
app.post('/api/users/:id/follow', authenticateToken, (req, res) => {
  const user = users.get(req.user.email);
  let target = null;
  users.forEach(u => { if (u.id === req.params.id) target = u; });
  if (!target) return res.status(404).json({ error: 'User not found' });
  const idx = user.following.indexOf(target.id);
  if (idx === -1) { user.following.push(target.id); target.followers.push(user.id); }
  else { user.following.splice(idx, 1); target.followers.splice(target.followers.indexOf(user.id), 1); }
  res.json({ following: idx === -1, followers: target.followers.length });
});

// == SEARCH ==
app.get('/api/search', (req, res) => {
  const q = (req.query.q || '').toLowerCase();
  const userResults = Array.from(users.values()).filter(u => u.username.toLowerCase().includes(q)).map(u => ({ id: u.id, username: u.username, avatar: u.avatar }));
  const videoResults = Array.from(videos.values()).filter(v => (v.description || '').toLowerCase().includes(q) || (v.hashtags || []).some(h => h.toLowerCase().includes(q)));
  res.json({ users: userResults, videos: videoResults });
});

// == HEALTH CHECK ==
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', users: users.size, videos: videos.size, streams: liveStreams.size, uptime: process.uptime() });
});

// == SOCKET.IO - REAL-TIME ==
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);
  socket.on('joinChat', (chatId) => socket.join(chatId));
  socket.on('leaveChat', (chatId) => socket.leave(chatId));
  socket.on('joinStream', (streamKey) => {
    socket.join(streamKey);
    const stream = liveStreams.get(streamKey);
    if (stream) { stream.viewers++; io.to(streamKey).emit('viewerCount', stream.viewers); }
  });
  socket.on('leaveStream', (streamKey) => {
    socket.leave(streamKey);
    const stream = liveStreams.get(streamKey);
    if (stream && stream.viewers > 0) { stream.viewers--; io.to(streamKey).emit('viewerCount', stream.viewers); }
  });
  socket.on('sendMessage', (data) => { io.to(data.chatId).emit('newMessage', data); });
  socket.on('disconnect', () => console.log('User disconnected:', socket.id));
});

server.listen(PORT, () => console.log(`NVME.live ecosystem running on port ${PORT}`));
