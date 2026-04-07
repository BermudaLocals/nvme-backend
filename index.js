const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { Pool } = require('pg');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');

// ─── Configuration ───────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'nvme-live-secret-2026';
const DATABASE_URL = process.env.DATABASE_URL || 'postgresql://swarmnet:swarmnet_pass@swarmnet-db:5432/nvme_live';

// ─── PostgreSQL Pool ─────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: DATABASE_URL,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

pool.on('error', (err) => {
  console.error('[DB] Unexpected pool error:', err.message);
});

// ─── Express + Socket.io Setup ───────────────────────────────────────────────
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] },
  pingTimeout: 60000,
  pingInterval: 25000,
});

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.static('frontend'));
app.use('/uploads', express.static('uploads'));

// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, 'uploads');
const avatarsDir = path.join(uploadsDir, 'avatars');
const videosDir = path.join(uploadsDir, 'videos');
const postsDir = path.join(uploadsDir, 'posts');
[uploadsDir, avatarsDir, videosDir, postsDir].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// ─── Multer Configuration ────────────────────────────────────────────────────
const avatarStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, avatarsDir),
  filename: (req, file, cb) => cb(null, `${uuidv4()}${path.extname(file.originalname)}`),
});
const videoStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, videosDir),
  filename: (req, file, cb) => cb(null, `${uuidv4()}${path.extname(file.originalname)}`),
});
const postStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, postsDir),
  filename: (req, file, cb) => cb(null, `${uuidv4()}${path.extname(file.originalname)}`),
});

const uploadAvatar = multer({ storage: avatarStorage, limits: { fileSize: 10 * 1024 * 1024 } });
const uploadVideo = multer({ storage: videoStorage, limits: { fileSize: 500 * 1024 * 1024 } });
const uploadPost = multer({ storage: postStorage, limits: { fileSize: 50 * 1024 * 1024 } });

// ─── Auth Middleware ─────────────────────────────────────────────────────────
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
}

function optionalAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token) {
    try {
      req.user = jwt.verify(token, JWT_SECRET);
    } catch (e) { /* ignore */ }
  }
  next();
}

// ─── Helper: DB Query ────────────────────────────────────────────────────────
async function query(text, params) {
  const client = await pool.connect();
  try {
    const result = await client.query(text, params);
    return result;
  } finally {
    client.release();
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUTH ENDPOINTS
// ═══════════════════════════════════════════════════════════════════════════════

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Username, email, and password are required' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Check existing user
    const existing = await query(
      'SELECT id FROM users WHERE email = $1 OR username = $2',
      [email.toLowerCase(), username.toLowerCase()]
    );
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'Email or username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const userId = uuidv4();

    await query(
      `INSERT INTO users (id, username, email, password, avatar, bio, phone, tier, coins, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())`,
      [userId, username.toLowerCase(), email.toLowerCase(), hashedPassword, '/uploads/avatars/default.png', '', '', 'free', 100]
    );

    // Create wallet with 100 coins
    await query(
      'INSERT INTO wallets (id, user_id, balance, created_at) VALUES ($1, $2, $3, NOW())',
      [uuidv4(), userId, 100]
    );

    const token = jwt.sign({ id: userId, username: username.toLowerCase(), email: email.toLowerCase() }, JWT_SECRET, { expiresIn: '30d' });

    res.status(201).json({
      success: true,
      token,
      user: { id: userId, username: username.toLowerCase(), email: email.toLowerCase(), avatar: '/uploads/avatars/default.png', coins: 100 }
    });
  } catch (err) {
    console.error('[Register Error]', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const result = await query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, username: user.username, email: user.email }, JWT_SECRET, { expiresIn: '30d' });

    res.json({
      success: true,
      token,
      user: {
        id: user.id, username: user.username, email: user.email,
        avatar: user.avatar, bio: user.bio, coins: user.coins,
        tier: user.tier
      }
    });
  } catch (err) {
    console.error('[Login Error]', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// USER PROFILE
// ═══════════════════════════════════════════════════════════════════════════════

// GET /api/user/profile
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const result = await query(
      `SELECT id, username, email, avatar, bio, phone, tier, coins,
              whatsapp, facebook, instagram, tiktok, snapchat, telegram, twitter, youtube, created_at
       FROM users WHERE id = $1`,
      [req.user.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });

    const user = result.rows[0];

    // Get follower/following counts
    const followers = await query('SELECT COUNT(*) FROM follows WHERE following_id = $1', [req.user.id]);
    const following = await query('SELECT COUNT(*) FROM follows WHERE follower_id = $1', [req.user.id]);
    const videoCount = await query('SELECT COUNT(*) FROM videos WHERE user_id = $1', [req.user.id]);

    res.json({
      success: true,
      user: {
        ...user,
        followers_count: parseInt(followers.rows[0].count),
        following_count: parseInt(following.rows[0].count),
        videos_count: parseInt(videoCount.rows[0].count)
      }
    });
  } catch (err) {
    console.error('[Profile Error]', err);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// GET /api/user/profile/:userId
app.get('/api/user/profile/:userId', optionalAuth, async (req, res) => {
  try {
    const result = await query(
      `SELECT id, username, avatar, bio, tier, coins,
              whatsapp, facebook, instagram, tiktok, snapchat, telegram, twitter, youtube, created_at
       FROM users WHERE id = $1`,
      [req.params.userId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });

    const user = result.rows[0];
    const followers = await query('SELECT COUNT(*) FROM follows WHERE following_id = $1', [req.params.userId]);
    const following = await query('SELECT COUNT(*) FROM follows WHERE follower_id = $1', [req.params.userId]);
    const videoCount = await query('SELECT COUNT(*) FROM videos WHERE user_id = $1', [req.params.userId]);

    let isFollowing = false;
    if (req.user) {
      const followCheck = await query('SELECT 1 FROM follows WHERE follower_id = $1 AND following_id = $2', [req.user.id, req.params.userId]);
      isFollowing = followCheck.rows.length > 0;
    }

    res.json({
      success: true,
      user: {
        ...user,
        followers_count: parseInt(followers.rows[0].count),
        following_count: parseInt(following.rows[0].count),
        videos_count: parseInt(videoCount.rows[0].count),
        is_following: isFollowing
      }
    });
  } catch (err) {
    console.error('[Profile Error]', err);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// PUT /api/user/profile
app.put('/api/user/profile', authenticateToken, uploadAvatar.single('avatar'), async (req, res) => {
  try {
    const { username, bio, phone, whatsapp, facebook, instagram, tiktok, snapchat, telegram, twitter, youtube } = req.body;
    const updates = [];
    const values = [];
    let paramIndex = 1;

    if (username !== undefined) { updates.push(`username = $${paramIndex++}`); values.push(username.toLowerCase()); }
    if (bio !== undefined) { updates.push(`bio = $${paramIndex++}`); values.push(bio); }
    if (phone !== undefined) { updates.push(`phone = $${paramIndex++}`); values.push(phone); }
    if (whatsapp !== undefined) { updates.push(`whatsapp = $${paramIndex++}`); values.push(whatsapp); }
    if (facebook !== undefined) { updates.push(`facebook = $${paramIndex++}`); values.push(facebook); }
    if (instagram !== undefined) { updates.push(`instagram = $${paramIndex++}`); values.push(instagram); }
    if (tiktok !== undefined) { updates.push(`tiktok = $${paramIndex++}`); values.push(tiktok); }
    if (snapchat !== undefined) { updates.push(`snapchat = $${paramIndex++}`); values.push(snapchat); }
    if (telegram !== undefined) { updates.push(`telegram = $${paramIndex++}`); values.push(telegram); }
    if (twitter !== undefined) { updates.push(`twitter = $${paramIndex++}`); values.push(twitter); }
    if (youtube !== undefined) { updates.push(`youtube = $${paramIndex++}`); values.push(youtube); }
    if (req.file) { updates.push(`avatar = $${paramIndex++}`); values.push(`/uploads/avatars/${req.file.filename}`); }

    if (updates.length === 0) return res.status(400).json({ error: 'No fields to update' });

    values.push(req.user.id);
    const result = await query(
      `UPDATE users SET ${updates.join(', ')} WHERE id = $${paramIndex} RETURNING id, username, email, avatar, bio, phone, tier, coins, whatsapp, facebook, instagram, tiktok, snapchat, telegram, twitter, youtube`,
      values
    );

    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    console.error('[Update Profile Error]', err);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// TIKTOK FEED - VIDEO UPLOAD & FEED
// ═══════════════════════════════════════════════════════════════════════════════

// POST /api/videos/upload
app.post('/api/videos/upload', authenticateToken, uploadVideo.single('video'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'Video file is required' });

    const { description, hashtags, is_premium, price } = req.body;
    const videoId = uuidv4();
    const videoUrl = `/uploads/videos/${req.file.filename}`;
    const hashtagArray = hashtags ? hashtags.split(',').map(t => t.trim()) : [];

    await query(
      `INSERT INTO videos (id, user_id, video_url, description, hashtags, is_premium, price, likes, comments_count, views, shares, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, 0, 0, 0, 0, NOW())`,
      [videoId, req.user.id, videoUrl, description || '', hashtagArray, is_premium === 'true', parseFloat(price) || 0]
    );

    const result = await query(
      `SELECT v.*, u.username, u.avatar FROM videos v JOIN users u ON v.user_id = u.id WHERE v.id = $1`,
      [videoId]
    );

    res.status(201).json({ success: true, video: result.rows[0] });
  } catch (err) {
    console.error('[Video Upload Error]', err);
    res.status(500).json({ error: 'Failed to upload video' });
  }
});

// GET /api/videos/feed
app.get('/api/videos/feed', optionalAuth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const offset = (page - 1) * limit;

    const result = await query(
      `SELECT v.*, u.username, u.avatar,
              CASE WHEN $1::uuid IS NOT NULL THEN EXISTS(SELECT 1 FROM video_likes WHERE user_id = $1 AND video_id = v.id) ELSE false END AS is_liked
       FROM videos v
       JOIN users u ON v.user_id = u.id
       ORDER BY v.created_at DESC
       LIMIT $2 OFFSET $3`,
      [req.user?.id || null, limit, offset]
    );

    // Increment views
    if (result.rows.length > 0) {
      const ids = result.rows.map(v => v.id);
      await query(`UPDATE videos SET views = views + 1 WHERE id = ANY($1)`, [ids]);
    }

    res.json({ success: true, videos: result.rows, page, limit });
  } catch (err) {
    console.error('[Feed Error]', err);
    res.status(500).json({ error: 'Failed to fetch feed' });
  }
});

// GET /api/feed/tiktok
app.get('/api/feed/tiktok', optionalAuth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const offset = (page - 1) * limit;

    const result = await query(
      `SELECT v.*, u.username, u.avatar,
              CASE WHEN $1::uuid IS NOT NULL THEN EXISTS(SELECT 1 FROM video_likes WHERE user_id = $1 AND video_id = v.id) ELSE false END AS is_liked,
              (SELECT COUNT(*) FROM video_comments WHERE video_id = v.id) as comment_count
       FROM videos v
       JOIN users u ON v.user_id = u.id
       ORDER BY RANDOM()
       LIMIT $2 OFFSET $3`,
      [req.user?.id || null, limit, offset]
    );

    if (result.rows.length > 0) {
      const ids = result.rows.map(v => v.id);
      await query(`UPDATE videos SET views = views + 1 WHERE id = ANY($1)`, [ids]);
    }

    res.json({ success: true, videos: result.rows, page, limit });
  } catch (err) {
    console.error('[TikTok Feed Error]', err);
    res.status(500).json({ error: 'Failed to fetch TikTok feed' });
  }
});

// POST /api/videos/:id/like
app.post('/api/videos/:id/like', authenticateToken, async (req, res) => {
  try {
    const videoId = req.params.id;
    const userId = req.user.id;

    const existing = await query('SELECT 1 FROM video_likes WHERE user_id = $1 AND video_id = $2', [userId, videoId]);

    if (existing.rows.length > 0) {
      // Unlike
      await query('DELETE FROM video_likes WHERE user_id = $1 AND video_id = $2', [userId, videoId]);
      await query('UPDATE videos SET likes = GREATEST(likes - 1, 0) WHERE id = $1', [videoId]);
      res.json({ success: true, liked: false });
    } else {
      // Like
      await query('INSERT INTO video_likes (user_id, video_id, created_at) VALUES ($1, $2, NOW())', [userId, videoId]);
      await query('UPDATE videos SET likes = likes + 1 WHERE id = $1', [videoId]);
      res.json({ success: true, liked: true });
    }
  } catch (err) {
    console.error('[Like Error]', err);
    res.status(500).json({ error: 'Failed to like/unlike video' });
  }
});

// POST /api/videos/:id/comment
app.post('/api/videos/:id/comment', authenticateToken, async (req, res) => {
  try {
    const { text } = req.body;
    if (!text || !text.trim()) return res.status(400).json({ error: 'Comment text is required' });

    const commentId = uuidv4();
    await query(
      'INSERT INTO video_comments (id, video_id, user_id, text, created_at) VALUES ($1, $2, $3, $4, NOW())',
      [commentId, req.params.id, req.user.id, text.trim()]
    );
    await query('UPDATE videos SET comments_count = comments_count + 1 WHERE id = $1', [req.params.id]);

    const result = await query(
      `SELECT vc.*, u.username, u.avatar FROM video_comments vc JOIN users u ON vc.user_id = u.id WHERE vc.id = $1`,
      [commentId]
    );

    res.status(201).json({ success: true, comment: result.rows[0] });
  } catch (err) {
    console.error('[Comment Error]', err);
    res.status(500).json({ error: 'Failed to add comment' });
  }
});

// GET /api/videos/:id/comments
app.get('/api/videos/:id/comments', async (req, res) => {
  try {
    const result = await query(
      `SELECT vc.*, u.username, u.avatar FROM video_comments vc
       JOIN users u ON vc.user_id = u.id
       WHERE vc.video_id = $1
       ORDER BY vc.created_at DESC
       LIMIT 50`,
      [req.params.id]
    );
    res.json({ success: true, comments: result.rows });
  } catch (err) {
    console.error('[Comments Error]', err);
    res.status(500).json({ error: 'Failed to fetch comments' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// INSTAGRAM FEED
// ═══════════════════════════════════════════════════════════════════════════════

// POST /api/posts/upload
app.post('/api/posts/upload', authenticateToken, uploadPost.single('image'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'Image file is required' });

    const { description, hashtags } = req.body;
    const postId = uuidv4();
    const imageUrl = `/uploads/posts/${req.file.filename}`;
    const hashtagArray = hashtags ? hashtags.split(',').map(t => t.trim()) : [];

    // Reuse videos table for posts (type differentiation via video_url being an image)
    await query(
      `INSERT INTO videos (id, user_id, video_url, description, hashtags, is_premium, price, likes, comments_count, views, shares, created_at)
       VALUES ($1, $2, $3, $4, $5, false, 0, 0, 0, 0, 0, NOW())`,
      [postId, req.user.id, imageUrl, description || '', hashtagArray]
    );

    const result = await query(
      `SELECT v.*, u.username, u.avatar FROM videos v JOIN users u ON v.user_id = u.id WHERE v.id = $1`,
      [postId]
    );

    res.status(201).json({ success: true, post: result.rows[0] });
  } catch (err) {
    console.error('[Post Upload Error]', err);
    res.status(500).json({ error: 'Failed to upload post' });
  }
});

// GET /api/feed/instagram
app.get('/api/feed/instagram', optionalAuth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const offset = (page - 1) * limit;

    const result = await query(
      `SELECT v.*, u.username, u.avatar,
              CASE WHEN $1::uuid IS NOT NULL THEN EXISTS(SELECT 1 FROM video_likes WHERE user_id = $1 AND video_id = v.id) ELSE false END AS is_liked
       FROM videos v
       JOIN users u ON v.user_id = u.id
       ORDER BY v.created_at DESC
       LIMIT $2 OFFSET $3`,
      [req.user?.id || null, limit, offset]
    );

    res.json({ success: true, posts: result.rows, page, limit });
  } catch (err) {
    console.error('[Instagram Feed Error]', err);
    res.status(500).json({ error: 'Failed to fetch Instagram feed' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// WHATSAPP MESSAGING + VIDEO CALLING
// ═══════════════════════════════════════════════════════════════════════════════

// POST /api/messages/send
app.post('/api/messages/send', authenticateToken, async (req, res) => {
  try {
    const { chat_id, content, msg_type, recipient_id } = req.body;
    if (!content) return res.status(400).json({ error: 'Message content is required' });

    // Generate or use existing chat_id
    let chatId = chat_id;
    if (!chatId && recipient_id) {
      // Create deterministic chat_id from both user IDs
      const ids = [req.user.id, recipient_id].sort();
      chatId = `dm_${ids[0]}_${ids[1]}`;
    }
    if (!chatId) return res.status(400).json({ error: 'chat_id or recipient_id is required' });

    const msgId = uuidv4();
    await query(
      `INSERT INTO messages (id, chat_id, sender_id, content, msg_type, created_at)
       VALUES ($1, $2, $3, $4, $5, NOW())`,
      [msgId, chatId, req.user.id, content, msg_type || 'text']
    );

    const result = await query(
      `SELECT m.*, u.username, u.avatar FROM messages m JOIN users u ON m.sender_id = u.id WHERE m.id = $1`,
      [msgId]
    );

    const message = result.rows[0];

    // Emit real-time message via Socket.io
    io.to(`chat:${chatId}`).emit('new_message', message);

    res.status(201).json({ success: true, message });
  } catch (err) {
    console.error('[Send Message Error]', err);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// GET /api/messages/:chatId
app.get('/api/messages/:chatId', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const offset = (page - 1) * limit;

    const result = await query(
      `SELECT m.*, u.username, u.avatar FROM messages m
       JOIN users u ON m.sender_id = u.id
       WHERE m.chat_id = $1
       ORDER BY m.created_at ASC
       LIMIT $2 OFFSET $3`,
      [req.params.chatId, limit, offset]
    );

    res.json({ success: true, messages: result.rows, page, limit });
  } catch (err) {
    console.error('[Messages Error]', err);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// GET /api/conversations
app.get('/api/conversations', authenticateToken, async (req, res) => {
  try {
    const result = await query(
      `SELECT DISTINCT ON (m.chat_id)
              m.chat_id, m.content, m.msg_type, m.created_at,
              u.id as other_user_id, u.username as other_username, u.avatar as other_avatar
       FROM messages m
       JOIN users u ON (
         CASE WHEN m.sender_id = $1 THEN
           u.id = (
             SELECT sender_id FROM messages
             WHERE chat_id = m.chat_id AND sender_id != $1
             LIMIT 1
           )
         ELSE u.id = m.sender_id
         END
       )
       WHERE m.chat_id IN (
         SELECT DISTINCT chat_id FROM messages WHERE sender_id = $1
         UNION
         SELECT DISTINCT chat_id FROM messages WHERE chat_id LIKE '%' || $1 || '%'
       )
       ORDER BY m.chat_id, m.created_at DESC`,
      [req.user.id]
    );

    res.json({ success: true, conversations: result.rows });
  } catch (err) {
    console.error('[Conversations Error]', err);
    // Fallback simpler query
    try {
      const result = await query(
        `SELECT chat_id, content, msg_type, created_at
         FROM messages
         WHERE sender_id = $1 OR chat_id LIKE '%' || $1 || '%'
         ORDER BY created_at DESC`,
        [req.user.id]
      );

      // Group by chat_id
      const convMap = new Map();
      for (const msg of result.rows) {
        if (!convMap.has(msg.chat_id)) convMap.set(msg.chat_id, msg);
      }

      res.json({ success: true, conversations: Array.from(convMap.values()) });
    } catch (err2) {
      res.status(500).json({ error: 'Failed to fetch conversations' });
    }
  }
});

// POST /api/calls/initiate - Video/Voice Call Signaling
app.post('/api/calls/initiate', authenticateToken, async (req, res) => {
  try {
    const { recipient_id, call_type } = req.body; // call_type: 'video' | 'voice'
    if (!recipient_id) return res.status(400).json({ error: 'recipient_id is required' });

    const callId = uuidv4();
    const callData = {
      id: callId,
      caller_id: req.user.id,
      caller_username: req.user.username,
      recipient_id,
      call_type: call_type || 'video',
      status: 'ringing',
      created_at: new Date().toISOString()
    };

    // Notify recipient via Socket.io
    io.to(`user:${recipient_id}`).emit('incoming_call', callData);

    res.json({ success: true, call: callData });
  } catch (err) {
    console.error('[Call Initiate Error]', err);
    res.status(500).json({ error: 'Failed to initiate call' });
  }
});

// POST /api/calls/answer
app.post('/api/calls/answer', authenticateToken, async (req, res) => {
  try {
    const { call_id, caller_id, accepted } = req.body;

    // Notify caller of answer
    io.to(`user:${caller_id}`).emit('call_answered', {
      call_id,
      accepted,
      answerer_id: req.user.id,
      answerer_username: req.user.username
    });

    res.json({ success: true, accepted });
  } catch (err) {
    console.error('[Call Answer Error]', err);
    res.status(500).json({ error: 'Failed to answer call' });
  }
});

// POST /api/calls/signal - WebRTC signaling relay
app.post('/api/calls/signal', authenticateToken, async (req, res) => {
  try {
    const { target_id, signal_data } = req.body;

    io.to(`user:${target_id}`).emit('call_signal', {
      from_id: req.user.id,
      signal_data
    });

    res.json({ success: true });
  } catch (err) {
    console.error('[Call Signal Error]', err);
    res.status(500).json({ error: 'Failed to relay signal' });
  }
});

// POST /api/calls/end
app.post('/api/calls/end', authenticateToken, async (req, res) => {
  try {
    const { call_id, target_id } = req.body;

    io.to(`user:${target_id}`).emit('call_ended', {
      call_id,
      ended_by: req.user.id
    });

    res.json({ success: true });
  } catch (err) {
    console.error('[Call End Error]', err);
    res.status(500).json({ error: 'Failed to end call' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// YOUTUBE LIVE STREAMING + BATTLES
// ═══════════════════════════════════════════════════════════════════════════════

// In-memory live stream & battle state (ephemeral by nature)
const liveStreams = new Map();
const liveBattles = new Map();

// POST /api/stream/start
app.post('/api/stream/start', authenticateToken, async (req, res) => {
  try {
    const { title, description, category } = req.body;
    const streamId = uuidv4();

    const streamData = {
      id: streamId,
      user_id: req.user.id,
      username: req.user.username,
      title: title || `${req.user.username}'s Live Stream`,
      description: description || '',
      category: category || 'general',
      viewers: 0,
      viewer_list: new Set(),
      gifts_received: [],
      total_gift_value: 0,
      started_at: new Date().toISOString(),
      status: 'live',
      battle_id: null
    };

    liveStreams.set(streamId, streamData);

    // Also track by user_id for easy lookup
    liveStreams.set(`user:${req.user.id}`, streamId);

    io.emit('stream_started', {
      id: streamId,
      user_id: req.user.id,
      username: req.user.username,
      title: streamData.title,
      category: streamData.category,
      viewers: 0
    });

    res.json({ success: true, stream: { ...streamData, viewer_list: undefined } });
  } catch (err) {
    console.error('[Stream Start Error]', err);
    res.status(500).json({ error: 'Failed to start stream' });
  }
});

// POST /api/stream/stop
app.post('/api/stream/stop', authenticateToken, async (req, res) => {
  try {
    const streamIdKey = `user:${req.user.id}`;
    const streamId = liveStreams.get(streamIdKey);
    if (!streamId) return res.status(404).json({ error: 'No active stream found' });

    const stream = liveStreams.get(streamId);

    // End any active battle
    if (stream && stream.battle_id) {
      const battle = liveBattles.get(stream.battle_id);
      if (battle) {
        battle.status = 'ended';
        battle.ended_at = new Date().toISOString();
        io.to(`battle:${stream.battle_id}`).emit('battle_ended', battle);
        liveBattles.delete(stream.battle_id);
      }
    }

    io.to(`stream:${streamId}`).emit('stream_ended', { stream_id: streamId });
    io.emit('stream_stopped', { stream_id: streamId, user_id: req.user.id });

    liveStreams.delete(streamId);
    liveStreams.delete(streamIdKey);

    res.json({ success: true, message: 'Stream stopped', total_gift_value: stream?.total_gift_value || 0 });
  } catch (err) {
    console.error('[Stream Stop Error]', err);
    res.status(500).json({ error: 'Failed to stop stream' });
  }
});

// GET /api/streams/live
app.get('/api/streams/live', async (req, res) => {
  try {
    const streams = [];
    for (const [key, value] of liveStreams.entries()) {
      if (!key.startsWith('user:') && typeof value === 'object' && value.status === 'live') {
        streams.push({
          id: value.id,
          user_id: value.user_id,
          username: value.username,
          title: value.title,
          description: value.description,
          category: value.category,
          viewers: value.viewers,
          total_gift_value: value.total_gift_value,
          started_at: value.started_at,
          battle_id: value.battle_id
        });
      }
    }
    res.json({ success: true, streams });
  } catch (err) {
    console.error('[Live Streams Error]', err);
    res.status(500).json({ error: 'Failed to fetch live streams' });
  }
});

// GET /api/stream/:streamId
app.get('/api/stream/:streamId', async (req, res) => {
  try {
    const stream = liveStreams.get(req.params.streamId);
    if (!stream || typeof stream !== 'object') return res.status(404).json({ error: 'Stream not found' });

    res.json({
      success: true,
      stream: {
        id: stream.id,
        user_id: stream.user_id,
        username: stream.username,
        title: stream.title,
        description: stream.description,
        category: stream.category,
        viewers: stream.viewers,
        total_gift_value: stream.total_gift_value,
        started_at: stream.started_at,
        battle_id: stream.battle_id
      }
    });
  } catch (err) {
    console.error('[Stream Info Error]', err);
    res.status(500).json({ error: 'Failed to fetch stream info' });
  }
});

// ─── BATTLE SYSTEM ───────────────────────────────────────────────────────────

// POST /api/battles/challenge
app.post('/api/battles/challenge', authenticateToken, async (req, res) => {
  try {
    const { target_user_id, duration } = req.body;
    if (!target_user_id) return res.status(400).json({ error: 'target_user_id is required' });

    // Both users must be live
    const myStreamId = liveStreams.get(`user:${req.user.id}`);
    const targetStreamId = liveStreams.get(`user:${target_user_id}`);

    if (!myStreamId) return res.status(400).json({ error: 'You must be live to start a battle' });
    if (!targetStreamId) return res.status(400).json({ error: 'Target user is not live' });

    const battleId = uuidv4();
    const battleData = {
      id: battleId,
      challenger_id: req.user.id,
      challenger_username: req.user.username,
      challenger_stream_id: myStreamId,
      opponent_id: target_user_id,
      opponent_stream_id: targetStreamId,
      duration_seconds: duration || 180, // 3 min default
      challenger_score: 0,
      opponent_score: 0,
      challenger_gifts: [],
      opponent_gifts: [],
      status: 'pending',
      created_at: new Date().toISOString()
    };

    liveBattles.set(battleId, battleData);

    // Notify opponent
    io.to(`user:${target_user_id}`).emit('battle_challenge', battleData);

    res.json({ success: true, battle: battleData });
  } catch (err) {
    console.error('[Battle Challenge Error]', err);
    res.status(500).json({ error: 'Failed to create battle challenge' });
  }
});

// POST /api/battles/:battleId/accept
app.post('/api/battles/:battleId/accept', authenticateToken, async (req, res) => {
  try {
    const battle = liveBattles.get(req.params.battleId);
    if (!battle) return res.status(404).json({ error: 'Battle not found' });
    if (battle.opponent_id !== req.user.id) return res.status(403).json({ error: 'Not your battle to accept' });

    battle.status = 'active';
    battle.started_at = new Date().toISOString();
    battle.ends_at = new Date(Date.now() + battle.duration_seconds * 1000).toISOString();

    // Link battle to both streams
    const challengerStream = liveStreams.get(battle.challenger_stream_id);
    const opponentStream = liveStreams.get(battle.opponent_stream_id);
    if (challengerStream) challengerStream.battle_id = battle.id;
    if (opponentStream) opponentStream.battle_id = battle.id;

    // Get opponent username
    const oppUser = await query('SELECT username FROM users WHERE id = $1', [battle.opponent_id]);
    battle.opponent_username = oppUser.rows[0]?.username || 'Unknown';

    // Notify both streamers and their viewers
    io.to(`stream:${battle.challenger_stream_id}`).emit('battle_started', battle);
    io.to(`stream:${battle.opponent_stream_id}`).emit('battle_started', battle);
    io.to(`user:${battle.challenger_id}`).emit('battle_accepted', battle);
    io.emit('battle_live', battle);

    // Set auto-end timer
    setTimeout(() => {
      const b = liveBattles.get(req.params.battleId);
      if (b && b.status === 'active') {
        b.status = 'ended';
        b.ended_at = new Date().toISOString();
        b.winner = b.challenger_score > b.opponent_score ? b.challenger_id :
                   b.opponent_score > b.challenger_score ? b.opponent_id : 'draw';

        io.to(`stream:${b.challenger_stream_id}`).emit('battle_ended', b);
        io.to(`stream:${b.opponent_stream_id}`).emit('battle_ended', b);
        io.emit('battle_result', b);

        // Unlink from streams
        const cs = liveStreams.get(b.challenger_stream_id);
        const os = liveStreams.get(b.opponent_stream_id);
        if (cs) cs.battle_id = null;
        if (os) os.battle_id = null;

        liveBattles.delete(req.params.battleId);
      }
    }, battle.duration_seconds * 1000);

    res.json({ success: true, battle });
  } catch (err) {
    console.error('[Battle Accept Error]', err);
    res.status(500).json({ error: 'Failed to accept battle' });
  }
});

// POST /api/battles/:battleId/decline
app.post('/api/battles/:battleId/decline', authenticateToken, async (req, res) => {
  try {
    const battle = liveBattles.get(req.params.battleId);
    if (!battle) return res.status(404).json({ error: 'Battle not found' });

    battle.status = 'declined';
    io.to(`user:${battle.challenger_id}`).emit('battle_declined', { battle_id: battle.id });
    liveBattles.delete(req.params.battleId);

    res.json({ success: true, message: 'Battle declined' });
  } catch (err) {
    console.error('[Battle Decline Error]', err);
    res.status(500).json({ error: 'Failed to decline battle' });
  }
});

// GET /api/battles/active
app.get('/api/battles/active', async (req, res) => {
  try {
    const battles = [];
    for (const [, battle] of liveBattles.entries()) {
      if (battle.status === 'active') {
        battles.push(battle);
      }
    }
    res.json({ success: true, battles });
  } catch (err) {
    console.error('[Active Battles Error]', err);
    res.status(500).json({ error: 'Failed to fetch active battles' });
  }
});

// GET /api/battles/:battleId
app.get('/api/battles/:battleId', async (req, res) => {
  try {
    const battle = liveBattles.get(req.params.battleId);
    if (!battle) return res.status(404).json({ error: 'Battle not found' });
    res.json({ success: true, battle });
  } catch (err) {
    console.error('[Battle Info Error]', err);
    res.status(500).json({ error: 'Failed to fetch battle info' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// WALLET & GIFTS
// ═══════════════════════════════════════════════════════════════════════════════

// GET /api/wallet
app.get('/api/wallet', authenticateToken, async (req, res) => {
  try {
    const wallet = await query('SELECT * FROM wallets WHERE user_id = $1', [req.user.id]);
    if (wallet.rows.length === 0) {
      // Create wallet if not exists
      const walletId = uuidv4();
      await query('INSERT INTO wallets (id, user_id, balance, created_at) VALUES ($1, $2, 0, NOW())', [walletId, req.user.id]);
      return res.json({ success: true, wallet: { id: walletId, user_id: req.user.id, balance: 0 } });
    }

    const transactions = await query(
      `SELECT * FROM wallet_transactions WHERE from_user = $1 OR to_user = $1 ORDER BY created_at DESC LIMIT 50`,
      [req.user.id]
    );

    res.json({ success: true, wallet: wallet.rows[0], transactions: transactions.rows });
  } catch (err) {
    console.error('[Wallet Error]', err);
    res.status(500).json({ error: 'Failed to fetch wallet' });
  }
});

// POST /api/wallet/send
app.post('/api/wallet/send', authenticateToken, async (req, res) => {
  try {
    const { to_user_id, amount } = req.body;
    const sendAmount = parseInt(amount);
    if (!to_user_id || !sendAmount || sendAmount <= 0) {
      return res.status(400).json({ error: 'Valid to_user_id and amount are required' });
    }
    if (to_user_id === req.user.id) return res.status(400).json({ error: 'Cannot send coins to yourself' });

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Check sender balance
      const senderWallet = await client.query('SELECT * FROM wallets WHERE user_id = $1 FOR UPDATE', [req.user.id]);
      if (senderWallet.rows.length === 0 || senderWallet.rows[0].balance < sendAmount) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'Insufficient balance' });
      }

      // Ensure recipient wallet exists
      const recipientWallet = await client.query('SELECT * FROM wallets WHERE user_id = $1 FOR UPDATE', [to_user_id]);
      if (recipientWallet.rows.length === 0) {
        await client.query('INSERT INTO wallets (id, user_id, balance, created_at) VALUES ($1, $2, 0, NOW())', [uuidv4(), to_user_id]);
      }

      // Deduct from sender
      await client.query('UPDATE wallets SET balance = balance - $1 WHERE user_id = $2', [sendAmount, req.user.id]);
      // Add to recipient
      await client.query('UPDATE wallets SET balance = balance + $1 WHERE user_id = $2', [sendAmount, to_user_id]);
      // Update user coins too
      await client.query('UPDATE users SET coins = coins - $1 WHERE id = $2', [sendAmount, req.user.id]);
      await client.query('UPDATE users SET coins = coins + $1 WHERE id = $2', [sendAmount, to_user_id]);

      // Create transaction
      await client.query(
        'INSERT INTO wallet_transactions (id, from_user, to_user, amount, gift_type, created_at) VALUES ($1, $2, $3, $4, $5, NOW())',
        [uuidv4(), req.user.id, to_user_id, sendAmount, 'transfer']
      );

      await client.query('COMMIT');

      res.json({ success: true, message: `Sent ${sendAmount} coins` });
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  } catch (err) {
    console.error('[Wallet Send Error]', err);
    res.status(500).json({ error: 'Failed to send coins' });
  }
});

// GET /api/gifts
app.get('/api/gifts', async (req, res) => {
  try {
    const result = await query('SELECT * FROM gifts ORDER BY cost ASC');
    res.json({ success: true, gifts: result.rows });
  } catch (err) {
    console.error('[Gifts Error]', err);
    res.status(500).json({ error: 'Failed to fetch gifts' });
  }
});

// POST /api/gifts/send
app.post('/api/gifts/send', authenticateToken, async (req, res) => {
  try {
    const { gift_id, to_user_id, stream_id, battle_id } = req.body;
    if (!gift_id || !to_user_id) {
      return res.status(400).json({ error: 'gift_id and to_user_id are required' });
    }

    // Get gift details
    const giftResult = await query('SELECT * FROM gifts WHERE id = $1', [gift_id]);
    if (giftResult.rows.length === 0) return res.status(404).json({ error: 'Gift not found' });

    const gift = giftResult.rows[0];

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Check sender balance
      const senderWallet = await client.query('SELECT * FROM wallets WHERE user_id = $1 FOR UPDATE', [req.user.id]);
      if (senderWallet.rows.length === 0 || senderWallet.rows[0].balance < gift.cost) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'Insufficient balance' });
      }

      // Ensure recipient wallet
      const recipientWallet = await client.query('SELECT * FROM wallets WHERE user_id = $1 FOR UPDATE', [to_user_id]);
      if (recipientWallet.rows.length === 0) {
        await client.query('INSERT INTO wallets (id, user_id, balance, created_at) VALUES ($1, $2, 0, NOW())', [uuidv4(), to_user_id]);
      }

      // Transfer
      await client.query('UPDATE wallets SET balance = balance - $1 WHERE user_id = $2', [gift.cost, req.user.id]);
      await client.query('UPDATE wallets SET balance = balance + $1 WHERE user_id = $2', [gift.cost, to_user_id]);
      await client.query('UPDATE users SET coins = coins - $1 WHERE id = $2', [gift.cost, req.user.id]);
      await client.query('UPDATE users SET coins = coins + $1 WHERE id = $2', [gift.cost, to_user_id]);

      // Record transaction
      await client.query(
        'INSERT INTO wallet_transactions (id, from_user, to_user, amount, gift_type, created_at) VALUES ($1, $2, $3, $4, $5, NOW())',
        [uuidv4(), req.user.id, to_user_id, gift.cost, gift.name]
      );

      await client.query('COMMIT');

      const giftEvent = {
        gift_id: gift.id,
        gift_name: gift.name,
        gift_emoji: gift.emoji,
        gift_animation: gift.animation,
        gift_cost: gift.cost,
        from_user_id: req.user.id,
        from_username: req.user.username,
        to_user_id,
        stream_id: stream_id || null,
        battle_id: battle_id || null
      };

      // Emit gift to stream viewers
      if (stream_id) {
        const stream = liveStreams.get(stream_id);
        if (stream) {
          stream.gifts_received.push(giftEvent);
          stream.total_gift_value += gift.cost;
        }
        io.to(`stream:${stream_id}`).emit('gift_received', giftEvent);
      }

      // If battle gift, add to battle score
      if (battle_id) {
        const battle = liveBattles.get(battle_id);
        if (battle && battle.status === 'active') {
          if (to_user_id === battle.challenger_id) {
            battle.challenger_score += gift.cost;
            battle.challenger_gifts.push(giftEvent);
          } else if (to_user_id === battle.opponent_id) {
            battle.opponent_score += gift.cost;
            battle.opponent_gifts.push(giftEvent);
          }
          io.to(`stream:${battle.challenger_stream_id}`).emit('battle_score_update', {
            battle_id: battle.id,
            challenger_score: battle.challenger_score,
            opponent_score: battle.opponent_score
          });
          io.to(`stream:${battle.opponent_stream_id}`).emit('battle_score_update', {
            battle_id: battle.id,
            challenger_score: battle.challenger_score,
            opponent_score: battle.opponent_score
          });
        }
      }

      // Notify recipient
      io.to(`user:${to_user_id}`).emit('gift_received', giftEvent);

      res.json({ success: true, gift: giftEvent });
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  } catch (err) {
    console.error('[Gift Send Error]', err);
    res.status(500).json({ error: 'Failed to send gift' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// SOCIAL - FOLLOW & SEARCH
// ═══════════════════════════════════════════════════════════════════════════════

// POST /api/users/:id/follow
app.post('/api/users/:id/follow', authenticateToken, async (req, res) => {
  try {
    const targetId = req.params.id;
    if (targetId === req.user.id) return res.status(400).json({ error: 'Cannot follow yourself' });

    const existing = await query(
      'SELECT 1 FROM follows WHERE follower_id = $1 AND following_id = $2',
      [req.user.id, targetId]
    );

    if (existing.rows.length > 0) {
      // Unfollow
      await query('DELETE FROM follows WHERE follower_id = $1 AND following_id = $2', [req.user.id, targetId]);
      res.json({ success: true, following: false });
    } else {
      // Follow
      await query('INSERT INTO follows (follower_id, following_id, created_at) VALUES ($1, $2, NOW())', [req.user.id, targetId]);

      // Notify
      io.to(`user:${targetId}`).emit('new_follower', {
        follower_id: req.user.id,
        follower_username: req.user.username
      });

      res.json({ success: true, following: true });
    }
  } catch (err) {
    console.error('[Follow Error]', err);
    res.status(500).json({ error: 'Failed to follow/unfollow' });
  }
});

// GET /api/users/:id/followers
app.get('/api/users/:id/followers', async (req, res) => {
  try {
    const result = await query(
      `SELECT u.id, u.username, u.avatar, u.bio FROM follows f
       JOIN users u ON f.follower_id = u.id
       WHERE f.following_id = $1
       ORDER BY f.created_at DESC`,
      [req.params.id]
    );
    res.json({ success: true, followers: result.rows });
  } catch (err) {
    console.error('[Followers Error]', err);
    res.status(500).json({ error: 'Failed to fetch followers' });
  }
});

// GET /api/users/:id/following
app.get('/api/users/:id/following', async (req, res) => {
  try {
    const result = await query(
      `SELECT u.id, u.username, u.avatar, u.bio FROM follows f
       JOIN users u ON f.following_id = u.id
       WHERE f.follower_id = $1
       ORDER BY f.created_at DESC`,
      [req.params.id]
    );
    res.json({ success: true, following: result.rows });
  } catch (err) {
    console.error('[Following Error]', err);
    res.status(500).json({ error: 'Failed to fetch following' });
  }
});

// GET /api/search
app.get('/api/search', async (req, res) => {
  try {
    const { q, type } = req.query;
    if (!q) return res.status(400).json({ error: 'Search query is required' });

    const searchTerm = `%${q.toLowerCase()}%`;

    if (type === 'videos' || !type) {
      const videos = await query(
        `SELECT v.*, u.username, u.avatar FROM videos v
         JOIN users u ON v.user_id = u.id
         WHERE LOWER(v.description) LIKE $1 OR $2 = ANY(v.hashtags)
         ORDER BY v.views DESC LIMIT 20`,
        [searchTerm, q.toLowerCase()]
      );

      if (type === 'videos') return res.json({ success: true, videos: videos.rows });
    }

    const users = await query(
      `SELECT id, username, avatar, bio FROM users
       WHERE LOWER(username) LIKE $1 OR LOWER(bio) LIKE $1
       LIMIT 20`,
      [searchTerm]
    );

    if (type === 'users') return res.json({ success: true, users: users.rows });

    // Return both
    const videos = await query(
      `SELECT v.*, u.username, u.avatar FROM videos v
       JOIN users u ON v.user_id = u.id
       WHERE LOWER(v.description) LIKE $1
       ORDER BY v.views DESC LIMIT 20`,
      [searchTerm]
    );

    res.json({ success: true, users: users.rows, videos: videos.rows });
  } catch (err) {
    console.error('[Search Error]', err);
    res.status(500).json({ error: 'Search failed' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// HEALTH CHECK
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/health', async (req, res) => {
  try {
    const dbCheck = await query('SELECT NOW()');
    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      database: 'connected',
      db_time: dbCheck.rows[0].now,
      active_streams: liveStreams.size / 2, // divide by 2 because we store both streamId and user:id keys
      active_battles: liveBattles.size,
      memory: {
        rss: `${Math.round(process.memoryUsage().rss / 1024 / 1024)}MB`,
        heap: `${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)}MB`
      }
    });
  } catch (err) {
    res.status(503).json({
      status: 'unhealthy',
      database: 'disconnected',
      error: err.message
    });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// SOCKET.IO - REAL-TIME ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

// Online users tracking
const onlineUsers = new Map(); // socketId -> userData
const userSockets = new Map(); // userId -> Set<socketId>

io.on('connection', (socket) => {
  console.log(`[Socket] Connected: ${socket.id}`);

  // ─── Authentication ──────────────────────────────────────────────────
  socket.on('authenticate', (data) => {
    try {
      const decoded = jwt.verify(data.token, JWT_SECRET);
      socket.userId = decoded.id;
      socket.username = decoded.username;

      // Join personal room
      socket.join(`user:${decoded.id}`);

      // Track online status
      onlineUsers.set(socket.id, { id: decoded.id, username: decoded.username });
      if (!userSockets.has(decoded.id)) userSockets.set(decoded.id, new Set());
      userSockets.get(decoded.id).add(socket.id);

      socket.emit('authenticated', { success: true, userId: decoded.id });
      io.emit('user_online', { user_id: decoded.id, username: decoded.username });

      console.log(`[Socket] Authenticated: ${decoded.username} (${decoded.id})`);
    } catch (err) {
      socket.emit('auth_error', { error: 'Invalid token' });
    }
  });

  // ─── Chat / DM ───────────────────────────────────────────────────────
  socket.on('join_chat', (chatId) => {
    socket.join(`chat:${chatId}`);
    console.log(`[Socket] ${socket.username || socket.id} joined chat:${chatId}`);
  });

  socket.on('leave_chat', (chatId) => {
    socket.leave(`chat:${chatId}`);
  });

  socket.on('typing', (data) => {
    socket.to(`chat:${data.chat_id}`).emit('user_typing', {
      user_id: socket.userId,
      username: socket.username,
      chat_id: data.chat_id
    });
  });

  socket.on('stop_typing', (data) => {
    socket.to(`chat:${data.chat_id}`).emit('user_stop_typing', {
      user_id: socket.userId,
      chat_id: data.chat_id
    });
  });

  // ─── Real-time messaging via socket ──────────────────────────────────
  socket.on('send_message', async (data) => {
    try {
      if (!socket.userId) return socket.emit('error', { message: 'Not authenticated' });

      const msgId = uuidv4();
      const chatId = data.chat_id;
      const content = data.content;
      const msgType = data.msg_type || 'text';

      await query(
        'INSERT INTO messages (id, chat_id, sender_id, content, msg_type, created_at) VALUES ($1, $2, $3, $4, $5, NOW())',
        [msgId, chatId, socket.userId, content, msgType]
      );

      const msg = {
        id: msgId,
        chat_id: chatId,
        sender_id: socket.userId,
        username: socket.username,
        content,
        msg_type: msgType,
        created_at: new Date().toISOString()
      };

      io.to(`chat:${chatId}`).emit('new_message', msg);
    } catch (err) {
      console.error('[Socket Message Error]', err);
      socket.emit('error', { message: 'Failed to send message' });
    }
  });

  // ─── Video/Voice Call Signaling ──────────────────────────────────────
  socket.on('call_offer', (data) => {
    // data: { target_id, offer (SDP), call_type }
    io.to(`user:${data.target_id}`).emit('call_offer', {
      from_id: socket.userId,
      from_username: socket.username,
      offer: data.offer,
      call_type: data.call_type || 'video'
    });
  });

  socket.on('call_answer', (data) => {
    // data: { target_id, answer (SDP) }
    io.to(`user:${data.target_id}`).emit('call_answer', {
      from_id: socket.userId,
      answer: data.answer
    });
  });

  socket.on('ice_candidate', (data) => {
    // data: { target_id, candidate }
    io.to(`user:${data.target_id}`).emit('ice_candidate', {
      from_id: socket.userId,
      candidate: data.candidate
    });
  });

  socket.on('call_reject', (data) => {
    io.to(`user:${data.target_id}`).emit('call_rejected', {
      from_id: socket.userId,
      reason: data.reason || 'rejected'
    });
  });

  socket.on('call_hangup', (data) => {
    io.to(`user:${data.target_id}`).emit('call_hangup', {
      from_id: socket.userId
    });
  });

  // ─── Live Stream ─────────────────────────────────────────────────────
  socket.on('join_stream', (streamId) => {
    socket.join(`stream:${streamId}`);
    const stream = liveStreams.get(streamId);
    if (stream && typeof stream === 'object') {
      if (socket.userId) stream.viewer_list.add(socket.userId);
      stream.viewers = stream.viewer_list.size;
      io.to(`stream:${streamId}`).emit('viewer_count', {
        stream_id: streamId,
        viewers: stream.viewers
      });
    }
    console.log(`[Socket] ${socket.username || socket.id} joined stream:${streamId}`);
  });

  socket.on('leave_stream', (streamId) => {
    socket.leave(`stream:${streamId}`);
    const stream = liveStreams.get(streamId);
    if (stream && typeof stream === 'object') {
      if (socket.userId) stream.viewer_list.delete(socket.userId);
      stream.viewers = stream.viewer_list.size;
      io.to(`stream:${streamId}`).emit('viewer_count', {
        stream_id: streamId,
        viewers: stream.viewers
      });
    }
  });

  socket.on('stream_chat', (data) => {
    // data: { stream_id, message }
    io.to(`stream:${data.stream_id}`).emit('stream_chat_message', {
      user_id: socket.userId,
      username: socket.username,
      message: data.message,
      timestamp: new Date().toISOString()
    });
  });

  // ─── Battle Events ──────────────────────────────────────────────────
  socket.on('join_battle', (battleId) => {
    socket.join(`battle:${battleId}`);
  });

  socket.on('battle_reaction', (data) => {
    // data: { battle_id, reaction }
    io.to(`battle:${data.battle_id}`).emit('battle_reaction', {
      user_id: socket.userId,
      username: socket.username,
      reaction: data.reaction
    });
  });

  // ─── Disconnect ──────────────────────────────────────────────────────
  socket.on('disconnect', () => {
    const userData = onlineUsers.get(socket.id);
    if (userData) {
      const sockets = userSockets.get(userData.id);
      if (sockets) {
        sockets.delete(socket.id);
        if (sockets.size === 0) {
          userSockets.delete(userData.id);
          io.emit('user_offline', { user_id: userData.id });
        }
      }

      // Remove from any streams
      for (const [key, stream] of liveStreams.entries()) {
        if (typeof stream === 'object' && stream.viewer_list) {
          if (stream.viewer_list.delete(userData.id)) {
            stream.viewers = stream.viewer_list.size;
            io.to(`stream:${stream.id}`).emit('viewer_count', {
              stream_id: stream.id,
              viewers: stream.viewers
            });
          }
        }
      }
    }
    onlineUsers.delete(socket.id);
    console.log(`[Socket] Disconnected: ${socket.id}`);
  });
});

// ─── Get Online Users ────────────────────────────────────────────────────────
app.get('/api/users/online', (req, res) => {
  const online = [];
  const seen = new Set();
  for (const [, data] of onlineUsers.entries()) {
    if (!seen.has(data.id)) {
      seen.add(data.id);
      online.push({ id: data.id, username: data.username });
    }
  }
  res.json({ success: true, online_users: online, count: online.length });
});

// ═══════════════════════════════════════════════════════════════════════════════
// SPA FALLBACK
// ═══════════════════════════════════════════════════════════════════════════════
app.get('*', (req, res) => {
  const indexPath = path.join(__dirname, 'frontend', 'index.html');
  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    res.status(404).json({ error: 'Not found' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// GLOBAL ERROR HANDLER
// ═══════════════════════════════════════════════════════════════════════════════
app.use((err, req, res, next) => {
  console.error('[Global Error]', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ═══════════════════════════════════════════════════════════════════════════════
// START SERVER
// ═══════════════════════════════════════════════════════════════════════════════
server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n═══════════════════════════════════════════`);
  console.log(`  NVME Live Platform Server`);
  console.log(`  Port: ${PORT}`);
  console.log(`  Database: PostgreSQL connected`);
  console.log(`  Socket.io: Real-time enabled`);
  console.log(`  Features:`);
  console.log(`    ✓ TikTok Feed & Video Upload`);
  console.log(`    ✓ Instagram Feed & Posts`);
  console.log(`    ✓ WhatsApp DMs & Video Calling`);
  console.log(`    ✓ YouTube Live Streaming`);
  console.log(`    ✓ Live Battles System`);
  console.log(`    ✓ Wallet & Gift Economy`);
  console.log(`    ✓ Social Follow System`);
  console.log(`    ✓ Real-time Notifications`);
  console.log(`═══════════════════════════════════════════\n`);
});

module.exports = { app, server, io };
