const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] }
});

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const JWT_SECRET = process.env.JWT_SECRET || 'nvme-secret-change-me';

app.use(cors());
app.use(express.json());

// ── Auth Middleware ───────────────────────────────────────────────────────────
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
};

// ── Health ────────────────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({
  status: 'ok',
  service: 'NVME.live',
  version: '1.0.0',
  timestamp: new Date().toISOString(),
  features: ['video', 'live', 'gifts', 'earnings', 'creators']
}));

// ── Creators ──────────────────────────────────────────────────────────────────
app.get('/api/creators', async (req, res) => {
  try {
    const { niche, limit = 20, offset = 0 } = req.query;
    let query = `SELECT id, name, niche, bio, tagline, avatar_url, 
                 subscriber_count, video_count, total_views, is_live,
                 subscription_price, created_at
                 FROM nvme_creators WHERE is_active = true`;
    const params = [];
    if (niche) { params.push(niche); query += ` AND niche = $${params.length}`; }
    params.push(limit, offset);
    query += ` ORDER BY subscriber_count DESC LIMIT $${params.length - 1} OFFSET $${params.length}`;
    const result = await pool.query(query, params);
    res.json({ creators: result.rows, total: result.rowCount });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/creators/:id', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT c.*, 
       COUNT(DISTINCT v.id) as video_count,
       COALESCE(SUM(v.views), 0) as total_views
       FROM nvme_creators c
       LEFT JOIN nvme_videos v ON v.creator_id = c.id
       WHERE c.id = $1 GROUP BY c.id`,
      [req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Creator not found' });
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── Videos ────────────────────────────────────────────────────────────────────
app.get('/api/videos', async (req, res) => {
  try {
    const { creator_id, limit = 20, offset = 0, sort = 'recent' } = req.query;
    const orderMap = {
      recent: 'v.created_at DESC',
      popular: 'v.views DESC',
      trending: 'v.likes DESC'
    };
    let query = `SELECT v.id, v.title, v.description, v.thumbnail_url,
                 v.video_url, v.duration, v.views, v.likes, v.is_free,
                 v.price, v.created_at,
                 c.name as creator_name, c.id as creator_id
                 FROM nvme_videos v
                 JOIN nvme_creators c ON c.id = v.creator_id
                 WHERE v.is_published = true`;
    const params = [];
    if (creator_id) { params.push(creator_id); query += ` AND v.creator_id = $${params.length}`; }
    query += ` ORDER BY ${orderMap[sort] || orderMap.recent}`;
    params.push(limit, offset);
    query += ` LIMIT $${params.length - 1} OFFSET $${params.length}`;
    const result = await pool.query(query, params);
    res.json({ videos: result.rows, total: result.rowCount });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/videos/:id', async (req, res) => {
  try {
    await pool.query('UPDATE nvme_videos SET views = views + 1 WHERE id = $1', [req.params.id]);
    const result = await pool.query(
      `SELECT v.*, c.name as creator_name, c.avatar_url as creator_avatar
       FROM nvme_videos v JOIN nvme_creators c ON c.id = v.creator_id WHERE v.id = $1`,
      [req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Video not found' });
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/videos/:id/like', auth, async (req, res) => {
  try {
    await pool.query('UPDATE nvme_videos SET likes = likes + 1 WHERE id = $1', [req.params.id]);
    await pool.query(
      'INSERT INTO nvme_video_likes (video_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
      [req.params.id, req.user.id]
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── Live Streams ──────────────────────────────────────────────────────────────
app.get('/api/live', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT l.*, c.name as creator_name, c.avatar_url,
       COUNT(DISTINCT lv.user_id) as viewer_count,
       COALESCE(SUM(g.amount), 0) as total_gifts
       FROM nvme_live_streams l
       JOIN nvme_creators c ON c.id = l.creator_id
       LEFT JOIN nvme_live_viewers lv ON lv.stream_id = l.id
       LEFT JOIN nvme_gifts g ON g.stream_id = l.id
       WHERE l.is_active = true
       GROUP BY l.id, c.name, c.avatar_url
       ORDER BY viewer_count DESC`
    );
    res.json({ streams: result.rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/live/start', auth, async (req, res) => {
  try {
    const { title, description } = req.body;
    const streamKey = 'nvme_' + Math.random().toString(36).substr(2, 16);
    const result = await pool.query(
      `INSERT INTO nvme_live_streams (creator_id, title, description, stream_key, is_active, started_at)
       VALUES ($1, $2, $3, $4, true, NOW()) RETURNING *`,
      [req.user.id, title, description, streamKey]
    );
    await pool.query('UPDATE nvme_creators SET is_live = true WHERE id = $1', [req.user.id]);
    io.emit('stream:started', { stream: result.rows[0] });
    res.json({ stream: result.rows[0], stream_key: streamKey });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/live/:id/end', auth, async (req, res) => {
  try {
    await pool.query(
      `UPDATE nvme_live_streams SET is_active = false, ended_at = NOW() WHERE id = $1`,
      [req.params.id]
    );
    await pool.query('UPDATE nvme_creators SET is_live = false WHERE id = $1', [req.user.id]);
    io.emit('stream:ended', { stream_id: req.params.id });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── Gifts ─────────────────────────────────────────────────────────────────────
const GIFT_TYPES = {
  rose:     { name: 'Rose',       emoji: '🌹', coins: 1,    usd: 0.01  },
  heart:    { name: 'Heart',      emoji: '❤️',  coins: 10,   usd: 0.10  },
  star:     { name: 'Star',       emoji: '⭐',  coins: 50,   usd: 0.50  },
  diamond:  { name: 'Diamond',    emoji: '💎',  coins: 100,  usd: 1.00  },
  crown:    { name: 'Crown',      emoji: '👑',  coins: 500,  usd: 5.00  },
  rocket:   { name: 'Rocket',     emoji: '🚀',  coins: 1000, usd: 10.00 },
  galaxy:   { name: 'Galaxy',     emoji: '🌌',  coins: 5000, usd: 50.00 },
  empire:   { name: 'Empire',     emoji: '🏆',  coins: 10000,usd: 100.00}
};

app.get('/api/gifts/types', (req, res) => res.json({ gifts: GIFT_TYPES }));

app.post('/api/gifts/send', auth, async (req, res) => {
  try {
    const { stream_id, creator_id, gift_type, message } = req.body;
    const gift = GIFT_TYPES[gift_type];
    if (!gift) return res.status(400).json({ error: 'Invalid gift type' });

    const result = await pool.query(
      `INSERT INTO nvme_gifts (user_id, creator_id, stream_id, gift_type, amount, coins, message, sent_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW()) RETURNING *`,
      [req.user.id, creator_id, stream_id, gift_type, gift.usd, gift.coins, message]
    );

    // 90% to creator
    const creatorEarning = gift.usd * 0.90;
    await pool.query(
      `UPDATE nvme_creators SET total_earnings = total_earnings + $1 WHERE id = $2`,
      [creatorEarning, creator_id]
    );

    const giftEvent = {
      ...result.rows[0],
      gift_name: gift.name,
      gift_emoji: gift.emoji,
      sender_id: req.user.id
    };

    io.to(`stream:${stream_id}`).emit('gift:received', giftEvent);
    io.to(`creator:${creator_id}`).emit('gift:received', giftEvent);

    res.json({ success: true, gift: giftEvent });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── Earnings ──────────────────────────────────────────────────────────────────
app.get('/api/earnings', auth, async (req, res) => {
  try {
    const { period = '30' } = req.query;
    const result = await pool.query(
      `SELECT 
        COALESCE(SUM(CASE WHEN type='subscription' THEN amount END), 0) as subscription_revenue,
        COALESCE(SUM(CASE WHEN type='ppv' THEN amount END), 0) as ppv_revenue,
        COALESCE(SUM(CASE WHEN type='gift' THEN amount END), 0) as gift_revenue,
        COALESCE(SUM(CASE WHEN type='tip' THEN amount END), 0) as tip_revenue,
        COALESCE(SUM(amount), 0) as total_revenue,
        COUNT(*) as transaction_count
       FROM nvme_earnings
       WHERE creator_id = $1 AND created_at >= NOW() - INTERVAL '${parseInt(period)} days'`,
      [req.user.id]
    );

    const daily = await pool.query(
      `SELECT DATE(created_at) as date, SUM(amount) as revenue
       FROM nvme_earnings WHERE creator_id = $1
       AND created_at >= NOW() - INTERVAL '${parseInt(period)} days'
       GROUP BY DATE(created_at) ORDER BY date ASC`,
      [req.user.id]
    );

    const pending = await pool.query(
      `SELECT COALESCE(SUM(amount * 0.90), 0) as pending_payout
       FROM nvme_earnings WHERE creator_id = $1 AND paid_out = false`,
      [req.user.id]
    );

    res.json({
      summary: result.rows[0],
      daily_breakdown: daily.rows,
      pending_payout: pending.rows[0].pending_payout,
      payout_rate: 0.90
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/earnings/leaderboard', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT c.id, c.name, c.avatar_url, c.niche,
       COALESCE(SUM(e.amount), 0) as total_earnings,
       c.subscriber_count
       FROM nvme_creators c
       LEFT JOIN nvme_earnings e ON e.creator_id = c.id
       WHERE c.is_active = true
       GROUP BY c.id ORDER BY total_earnings DESC LIMIT 10`
    );
    res.json({ leaderboard: result.rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── Subscriptions ─────────────────────────────────────────────────────────────
app.post('/api/subscriptions/subscribe', auth, async (req, res) => {
  try {
    const { creator_id } = req.body;
    const creator = await pool.query('SELECT * FROM nvme_creators WHERE id = $1', [creator_id]);
    if (!creator.rows.length) return res.status(404).json({ error: 'Creator not found' });

    const existing = await pool.query(
      'SELECT id FROM nvme_subscriptions WHERE user_id = $1 AND creator_id = $2 AND is_active = true',
      [req.user.id, creator_id]
    );
    if (existing.rows.length) return res.status(409).json({ error: 'Already subscribed' });

    const sub = await pool.query(
      `INSERT INTO nvme_subscriptions (user_id, creator_id, amount, started_at, expires_at, is_active)
       VALUES ($1, $2, $3, NOW(), NOW() + INTERVAL '30 days', true) RETURNING *`,
      [req.user.id, creator_id, creator.rows[0].subscription_price]
    );

    await pool.query(
      'UPDATE nvme_creators SET subscriber_count = subscriber_count + 1 WHERE id = $1',
      [creator_id]
    );

    await pool.query(
      `INSERT INTO nvme_earnings (creator_id, type, amount, description, created_at)
       VALUES ($1, 'subscription', $2, 'New subscriber', NOW())`,
      [creator_id, creator.rows[0].subscription_price * 0.85]
    );

    res.json({ subscription: sub.rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── WebSocket ─────────────────────────────────────────────────────────────────
io.on('connection', (socket) => {
  console.log('[NVME] Socket connected:', socket.id);

  socket.on('join:stream', ({ stream_id, user_id }) => {
    socket.join(`stream:${stream_id}`);
    socket.to(`stream:${stream_id}`).emit('viewer:joined', { user_id, count: io.sockets.adapter.rooms.get(`stream:${stream_id}`)?.size || 0 });
    pool.query('INSERT INTO nvme_live_viewers (stream_id, user_id, joined_at) VALUES ($1, $2, NOW()) ON CONFLICT DO NOTHING', [stream_id, user_id]).catch(() => {});
  });

  socket.on('leave:stream', ({ stream_id, user_id }) => {
    socket.leave(`stream:${stream_id}`);
    socket.to(`stream:${stream_id}`).emit('viewer:left', { user_id });
  });

  socket.on('join:creator', ({ creator_id }) => {
    socket.join(`creator:${creator_id}`);
  });

  socket.on('stream:chat', ({ stream_id, user_id, message, username }) => {
    io.to(`stream:${stream_id}`).emit('stream:chat', {
      user_id, username, message,
      timestamp: new Date().toISOString()
    });
  });

  socket.on('disconnect', () => {
    console.log('[NVME] Socket disconnected:', socket.id);
  });
});

// ── DB Schema Init ────────────────────────────────────────────────────────────
async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS nvme_creators (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID,
        name VARCHAR(100) NOT NULL,
        niche VARCHAR(100),
        bio TEXT,
        tagline VARCHAR(200),
        avatar_url TEXT,
        banner_url TEXT,
        subscription_price DECIMAL(10,2) DEFAULT 9.99,
        subscriber_count INT DEFAULT 0,
        video_count INT DEFAULT 0,
        total_views BIGINT DEFAULT 0,
        total_earnings DECIMAL(12,2) DEFAULT 0,
        is_live BOOLEAN DEFAULT false,
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS nvme_videos (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        creator_id UUID REFERENCES nvme_creators(id),
        title VARCHAR(200) NOT NULL,
        description TEXT,
        video_url TEXT,
        thumbnail_url TEXT,
        duration INT DEFAULT 0,
        views BIGINT DEFAULT 0,
        likes INT DEFAULT 0,
        is_free BOOLEAN DEFAULT false,
        price DECIMAL(10,2) DEFAULT 0,
        is_published BOOLEAN DEFAULT true,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS nvme_live_streams (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        creator_id UUID REFERENCES nvme_creators(id),
        title VARCHAR(200),
        description TEXT,
        stream_key VARCHAR(100) UNIQUE,
        is_active BOOLEAN DEFAULT false,
        viewer_peak INT DEFAULT 0,
        started_at TIMESTAMPTZ,
        ended_at TIMESTAMPTZ
      );

      CREATE TABLE IF NOT EXISTS nvme_live_viewers (
        stream_id UUID REFERENCES nvme_live_streams(id),
        user_id UUID,
        joined_at TIMESTAMPTZ DEFAULT NOW(),
        PRIMARY KEY (stream_id, user_id)
      );

      CREATE TABLE IF NOT EXISTS nvme_gifts (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL,
        creator_id UUID REFERENCES nvme_creators(id),
        stream_id UUID REFERENCES nvme_live_streams(id),
        gift_type VARCHAR(50),
        amount DECIMAL(10,2),
        coins INT,
        message TEXT,
        sent_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS nvme_earnings (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        creator_id UUID REFERENCES nvme_creators(id),
        type VARCHAR(50),
        amount DECIMAL(10,2),
        description TEXT,
        paid_out BOOLEAN DEFAULT false,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS nvme_subscriptions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL,
        creator_id UUID REFERENCES nvme_creators(id),
        amount DECIMAL(10,2),
        started_at TIMESTAMPTZ DEFAULT NOW(),
        expires_at TIMESTAMPTZ,
        is_active BOOLEAN DEFAULT true
      );

      CREATE TABLE IF NOT EXISTS nvme_video_likes (
        video_id UUID REFERENCES nvme_videos(id),
        user_id UUID,
        PRIMARY KEY (video_id, user_id)
      );
    `);

    // Seed creators from our 29 profiles
    const existingCreators = await pool.query('SELECT COUNT(*) FROM nvme_creators');
    if (parseInt(existingCreators.rows[0].count) === 0) {
      const creators = [
        { name: 'Luna Voss', niche: 'Lifestyle & Fashion', bio: 'London-based AI lifestyle creator.', tagline: 'Life is the ultimate luxury.', price: 29 },
        { name: 'Jax Cyber', niche: 'Tech & Gaming', bio: 'Breaking tech, building futures.', tagline: 'The future is already here.', price: 19 },
        { name: 'Sienna Gold', niche: 'Fitness & Wellness', bio: 'Sydney girl building her best body.', tagline: 'Strong is the new everything.', price: 24 },
        { name: 'Crypto Kai', niche: 'Crypto & DeFi', bio: 'Turned $5K into $2M in 3 years.', tagline: 'Alpha or nothing.', price: 49 },
        { name: 'Marcus Fit', niche: 'Bodybuilding', bio: 'IFBB-trained physique coach.', tagline: 'Your body is your business.', price: 34 },
        { name: 'Velvet Vox', niche: 'Music & Voice', bio: 'Classically trained voice. Contemporary soul.', tagline: 'Let my voice find you.', price: 29 },
        { name: 'Duke Drops', niche: 'Luxury Lifestyle', bio: 'Documenting the 1% lifestyle.', tagline: 'Excellence is a lifestyle.', price: 39 },
        { name: 'Tony Trades', niche: 'Stock Trading', bio: 'Ex-Goldman. Now trading for myself.', tagline: 'The market rewards the prepared.', price: 49 },
      ];
      for (const c of creators) {
        await pool.query(
          `INSERT INTO nvme_creators (name, niche, bio, tagline, subscription_price, subscriber_count)
           VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING`,
          [c.name, c.niche, c.bio, c.tagline, c.price, Math.floor(Math.random() * 10000 + 500)]
        );
      }
      console.log('[NVME] Seeded 8 creators');
    }

    console.log('[NVME] Database ready');
  } catch (err) {
    console.error('[NVME] DB init error:', err.message);
  }
}

const PORT = process.env.NVME_PORT || 4000;
server.listen(PORT, async () => {
  await initDB();
  console.log(`[NVME] Running on port ${PORT}`);
  console.log(`[NVME] Routes: /health /api/creators /api/videos /api/live /api/gifts /api/earnings /api/subscriptions`);
});

module.exports = { app, io };
