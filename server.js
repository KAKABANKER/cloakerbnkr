const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const { Pool } = require('pg');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'cloakup_secret_key_2024';

// CONEXÃO POSTGRESQL - COLOQUE SUA STRING AQUI
const pool = new Pool({
  connectionString: 'postgresql://cloaker_db_user:kJTmzI74aNVzjvLHetCPFegRbPTTgMAE@dpg-d8hk90a8qa3s73diog4g-a.oregon-postgres.render.com/cloaker_db',
  ssl: { rejectUnauthorized: false }
});

app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use('/api/', limiter);

// CRIAR TABELAS NO POSTGRESQL
async function initDatabase() {
  try {
    // Tabela de usuários
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id VARCHAR(255) PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        name VARCHAR(255),
        role VARCHAR(50) DEFAULT 'user',
        plan VARCHAR(50) DEFAULT 'free',
        credits INTEGER DEFAULT 100,
        status VARCHAR(50) DEFAULT 'active',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Tabela de campanhas
    await pool.query(`
      CREATE TABLE IF NOT EXISTS campaigns (
        id VARCHAR(255) PRIMARY KEY,
        user_id VARCHAR(255) REFERENCES users(id),
        name VARCHAR(255) NOT NULL,
        safe_url TEXT NOT NULL,
        real_url TEXT NOT NULL,
        views INTEGER DEFAULT 0,
        bot_views INTEGER DEFAULT 0,
        status VARCHAR(50) DEFAULT 'active',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Tabela de logs
    await pool.query(`
      CREATE TABLE IF NOT EXISTS logs (
        id VARCHAR(255) PRIMARY KEY,
        campaign_id VARCHAR(255) REFERENCES campaigns(id),
        user_id VARCHAR(255) REFERENCES users(id),
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        ip VARCHAR(255),
        user_agent TEXT,
        should_cloak BOOLEAN,
        risk INTEGER,
        reason TEXT
      )
    `);

    console.log('PostgreSQL tables ready');
  } catch(err) {
    console.error('Database init error:', err);
  }
}

initDatabase();

const botPatterns = [
  { pattern: /googlebot/i, name: 'Googlebot', risk: 100 },
  { pattern: /bingbot/i, name: 'Bingbot', risk: 100 },
  { pattern: /slurp/i, name: 'Yahoo Slurp', risk: 100 },
  { pattern: /duckduckbot/i, name: 'DuckDuckGo', risk: 100 },
  { pattern: /baiduspider/i, name: 'Baidu', risk: 100 },
  { pattern: /yandex/i, name: 'Yandex', risk: 100 },
  { pattern: /facebookexternalhit/i, name: 'Facebook', risk: 95 },
  { pattern: /twitterbot/i, name: 'Twitter', risk: 95 },
  { pattern: /linkedinbot/i, name: 'LinkedIn', risk: 95 },
  { pattern: /pinterest/i, name: 'Pinterest', risk: 95 },
  { pattern: /ahrefs/i, name: 'Ahrefs', risk: 100 },
  { pattern: /semrush/i, name: 'Semrush', risk: 100 },
  { pattern: /mj12bot/i, name: 'Majestic', risk: 100 },
  { pattern: /rogerbot/i, name: 'Rogerbot', risk: 100 },
  { pattern: /dotbot/i, name: 'Dotbot', risk: 100 },
  { pattern: /headless/i, name: 'Headless', risk: 100 },
  { pattern: /puppeteer/i, name: 'Puppeteer', risk: 100 },
  { pattern: /selenium/i, name: 'Selenium', risk: 100 },
  { pattern: /phantomjs/i, name: 'PhantomJS', risk: 100 },
  { pattern: /playwright/i, name: 'Playwright', risk: 100 }
];

const datacenterRanges = [
  '3.', '52.', '54.', '13.', '35.', '34.',
  '104.', '107.', '142.', '146.',
  '20.', '40.', '51.', '123.',
  '170.', '173.', '174.', '157.', '158.', '159.'
];

function analyzeRequest(req) {
  const userAgent = req.headers['user-agent'] || '';
  const ip = req.ip || req.headers['x-forwarded-for'] || '';
  const accept = req.headers['accept'] || '';
  const referer = req.headers['referer'] || '';
  
  let totalRisk = 0;
  let reasons = [];
  
  for (const bot of botPatterns) {
    if (bot.pattern.test(userAgent)) {
      totalRisk += bot.risk;
      reasons.push(bot.name);
      break;
    }
  }
  
  for (const range of datacenterRanges) {
    if (ip.startsWith(range)) {
      totalRisk += 85;
      reasons.push('Datacenter IP');
      break;
    }
  }
  
  if (accept.includes('application/json') && !accept.includes('text/html')) {
    totalRisk += 70;
    reasons.push('JSON Accept header');
  }
  
  if (!referer && process.env.NODE_ENV === 'production') {
    totalRisk += 50;
    reasons.push('No referer');
  }
  
  return {
    shouldCloak: totalRisk >= 60,
    risk: Math.min(totalRisk, 100),
    reason: reasons.join(', ') || 'Valid human'
  };
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Access denied' });
  }
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
}

function isAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

// REGISTER
app.post('/api/auth/register', async (req, res) => {
  const { email, password, name } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }
  
  try {
    const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'Email already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = uuidv4();
    
    await pool.query(
      'INSERT INTO users (id, email, password, name, role, plan, credits, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)',
      [userId, email, hashedPassword, name || email.split('@')[0], 'user', 'free', 100, 'active']
    );
    
    const token = jwt.sign(
      { id: userId, email: email, role: 'user' },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.json({
      success: true,
      token,
      user: { id: userId, email, name: name || email.split('@')[0], role: 'user', plan: 'free', credits: 100 }
    });
  } catch(err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// LOGIN
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    if (user.status !== 'active') {
      return res.status(401).json({ error: 'Account disabled' });
    }
    
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        plan: user.plan,
        credits: user.credits
      }
    });
  } catch(err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// CLOAKER ENDPOINT
app.get('/cloak/:campaignId', async (req, res) => {
  try {
    const campaignResult = await pool.query('SELECT * FROM campaigns WHERE id = $1', [req.params.campaignId]);
    const campaign = campaignResult.rows[0];
    
    if (!campaign) {
      return res.status(404).send('Campaign not found');
    }
    
    const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [campaign.user_id]);
    const user = userResult.rows[0];
    
    const analysis = analyzeRequest(req);
    
    const logId = uuidv4();
    await pool.query(
      'INSERT INTO logs (id, campaign_id, user_id, ip, user_agent, should_cloak, risk, reason) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)',
      [logId, campaign.id, campaign.user_id, req.ip || req.headers['x-forwarded-for'], req.headers['user-agent'], analysis.shouldCloak, analysis.risk, analysis.reason]
    );
    
    if (!analysis.shouldCloak && user) {
      await pool.query('UPDATE users SET credits = GREATEST(0, credits - 1) WHERE id = $1', [user.id]);
      await pool.query('UPDATE campaigns SET views = views + 1 WHERE id = $1', [campaign.id]);
    } else if (analysis.shouldCloak) {
      await pool.query('UPDATE campaigns SET bot_views = bot_views + 1 WHERE id = $1', [campaign.id]);
    }
    
    const targetUrl = analysis.shouldCloak ? campaign.safe_url : campaign.real_url;
    res.redirect(302, targetUrl);
  } catch(err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

// CREATE CAMPAIGN
app.post('/api/campaigns', authenticateToken, async (req, res) => {
  const { name, safeUrl, realUrl } = req.body;
  
  if (!name || !safeUrl || !realUrl) {
    return res.status(400).json({ error: 'All fields required' });
  }
  
  try {
    const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
    const user = userResult.rows[0];
    
    const userCampaignsResult = await pool.query('SELECT COUNT(*) FROM campaigns WHERE user_id = $1', [req.user.id]);
    const userCampaignsCount = parseInt(userCampaignsResult.rows[0].count);
    
    let maxCampaigns = 1;
    if (user.plan === 'pro') maxCampaigns = 10;
    if (user.plan === 'enterprise') maxCampaigns = 999;
    
    if (userCampaignsCount >= maxCampaigns) {
      return res.status(400).json({ error: `Campaign limit reached (${maxCampaigns})` });
    }
    
    const campaignId = uuidv4();
    await pool.query(
      'INSERT INTO campaigns (id, user_id, name, safe_url, real_url) VALUES ($1, $2, $3, $4, $5)',
      [campaignId, req.user.id, name, safeUrl, realUrl]
    );
    
    res.json({
      success: true,
      campaign: {
        id: campaignId,
        name: name,
        cloakUrl: `${req.protocol}://${req.get('host')}/cloak/${campaignId}`,
        views: 0,
        botViews: 0
      }
    });
  } catch(err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET CAMPAIGNS
app.get('/api/campaigns', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, safe_url, real_url, views, bot_views, created_at FROM campaigns WHERE user_id = $1',
      [req.user.id]
    );
    
    const campaigns = result.rows.map(c => ({
      id: c.id,
      name: c.name,
      safeUrl: c.safe_url,
      realUrl: c.real_url,
      views: c.views || 0,
      botViews: c.bot_views || 0,
      cloakUrl: `${req.protocol}://${req.get('host')}/cloak/${c.id}`,
      createdAt: c.created_at
    }));
    
    res.json(campaigns);
  } catch(err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// DELETE CAMPAIGN
app.delete('/api/campaigns/:id', authenticateToken, async (req, res) => {
  try {
    await pool.query('DELETE FROM campaigns WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
    res.json({ success: true });
  } catch(err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// STATS
app.get('/api/stats', authenticateToken, async (req, res) => {
  try {
    const campaignsResult = await pool.query(
      'SELECT COALESCE(SUM(views), 0) as total_views, COALESCE(SUM(bot_views), 0) as total_bots FROM campaigns WHERE user_id = $1',
      [req.user.id]
    );
    
    const campaignsCountResult = await pool.query('SELECT COUNT(*) FROM campaigns WHERE user_id = $1', [req.user.id]);
    
    const userResult = await pool.query('SELECT credits, plan FROM users WHERE id = $1', [req.user.id]);
    const user = userResult.rows[0];
    
    const logsResult = await pool.query(
      'SELECT id, timestamp, ip, should_cloak, risk, reason FROM logs WHERE user_id = $1 ORDER BY timestamp DESC LIMIT 20',
      [req.user.id]
    );
    
    const totalViews = parseInt(campaignsResult.rows[0].total_views);
    const totalBots = parseInt(campaignsResult.rows[0].total_bots);
    
    res.json({
      totalCampaigns: parseInt(campaignsCountResult.rows[0].count),
      totalViews,
      totalBots,
      blockRate: totalViews + totalBots > 0 ? ((totalBots / (totalViews + totalBots)) * 100).toFixed(1) : 0,
      credits: user ? user.credits : 0,
      plan: user ? user.plan : 'free',
      recentLogs: logsResult.rows.map(l => ({
        timestamp: l.timestamp,
        ip: l.ip,
        shouldCloak: l.should_cloak,
        risk: l.risk,
        reason: l.reason
      }))
    });
  } catch(err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ADMIN - GET USERS
app.get('/api/admin/users', authenticateToken, isAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, email, name, role, plan, credits, status, created_at FROM users');
    res.json(result.rows);
  } catch(err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ADMIN - UPDATE USER
app.put('/api/admin/users/:id', authenticateToken, isAdmin, async (req, res) => {
  const { plan, credits, status, role } = req.body;
  
  try {
    let query = 'UPDATE users SET ';
    const updates = [];
    const values = [];
    let idx = 1;
    
    if (plan) { updates.push(`plan = $${idx++}`); values.push(plan); }
    if (credits !== undefined) { updates.push(`credits = $${idx++}`); values.push(credits); }
    if (status) { updates.push(`status = $${idx++}`); values.push(status); }
    if (role) { updates.push(`role = $${idx++}`); values.push(role); }
    
    updates.push(`updated_at = CURRENT_TIMESTAMP`);
    query += updates.join(', ') + ` WHERE id = $${idx}`;
    values.push(req.params.id);
    
    await pool.query(query, values);
    res.json({ success: true });
  } catch(err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ADMIN - DELETE USER
app.delete('/api/admin/users/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM logs WHERE user_id = $1', [req.params.id]);
    await pool.query('DELETE FROM campaigns WHERE user_id = $1', [req.params.id]);
    await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch(err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ADMIN - STATS
app.get('/api/admin/stats', authenticateToken, isAdmin, async (req, res) => {
  try {
    const usersResult = await pool.query('SELECT COUNT(*) FROM users');
    const campaignsResult = await pool.query('SELECT COUNT(*) FROM campaigns');
    const logsResult = await pool.query('SELECT COUNT(*) FROM logs');
    const viewsResult = await pool.query('SELECT COALESCE(SUM(views), 0) as total_views, COALESCE(SUM(bot_views), 0) as total_bots FROM campaigns');
    
    const usersByPlanResult = await pool.query(`
      SELECT plan, COUNT(*) as count FROM users GROUP BY plan
    `);
    
    const usersByPlan = { free: 0, pro: 0, enterprise: 0 };
    usersByPlanResult.rows.forEach(row => {
      usersByPlan[row.plan] = parseInt(row.count);
    });
    
    res.json({
      totalUsers: parseInt(usersResult.rows[0].count),
      totalCampaigns: parseInt(campaignsResult.rows[0].count),
      totalLogs: parseInt(logsResult.rows[0].count),
      totalViews: parseInt(viewsResult.rows[0].total_views),
      totalBots: parseInt(viewsResult.rows[0].total_bots),
      usersByPlan,
      revenue: (usersByPlan.pro * 49.90) + (usersByPlan.enterprise * 199.90)
    });
  } catch(err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ADMIN - CAMPAIGNS
app.get('/api/admin/campaigns', authenticateToken, isAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT c.id, c.name, c.safe_url, c.real_url, c.views, c.bot_views, c.created_at, u.email as user_email
      FROM campaigns c
      JOIN users u ON c.user_id = u.id
      ORDER BY c.created_at DESC
    `);
    res.json(result.rows);
  } catch(err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ADMIN - LOGS
app.get('/api/admin/logs', authenticateToken, isAdmin, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 100;
    const result = await pool.query(
      'SELECT * FROM logs ORDER BY timestamp DESC LIMIT $1',
      [limit]
    );
    res.json(result.rows);
  } catch(err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// PLANS
app.get('/api/plans', (req, res) => {
  res.json([
    { id: 'free', name: 'Free', price: 0, credits: 100, features: ['1 campaign', '100 views/month'] },
    { id: 'pro', name: 'Pro', price: 49.90, credits: 5000, features: ['10 campaigns', '5000 views/month', 'Email support'] },
    { id: 'enterprise', name: 'Enterprise', price: 199.90, credits: 50000, features: ['Unlimited campaigns', '50000 views/month', 'Priority support', 'API access'] }
  ]);
});

// ROOT
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// CREATE ADMIN USER
async function createAdmin() {
  try {
    const adminExists = await pool.query('SELECT * FROM users WHERE role = $1', ['admin']);
    
    if (adminExists.rows.length === 0) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      const adminId = uuidv4();
      await pool.query(
        'INSERT INTO users (id, email, password, name, role, plan, credits, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)',
        [adminId, 'admin@cloakup.com', hashedPassword, 'Administrator', 'admin', 'enterprise', 999999, 'active']
      );
      console.log('Admin created: admin@cloakup.com / admin123');
    }
  } catch(err) {
    console.error('Error creating admin:', err);
  }
}

createAdmin();

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`PostgreSQL connected`);
  console.log(`Admin: admin@cloakup.com / admin123`);
});
