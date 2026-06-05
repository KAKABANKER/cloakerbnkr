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

app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://rsms.me"],
      styleSrcElem: ["'self'", "'unsafe-inline'", "https://rsms.me"],
      fontSrc: ["'self'", "https://rsms.me", "data:"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"],
    },
  },
}));

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use('/api/', limiter);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function initDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id VARCHAR(255) PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        name VARCHAR(255),
        role VARCHAR(50) DEFAULT 'user',
        plan VARCHAR(50) DEFAULT 'free',
        credits INTEGER DEFAULT 100,
        api_key VARCHAR(255),
        status VARCHAR(50) DEFAULT 'active',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS campaigns (
        id VARCHAR(255) PRIMARY KEY,
        user_id VARCHAR(255) REFERENCES users(id),
        name VARCHAR(255) NOT NULL,
        safe_url TEXT NOT NULL,
        real_url TEXT NOT NULL,
        views INTEGER DEFAULT 0,
        bot_views INTEGER DEFAULT 0,
        human_views INTEGER DEFAULT 0,
        spy_views INTEGER DEFAULT 0,
        status VARCHAR(50) DEFAULT 'active',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS logs (
        id VARCHAR(255) PRIMARY KEY,
        campaign_id VARCHAR(255) REFERENCES campaigns(id),
        user_id VARCHAR(255) REFERENCES users(id),
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        ip VARCHAR(255),
        user_agent TEXT,
        accept_header TEXT,
        accept_language TEXT,
        referer TEXT,
        sec_ch_ua TEXT,
        device_memory TEXT,
        hardware_concurrency TEXT,
        platform TEXT,
        screen_resolution TEXT,
        timezone VARCHAR(100),
        languages TEXT,
        webgl_vendor TEXT,
        webgl_renderer TEXT,
        font_list TEXT,
        canvas_hash VARCHAR(255),
        should_cloak BOOLEAN,
        risk INTEGER,
        reason TEXT,
        visitor_type VARCHAR(50)
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS ip_blacklist (
        id SERIAL PRIMARY KEY,
        ip VARCHAR(255) UNIQUE,
        reason VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    console.log('PostgreSQL tables ready');
  } catch(err) {
    console.error('Database init error:', err);
  }
}

initDatabase();

// DETECÇÃO AVANÇADA DE BOTS
const botPatterns = [
  { pattern: /googlebot/i, name: 'Googlebot', risk: 100, platform: 'Google' },
  { pattern: /bingbot/i, name: 'Bingbot', risk: 100, platform: 'Microsoft' },
  { pattern: /slurp/i, name: 'Yahoo Slurp', risk: 100, platform: 'Yahoo' },
  { pattern: /duckduckbot/i, name: 'DuckDuckGo', risk: 100, platform: 'DuckDuckGo' },
  { pattern: /baiduspider/i, name: 'Baidu', risk: 100, platform: 'Baidu' },
  { pattern: /yandex/i, name: 'Yandex', risk: 100, platform: 'Yandex' },
  { pattern: /facebookexternalhit/i, name: 'Facebook Bot', risk: 100, platform: 'Facebook' },
  { pattern: /facebot/i, name: 'Facebook Bot', risk: 100, platform: 'Facebook' },
  { pattern: /twitterbot/i, name: 'Twitter Bot', risk: 100, platform: 'Twitter' },
  { pattern: /linkedinbot/i, name: 'LinkedIn Bot', risk: 100, platform: 'LinkedIn' },
  { pattern: /pinterest/i, name: 'Pinterest Bot', risk: 100, platform: 'Pinterest' },
  { pattern: /tiktok/i, name: 'TikTok Bot', risk: 100, platform: 'TikTok' },
  { pattern: /snapchat/i, name: 'Snapchat Bot', risk: 100, platform: 'Snapchat' },
  { pattern: /ahrefs/i, name: 'Ahrefs', risk: 100, platform: 'SEO' },
  { pattern: /semrush/i, name: 'Semrush', risk: 100, platform: 'SEO' },
  { pattern: /mj12bot/i, name: 'Majestic', risk: 100, platform: 'SEO' },
  { pattern: /rogerbot/i, name: 'Rogerbot', risk: 100, platform: 'SEO' },
  { pattern: /dotbot/i, name: 'Dotbot', risk: 100, platform: 'SEO' },
  { pattern: /headless/i, name: 'Headless Browser', risk: 100, platform: 'Automation' },
  { pattern: /puppeteer/i, name: 'Puppeteer', risk: 100, platform: 'Automation' },
  { pattern: /selenium/i, name: 'Selenium', risk: 100, platform: 'Automation' },
  { pattern: /phantomjs/i, name: 'PhantomJS', risk: 100, platform: 'Automation' },
  { pattern: /playwright/i, name: 'Playwright', risk: 100, platform: 'Automation' },
  { pattern: /crawl/i, name: 'Generic Crawler', risk: 85, platform: 'SEO' },
  { pattern: /spider/i, name: 'Spider', risk: 85, platform: 'SEO' },
  { pattern: /scrape/i, name: 'Scraper', risk: 95, platform: 'Scraping' },
  { pattern: /bot/i, name: 'Generic Bot', risk: 80, platform: 'Unknown' }
];

// IPs de datacenter (bots)
const datacenterRanges = [
  '3.', '52.', '54.', '13.', '35.', '34.',
  '104.', '107.', '142.', '146.',
  '20.', '40.', '51.', '123.',
  '170.', '173.', '174.', '157.', '158.', '159.',
  '192.', '185.', '188.', '193.', '195.',
  '8.', '9.', '11.', '12.', '14.', '15.', '16.', '17.', '18.', '19.',
  '23.', '24.', '25.', '26.', '27.', '28.', '29.', '30.', '31.'
];

// User-Agents suspeitos de spy tools
const spyTools = [
  /whatsapp/i, /telegram/i, /discord/i, /slack/i,
  /curl/i, /wget/i, /python/i, /node-fetch/i,
  /axios/i, /postman/i, /insomnia/i, /burp/i,
  /nikto/i, /nmap/i, /sqlmap/i, /wpscan/i,
  /masscan/i, /zgrab/i, /httpx/i, /nuclei/i
];

function analyzeRequest(req) {
  const userAgent = req.headers['user-agent'] || '';
  const ip = req.ip || req.headers['x-forwarded-for'] || '';
  const accept = req.headers['accept'] || '';
  const referer = req.headers['referer'] || '';
  const acceptLanguage = req.headers['accept-language'] || '';
  const secChUa = req.headers['sec-ch-ua'] || '';
  const secChUaPlatform = req.headers['sec-ch-ua-platform'] || '';
  
  let totalRisk = 0;
  let reasons = [];
  let botName = null;
  let visitorType = 'human';
  
  // Detecção de bots por User-Agent
  for (const bot of botPatterns) {
    if (bot.pattern.test(userAgent)) {
      totalRisk += bot.risk;
      reasons.push(`${bot.name} (${bot.platform})`);
      botName = bot.name;
      visitorType = 'bot';
      break;
    }
  }
  
  // Detecção de spy tools
  for (const spy of spyTools) {
    if (spy.test(userAgent)) {
      totalRisk += 100;
      reasons.push(`Spy tool detected: ${userAgent.substring(0, 50)}`);
      visitorType = 'spy';
      break;
    }
  }
  
  // Detecção de IP de datacenter
  for (const range of datacenterRanges) {
    if (ip.startsWith(range)) {
      totalRisk += 85;
      reasons.push('Datacenter IP (bot host)');
      visitorType = 'bot';
      break;
    }
  }
  
  // Headers suspeitos
  if (accept.includes('application/json') && !accept.includes('text/html')) {
    totalRisk += 70;
    reasons.push('API request (JSON only)');
    visitorType = 'bot';
  }
  
  if (!referer && process.env.NODE_ENV === 'production') {
    totalRisk += 40;
    reasons.push('No referer header');
  }
  
  if (!acceptLanguage) {
    totalRisk += 30;
    reasons.push('No Accept-Language header');
  }
  
  // Headers headless
  if (secChUa.includes('Headless')) {
    totalRisk += 100;
    reasons.push('Headless Chrome detected');
    visitorType = 'bot';
  }
  
  // Browser normal (reduz risco)
  if (accept.includes('text/html') && userAgent.includes('Chrome') && !secChUa.includes('Headless')) {
    totalRisk = Math.max(0, totalRisk - 30);
  }
  
  const shouldCloak = totalRisk >= 50;
  
  return {
    shouldCloak,
    risk: Math.min(totalRisk, 100),
    reason: reasons.join(', ') || 'Valid human visitor',
    visitorType,
    botName
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
    const apiKey = 'clo_' + Math.random().toString(36).substring(2, 20) + Math.random().toString(36).substring(2, 10);
    
    await pool.query(
      'INSERT INTO users (id, email, password, name, role, plan, credits, api_key, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)',
      [userId, email, hashedPassword, name || email.split('@')[0], 'user', 'free', 100, apiKey, 'active']
    );
    
    const token = jwt.sign(
      { id: userId, email: email, role: 'user' },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.json({
      success: true,
      token,
      user: { id: userId, email, name: name || email.split('@')[0], role: 'user', plan: 'free', credits: 100, apiKey }
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
        credits: user.credits,
        apiKey: user.api_key
      }
    });
  } catch(err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// CLOAKER ENDPOINT PRINCIPAL
app.get('/cloak/:campaignId', async (req, res) => {
  try {
    const campaignResult = await pool.query('SELECT * FROM campaigns WHERE id = $1 AND status = $2', [req.params.campaignId, 'active']);
    const campaign = campaignResult.rows[0];
    
    if (!campaign) {
      return res.status(404).send(`
        <!DOCTYPE html>
        <html>
        <head><title>Campaign Not Found</title></head>
        <body style="background:#0a0a0a;color:#e0e0e0;display:flex;justify-content:center;align-items:center;height:100vh;font-family:monospace">
          <div style="text-align:center">
            <h1>404</h1>
            <p>Campaign not found</p>
          </div>
        </body>
        </html>
      `);
    }
    
    const analysis = analyzeRequest(req);
    
    // Atualizar contadores
    if (analysis.visitorType === 'bot') {
      await pool.query('UPDATE campaigns SET bot_views = bot_views + 1 WHERE id = $1', [campaign.id]);
    } else if (analysis.visitorType === 'spy') {
      await pool.query('UPDATE campaigns SET spy_views = spy_views + 1 WHERE id = $1', [campaign.id]);
    } else {
      await pool.query('UPDATE campaigns SET human_views = human_views + 1, views = views + 1 WHERE id = $1', [campaign.id]);
      
      // Debitar crédito do usuário
      await pool.query('UPDATE users SET credits = GREATEST(0, credits - 1) WHERE id = $1', [campaign.user_id]);
    }
    
    // Log detalhado
    await pool.query(
      `INSERT INTO logs (id, campaign_id, user_id, ip, user_agent, accept_header, accept_language, referer, sec_ch_ua, should_cloak, risk, reason, visitor_type)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
      [uuidv4(), campaign.id, campaign.user_id, req.ip || req.headers['x-forwarded-for'], req.headers['user-agent'],
       req.headers['accept'], req.headers['accept-language'], req.headers['referer'], req.headers['sec-ch-ua'],
       analysis.shouldCloak, analysis.risk, analysis.reason, analysis.visitorType]
    );
    
    const targetUrl = analysis.shouldCloak ? campaign.safe_url : campaign.real_url;
    res.redirect(302, targetUrl);
  } catch(err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

// API KEY AUTH (para integrações)
app.post('/api/cloak/:campaignId', async (req, res) => {
  const apiKey = req.headers['x-api-key'];
  const { campaignId } = req.params;
  
  if (!apiKey) {
    return res.status(401).json({ error: 'API key required' });
  }
  
  try {
    const userResult = await pool.query('SELECT * FROM users WHERE api_key = $1', [apiKey]);
    const user = userResult.rows[0];
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid API key' });
    }
    
    const campaignResult = await pool.query('SELECT * FROM campaigns WHERE id = $1 AND user_id = $2', [campaignId, user.id]);
    const campaign = campaignResult.rows[0];
    
    if (!campaign) {
      return res.status(404).json({ error: 'Campaign not found' });
    }
    
    // Análise via API (podem enviar dados do navegador)
    const analysis = analyzeRequest(req);
    
    return res.json({
      shouldCloak: analysis.shouldCloak,
      risk: analysis.risk,
      reason: analysis.reason,
      safeUrl: campaign.safe_url,
      realUrl: campaign.real_url
    });
  } catch(err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// CRIAR CAMPANHA
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
        apiUrl: `${req.protocol}://${req.get('host')}/api/cloak/${campaignId}`,
        views: 0,
        botViews: 0,
        humanViews: 0,
        spyViews: 0
      }
    });
  } catch(err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// LISTAR CAMPANHAS
app.get('/api/campaigns', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, safe_url, real_url, views, bot_views, human_views, spy_views, created_at, status FROM campaigns WHERE user_id = $1 ORDER BY created_at DESC',
      [req.user.id]
    );
    
    const campaigns = result.rows.map(c => ({
      id: c.id,
      name: c.name,
      safeUrl: c.safe_url,
      realUrl: c.real_url,
      views: c.views || 0,
      botViews: c.bot_views || 0,
      humanViews: c.human_views || 0,
      spyViews: c.spy_views || 0,
      cloakUrl: `${req.protocol}://${req.get('host')}/cloak/${c.id}`,
      apiUrl: `${req.protocol}://${req.get('host')}/api/cloak/${c.id}`,
      createdAt: c.created_at,
      status: c.status
    }));
    
    res.json(campaigns);
  } catch(err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ATUALIZAR CAMPANHA
app.put('/api/campaigns/:id', authenticateToken, async (req, res) => {
  const { name, safeUrl, realUrl, status } = req.body;
  
  try {
    const updates = [];
    const values = [];
    let idx = 1;
    
    if (name) { updates.push(`name = $${idx++}`); values.push(name); }
    if (safeUrl) { updates.push(`safe_url = $${idx++}`); values.push(safeUrl); }
    if (realUrl) { updates.push(`real_url = $${idx++}`); values.push(realUrl); }
    if (status) { updates.push(`status = $${idx++}`); values.push(status); }
    
    values.push(req.params.id, req.user.id);
    
    await pool.query(
      `UPDATE campaigns SET ${updates.join(', ')} WHERE id = $${idx} AND user_id = $${idx+1}`,
      values
    );
    
    res.json({ success: true });
  } catch(err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// DELETAR CAMPANHA
app.delete('/api/campaigns/:id', authenticateToken, async (req, res) => {
  try {
    await pool.query('DELETE FROM campaigns WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
    res.json({ success: true });
  } catch(err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ESTATÍSTICAS
app.get('/api/stats', authenticateToken, async (req, res) => {
  try {
    const campaignsResult = await pool.query(
      `SELECT 
        COALESCE(SUM(views), 0) as total_views,
        COALESCE(SUM(bot_views), 0) as total_bots,
        COALESCE(SUM(human_views), 0) as total_humans,
        COALESCE(SUM(spy_views), 0) as total_spies
       FROM campaigns WHERE user_id = $1`,
      [req.user.id]
    );
    
    const campaignsCountResult = await pool.query('SELECT COUNT(*) FROM campaigns WHERE user_id = $1', [req.user.id]);
    
    const userResult = await pool.query('SELECT credits, plan, api_key FROM users WHERE id = $1', [req.user.id]);
    const user = userResult.rows[0];
    
    const logsResult = await pool.query(
      `SELECT timestamp, ip, should_cloak, risk, reason, visitor_type 
       FROM logs WHERE user_id = $1 ORDER BY timestamp DESC LIMIT 30`,
      [req.user.id]
    );
    
    const totalViews = parseInt(campaignsResult.rows[0].total_views);
    const totalBots = parseInt(campaignsResult.rows[0].total_bots);
    const totalSpies = parseInt(campaignsResult.rows[0].total_spies);
    
    res.json({
      totalCampaigns: parseInt(campaignsCountResult.rows[0].count),
      totalViews,
      totalBots,
      totalSpies,
      blockRate: totalViews + totalBots > 0 ? ((totalBots / (totalViews + totalBots)) * 100).toFixed(1) : 0,
      credits: user ? user.credits : 0,
      plan: user ? user.plan : 'free',
      apiKey: user ? user.api_key : null,
      recentLogs: logsResult.rows.map(l => ({
        timestamp: l.timestamp,
        ip: l.ip,
        shouldCloak: l.should_cloak,
        risk: l.risk,
        reason: l.reason,
        visitorType: l.visitor_type
      }))
    });
  } catch(err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ADMIN ROUTES
app.get('/api/admin/users', authenticateToken, isAdmin, async (req, res) => {
  const result = await pool.query('SELECT id, email, name, role, plan, credits, status, api_key, created_at FROM users');
  res.json(result.rows);
});

app.put('/api/admin/users/:id', authenticateToken, isAdmin, async (req, res) => {
  const { plan, credits, status, role } = req.body;
  
  let query = 'UPDATE users SET ';
  const updates = [];
  const values = [];
  let idx = 1;
  
  if (plan) { updates.push(`plan = $${idx++}`); values.push(plan); }
  if (credits !== undefined) { updates.push(`credits = $${idx++}`); values.push(credits); }
  if (status) { updates.push(`status = $${idx++}`); values.push(status); }
  if (role) { updates.push(`role = $${idx++}`); values.push(role); }
  
  values.push(req.params.id);
  await pool.query(query + updates.join(', ') + ` WHERE id = $${idx}`, values);
  res.json({ success: true });
});

app.delete('/api/admin/users/:id', authenticateToken, isAdmin, async (req, res) => {
  await pool.query('DELETE FROM logs WHERE user_id = $1', [req.params.id]);
  await pool.query('DELETE FROM campaigns WHERE user_id = $1', [req.params.id]);
  await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
  res.json({ success: true });
});

app.get('/api/admin/stats', authenticateToken, isAdmin, async (req, res) => {
  const usersResult = await pool.query('SELECT COUNT(*) FROM users');
  const campaignsResult = await pool.query('SELECT COUNT(*) FROM campaigns');
  const logsResult = await pool.query('SELECT COUNT(*) FROM logs');
  const viewsResult = await pool.query('SELECT COALESCE(SUM(views), 0) as total_views, COALESCE(SUM(bot_views), 0) as total_bots FROM campaigns');
  
  const usersByPlanResult = await pool.query(`SELECT plan, COUNT(*) as count FROM users GROUP BY plan`);
  const usersByPlan = { free: 0, pro: 0, enterprise: 0 };
  usersByPlanResult.rows.forEach(row => { usersByPlan[row.plan] = parseInt(row.count); });
  
  res.json({
    totalUsers: parseInt(usersResult.rows[0].count),
    totalCampaigns: parseInt(campaignsResult.rows[0].count),
    totalLogs: parseInt(logsResult.rows[0].count),
    totalViews: parseInt(viewsResult.rows[0].total_views),
    totalBots: parseInt(viewsResult.rows[0].total_bots),
    usersByPlan,
    revenue: (usersByPlan.pro * 49.90) + (usersByPlan.enterprise * 199.90)
  });
});

app.get('/api/admin/logs', authenticateToken, isAdmin, async (req, res) => {
  const limit = parseInt(req.query.limit) || 100;
  const result = await pool.query('SELECT * FROM logs ORDER BY timestamp DESC LIMIT $1', [limit]);
  res.json(result.rows);
});

// PLANS
app.get('/api/plans', (req, res) => {
  res.json([
    { id: 'free', name: 'Free', price: 0, credits: 100, features: ['1 campaign', '100 views/month', 'Basic bot detection'] },
    { id: 'pro', name: 'Pro', price: 49.90, credits: 5000, features: ['10 campaigns', '5000 views/month', 'Advanced bot detection', 'Spy tool blocking', 'Email support'] },
    { id: 'enterprise', name: 'Enterprise', price: 199.90, credits: 50000, features: ['Unlimited campaigns', '50000 views/month', 'AI-powered detection', 'API access', 'Priority support', 'Custom rules'] }
  ]);
});

// UPDATE PLAN
app.post('/api/update-plan', authenticateToken, async (req, res) => {
  const { plan } = req.body;
  
  if (!plan || !['pro', 'enterprise'].includes(plan)) {
    return res.status(400).json({ error: 'Invalid plan' });
  }
  
  try {
    let credits = plan === 'pro' ? 5000 : 50000;
    await pool.query('UPDATE users SET plan = $1, credits = $2 WHERE id = $3', [plan, credits, req.user.id]);
    
    const newToken = jwt.sign(
      { id: req.user.id, email: req.user.email, role: req.user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.json({ success: true, token: newToken, plan: plan, credits: credits });
  } catch(err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
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
      const apiKey = 'clo_admin_' + Math.random().toString(36).substring(2, 20);
      await pool.query(
        'INSERT INTO users (id, email, password, name, role, plan, credits, api_key, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)',
        [adminId, 'admin@cloakup.com', hashedPassword, 'Administrator', 'admin', 'enterprise', 999999, apiKey, 'active']
      );
      console.log('Admin created: admin@cloakup.com / admin123');
    }
  } catch(err) {
    console.error('Error creating admin:', err);
  }
}

createAdmin();

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Cloakup Server running on port ${PORT}`);
  console.log(`Admin: admin@cloakup.com / admin123`);
});
