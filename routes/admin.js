const express = require('express');
const router = express.Router();
const { loadJSON, saveJSON } = require('../utils/security');

router.get('/users', (req, res) => {
  const users = loadJSON('users.json');
  const sanitized = users.map(u => ({
    id: u.id,
    email: u.email,
    name: u.name,
    role: u.role,
    plan: u.plan,
    credits: u.credits,
    status: u.status,
    createdAt: u.createdAt
  }));
  res.json(sanitized);
});

router.put('/users/:id', (req, res) => {
  const { plan, credits, status, role } = req.body;
  const users = loadJSON('users.json');
  const userIndex = users.findIndex(u => u.id === req.params.id);
  
  if (userIndex === -1) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  if (plan) users[userIndex].plan = plan;
  if (credits !== undefined) users[userIndex].credits = credits;
  if (status) users[userIndex].status = status;
  if (role) users[userIndex].role = role;
  
  saveJSON('users.json', users);
  res.json({ success: true, user: users[userIndex] });
});

router.delete('/users/:id', (req, res) => {
  let users = loadJSON('users.json');
  let campaigns = loadJSON('campaigns.json');
  
  users = users.filter(u => u.id !== req.params.id);
  campaigns = campaigns.filter(c => c.userId !== req.params.id);
  
  saveJSON('users.json', users);
  saveJSON('campaigns.json', campaigns);
  res.json({ success: true });
});

router.get('/stats', (req, res) => {
  const users = loadJSON('users.json');
  const campaigns = loadJSON('campaigns.json');
  const logs = loadJSON('logs.json');
  
  const totalViews = campaigns.reduce((sum, c) => sum + (c.views || 0), 0);
  const totalBots = campaigns.reduce((sum, c) => sum + (c.botViews || 0), 0);
  
  const usersByPlan = {
    free: users.filter(u => u.plan === 'free').length,
    pro: users.filter(u => u.plan === 'pro').length,
    enterprise: users.filter(u => u.plan === 'enterprise').length
  };
  
  res.json({
    totalUsers: users.length,
    totalCampaigns: campaigns.length,
    totalLogs: logs.length,
    totalViews,
    totalBots,
    usersByPlan,
    revenue: (usersByPlan.pro * 49.90) + (usersByPlan.enterprise * 199.90)
  });
});

router.get('/campaigns', (req, res) => {
  const campaigns = loadJSON('campaigns.json');
  const users = loadJSON('users.json');
  
  const result = campaigns.map(c => {
    const user = users.find(u => u.id === c.userId);
    return {
      id: c.id,
      name: c.name,
      userEmail: user ? user.email : 'Unknown',
      userId: c.userId,
      views: c.views || 0,
      botViews: c.botViews || 0,
      safeUrl: c.safeUrl,
      realUrl: c.realUrl,
      createdAt: c.createdAt
    };
  });
  
  res.json(result);
});

router.get('/logs', (req, res) => {
  const logs = loadJSON('logs.json');
  const limit = parseInt(req.query.limit) || 100;
  res.json(logs.slice(-limit).reverse());
});

module.exports = router;