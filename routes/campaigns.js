const express = require('express');
const router = express.Router();
const { loadJSON, saveJSON, generateId } = require('../utils/security');

router.post('/', async (req, res) => {
  const { name, safeUrl, realUrl } = req.body;
  
  if (!name || !safeUrl || !realUrl) {
    return res.status(400).json({ error: 'All fields required' });
  }
  
  const users = loadJSON('users.json');
  const user = users.find(u => u.id === req.user.id);
  
  const campaigns = loadJSON('campaigns.json');
  const userCampaigns = campaigns.filter(c => c.userId === req.user.id);
  
  let maxCampaigns = 1;
  if (user.plan === 'pro') maxCampaigns = 10;
  if (user.plan === 'enterprise') maxCampaigns = 999;
  
  if (userCampaigns.length >= maxCampaigns) {
    return res.status(400).json({ error: `Campaign limit reached (${maxCampaigns})` });
  }
  
  const newCampaign = {
    id: generateId(),
    userId: req.user.id,
    name,
    safeUrl,
    realUrl,
    views: 0,
    botViews: 0,
    createdAt: new Date().toISOString(),
    status: 'active'
  };
  
  campaigns.push(newCampaign);
  saveJSON('campaigns.json', campaigns);
  
  res.json({
    success: true,
    campaign: {
      id: newCampaign.id,
      name: newCampaign.name,
      cloakUrl: `http://localhost:${process.env.PORT || 3000}/cloak/${newCampaign.id}`,
      views: 0,
      botViews: 0
    }
  });
});

router.get('/', (req, res) => {
  const campaigns = loadJSON('campaigns.json');
  const userCampaigns = campaigns
    .filter(c => c.userId === req.user.id)
    .map(c => ({
      id: c.id,
      name: c.name,
      safeUrl: c.safeUrl,
      realUrl: c.realUrl,
      views: c.views || 0,
      botViews: c.botViews || 0,
      cloakUrl: `http://localhost:${process.env.PORT || 3000}/cloak/${c.id}`,
      createdAt: c.createdAt
    }));
  
  res.json(userCampaigns);
});

router.delete('/:id', (req, res) => {
  const campaigns = loadJSON('campaigns.json');
  const campaignIndex = campaigns.findIndex(c => c.id === req.params.id && c.userId === req.user.id);
  
  if (campaignIndex === -1) {
    return res.status(404).json({ error: 'Campaign not found' });
  }
  
  campaigns.splice(campaignIndex, 1);
  saveJSON('campaigns.json', campaigns);
  res.json({ success: true });
});

router.get('/stats', (req, res) => {
  const campaigns = loadJSON('campaigns.json');
  const logs = loadJSON('logs.json');
  const users = loadJSON('users.json');
  
  const userCampaigns = campaigns.filter(c => c.userId === req.user.id);
  const userLogs = logs.filter(l => l.userId === req.user.id);
  const user = users.find(u => u.id === req.user.id);
  
  const totalViews = userCampaigns.reduce((sum, c) => sum + (c.views || 0), 0);
  const totalBots = userCampaigns.reduce((sum, c) => sum + (c.botViews || 0), 0);
  
  res.json({
    totalCampaigns: userCampaigns.length,
    totalViews,
    totalBots,
    blockRate: totalViews + totalBots > 0 ? ((totalBots / (totalViews + totalBots)) * 100).toFixed(1) : 0,
    credits: user ? user.credits : 0,
    plan: user ? user.plan : 'free',
    recentLogs: userLogs.slice(-20).reverse()
  });
});

module.exports = router;