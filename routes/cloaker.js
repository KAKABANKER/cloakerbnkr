const express = require('express');
const router = express.Router();
const { analyzeRequest } = require('../utils/cloaker-engine');
const { loadJSON, saveJSON, generateId } = require('../utils/security');

router.get('/:campaignId', async (req, res) => {
  const campaigns = loadJSON('campaigns.json');
  const campaign = campaigns.find(c => c.id === req.params.campaignId);
  
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
  
  const users = loadJSON('users.json');
  const user = users.find(u => u.id === campaign.userId);
  
  const analysis = analyzeRequest(req);
  
  const logs = loadJSON('logs.json');
  logs.push({
    id: generateId(),
    campaignId: campaign.id,
    userId: campaign.userId,
    timestamp: new Date().toISOString(),
    ip: req.ip || req.headers['x-forwarded-for'],
    userAgent: req.headers['user-agent'],
    shouldCloak: analysis.shouldCloak,
    risk: analysis.risk,
    reason: analysis.reason
  });
  saveJSON('logs.json', logs);
  
  if (!analysis.shouldCloak && user) {
    user.credits = Math.max(0, user.credits - 1);
    campaign.views = (campaign.views || 0) + 1;
    saveJSON('users.json', users);
    saveJSON('campaigns.json', campaigns);
  } else if (analysis.shouldCloak) {
    campaign.botViews = (campaign.botViews || 0) + 1;
    saveJSON('campaigns.json', campaigns);
  }
  
  const targetUrl = analysis.shouldCloak ? campaign.safeUrl : campaign.realUrl;
  res.redirect(302, targetUrl);
});

module.exports = router;