const express = require('express');
const router = express.Router();
const { loadJSON, saveJSON, hashPassword, comparePassword, generateToken, generateId } = require('../utils/security');

router.post('/register', async (req, res) => {
  const { email, password, name } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }
  
  const users = loadJSON('users.json');
  
  if (users.find(u => u.email === email)) {
    return res.status(400).json({ error: 'Email already exists' });
  }
  
  const hashedPassword = await hashPassword(password);
  const newUser = {
    id: generateId(),
    email,
    password: hashedPassword,
    name: name || email.split('@')[0],
    role: 'user',
    plan: 'free',
    credits: 100,
    status: 'active',
    createdAt: new Date().toISOString()
  };
  
  users.push(newUser);
  saveJSON('users.json', users);
  
  const token = generateToken(newUser);
  
  res.json({
    success: true,
    token,
    user: {
      id: newUser.id,
      email: newUser.email,
      name: newUser.name,
      role: newUser.role,
      plan: newUser.plan,
      credits: newUser.credits
    }
  });
});

router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  
  const users = loadJSON('users.json');
  const user = users.find(u => u.email === email);
  
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  const validPassword = await comparePassword(password, user.password);
  if (!validPassword) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  if (user.status !== 'active') {
    return res.status(401).json({ error: 'Account disabled' });
  }
  
  const token = generateToken(user);
  
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
});

module.exports = router;