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
  { pattern: /playwright/i, name: 'Playwright', risk: 100 },
  { pattern: /crawl/i, name: 'Generic Crawler', risk: 90 },
  { pattern: /spider/i, name: 'Spider', risk: 90 },
  { pattern: /scrape/i, name: 'Scraper', risk: 90 },
  { pattern: /bot/i, name: 'Generic Bot', risk: 85 }
];

const datacenterRanges = [
  '3.', '52.', '54.', '13.', '35.', '34.',
  '104.', '107.', '142.', '146.',
  '20.', '40.', '51.', '123.',
  '170.', '173.', '174.', '157.', '158.', '159.',
  '192.', '185.', '188.', '193.', '195.',
  '8.', '9.', '11.', '12.', '14.', '15.', '16.', '17.', '18.', '19.',
  '23.', '24.', '25.', '26.', '27.', '28.', '29.', '30.', '31.'
];

function analyzeRequest(req) {
  const userAgent = req.headers['user-agent'] || '';
  const ip = req.ip || req.headers['x-forwarded-for'] || '';
  const accept = req.headers['accept'] || '';
  const referer = req.headers['referer'] || '';
  const acceptLanguage = req.headers['accept-language'] || '';
  const secChUa = req.headers['sec-ch-ua'] || '';
  
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
  
  if (!acceptLanguage) {
    totalRisk += 30;
    reasons.push('No Accept-Language');
  }
  
  if (secChUa.includes('Headless')) {
    totalRisk += 100;
    reasons.push('Headless Chrome detected');
  }
  
  return {
    shouldCloak: totalRisk >= 60,
    risk: Math.min(totalRisk, 100),
    reason: reasons.join(', ') || 'Valid human'
  };
}

module.exports = { analyzeRequest };