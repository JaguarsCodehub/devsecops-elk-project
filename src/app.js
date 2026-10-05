const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
require('dotenv').config();

const logger = require('./logger/logger');
const { connect: connectRedis, isBlacklisted, getActiveBlacklist } = require('./redis/client');
const { connectProducer, publishSecurityEvent, disconnectProducer } = require('./kafka/producer');
const { startDetectionEngine, stopDetectionEngine } = require('./kafka/consumer');

const app = express();
const PORT = process.env.PORT || 8000;

// Security Middlewares
app.use(helmet());
app.use(cors());
app.use(express.json());

// Helper to determine real client IP
function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    return forwarded.split(',')[0].trim();
  }
  return req.socket.remoteAddress || '127.0.0.1';
}

// ---------------------------------------------------------------------------
// MIDDLEWARE 1: Active Defense Redis Blacklist Filter
// ---------------------------------------------------------------------------
app.use(async (req, res, next) => {
  // Always allow health checks through
  if (req.path === '/health') return next();

  const ip = getClientIp(req);
  const banStatus = await isBlacklisted(ip);

  if (banStatus.blacklisted) {
    logger.warn('Blocked blacklisted IP attempt', {
      ip,
      path: req.path,
      method: req.method,
      reason: banStatus.reason,
      remainingTtl: banStatus.ttl
    });

    return res.status(403).json({
      error: 'Access Denied: IP Blacklisted by SecOps-Guard Active Defense',
      reason: banStatus.reason,
      remainingSeconds: banStatus.ttl
    });
  }

  next();
});

// ---------------------------------------------------------------------------
// MIDDLEWARE 2: Request Inspection & Exploit Signature Filter
// ---------------------------------------------------------------------------
const SQLI_REGEX = /(\b(SELECT|UNION|INSERT|DELETE|UPDATE|DROP|ALTER)\b|--|\/\*|\*\/|' OR '1'='1|1=1)/i;
const XSS_REGEX = /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/i;

app.use(async (req, res, next) => {
  const ip = getClientIp(req);
  const queryStr = JSON.stringify(req.query || {});
  const bodyStr = JSON.stringify(req.body || {});

  if (SQLI_REGEX.test(queryStr) || SQLI_REGEX.test(bodyStr)) {
    await publishSecurityEvent({
      eventType: 'SQLI_ATTEMPT',
      severity: 'CRITICAL',
      ip,
      path: req.path,
      userAgent: req.headers['user-agent'],
      metadata: { payloadSnippet: bodyStr.slice(0, 100) }
    });

    return res.status(400).json({ error: 'Malicious payload detected and quarantined.' });
  }

  if (XSS_REGEX.test(queryStr) || XSS_REGEX.test(bodyStr)) {
    await publishSecurityEvent({
      eventType: 'EXPLOIT_PAYLOAD',
      severity: 'CRITICAL',
      ip,
      path: req.path,
      userAgent: req.headers['user-agent'],
      metadata: { attack: 'XSS' }
    });

    return res.status(400).json({ error: 'Malicious script pattern rejected.' });
  }

  next();
});

// ---------------------------------------------------------------------------
// API ROUTES
// ---------------------------------------------------------------------------

// 1. Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: process.env.SERVICE_NAME || 'secops-guard',
    timestamp: new Date().toISOString(),
    uptimeSeconds: Math.floor(process.uptime())
  });
});

// 2. Authentication endpoint
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body || {};
  const ip = getClientIp(req);

  // Hardcoded demo credentials for illustration
  if (username === 'admin' && password === 'P@ssw0rdSecOps2026!') {
    await publishSecurityEvent({
      eventType: 'AUTH_SUCCESS',
      severity: 'LOW',
      ip,
      username,
      path: req.path
    });

    return res.json({
      message: 'Authentication successful',
      token: 'secops-demo-jwt-token-xyz'
    });
  }

  // Failed login
  await publishSecurityEvent({
    eventType: 'AUTH_FAILURE',
    severity: 'HIGH',
    ip,
    username: username || 'unknown',
    path: req.path,
    userAgent: req.headers['user-agent']
  });

  return res.status(401).json({ error: 'Invalid credentials provided' });
});

// 3. Protected Resource (Privilege checking)
app.get('/api/protected/resource', async (req, res) => {
  const authHeader = req.headers['authorization'];
  const ip = getClientIp(req);

  if (!authHeader || !authHeader.startsWith('Bearer secops-demo-jwt-token-xyz')) {
    await publishSecurityEvent({
      eventType: 'UNAUTHORIZED_ACCESS',
      severity: 'MEDIUM',
      ip,
      path: req.path,
      userAgent: req.headers['user-agent']
    });

    return res.status(401).json({ error: 'Unauthorized: Valid Bearer token required' });
  }

  res.json({
    data: 'Top Secret SecOps Data: Mission Success',
    timestamp: new Date().toISOString()
  });
});

// 4. View Active Blacklist
app.get('/api/security/blacklist', async (req, res) => {
  const banned = await getActiveBlacklist();
  res.json({
    activeBansCount: banned.length,
    bannedIps: banned
  });
});

// 5. Simulate Attack (For CI/CD automated validation and live demo)
app.post('/api/simulate/attack', async (req, res) => {
  const { type, simulatedIp = '198.51.100.42', count = 5 } = req.body;

  if (type === 'brute-force') {
    for (let i = 0; i < count; i++) {
      await publishSecurityEvent({
        eventType: 'AUTH_FAILURE',
        severity: 'HIGH',
        ip: simulatedIp,
        username: `attacker_target_${i}`,
        path: '/api/auth/login'
      });
    }
    return res.json({ message: `Dispatched ${count} brute-force attempts for IP ${simulatedIp}` });
  }

  if (type === 'sqli') {
    await publishSecurityEvent({
      eventType: 'SQLI_ATTEMPT',
      severity: 'CRITICAL',
      ip: simulatedIp,
      path: '/api/search',
      metadata: { payload: "' OR '1'='1' --" }
    });
    return res.json({ message: `Dispatched critical SQLi exploit event for IP ${simulatedIp}` });
  }

  res.status(400).json({ error: "Unknown attack simulation type. Use 'brute-force' or 'sqli'." });
});

// ---------------------------------------------------------------------------
// SERVER BOOTSTRAP
// ---------------------------------------------------------------------------
async function startServer() {
  try {
    // 1. Initialize Redis
    await connectRedis();

    // 2. Initialize Kafka Producer
    await connectProducer();

    // 3. Start Kafka Detection Engine Consumer
    await startDetectionEngine();

    // 4. Start HTTP Server
    const server = app.listen(PORT, '0.0.0.0', () => {
      logger.info(`SecOps-Guard Server active and listening on port ${PORT}`, {
        port: PORT,
        env: process.env.NODE_ENV || 'development'
      });
    });

    // Graceful Shutdown
    const shutdown = async () => {
      logger.info('Shutting down SecOps-Guard gracefully...');
      server.close();
      await stopDetectionEngine();
      await disconnectProducer();
      process.exit(0);
    };

    process.on('SIGTERM', shutdown);
    process.on('SIGINT', shutdown);
  } catch (err) {
    logger.error('Failed to bootstrap SecOps-Guard application', { error: err.message });
    process.exit(1);
  }
}

startServer();
