const Redis = require('ioredis');
const logger = require('../logger/logger');

const redisHost = process.env.REDIS_HOST || '127.0.0.1';
const redisPort = parseInt(process.env.REDIS_PORT || '6379', 10);
const redisPassword = process.env.REDIS_PASSWORD || undefined;

const redis = new Redis({
  host: redisHost,
  port: redisPort,
  password: redisPassword,
  retryStrategy(times) {
    const delay = Math.min(times * 100, 3000);
    return delay;
  },
  maxRetriesPerRequest: 3,
  lazyConnect: true
});

redis.on('connect', () => {
  logger.info('Connected to Redis instance', { host: redisHost, port: redisPort });
});

redis.on('error', (err) => {
  logger.error('Redis connection error', { error: err.message });
});

/**
 * Check if an IP address is currently blacklisted.
 * @param {string} ip
 * @returns {Promise<{ blacklisted: boolean, reason?: string, ttl?: number }>}
 */
async function isBlacklisted(ip) {
  try {
    const key = `blacklist:${ip}`;
    const [data, ttl] = await Promise.all([
      redis.get(key),
      redis.ttl(key)
    ]);

    if (data) {
      const parsed = JSON.parse(data);
      return { blacklisted: true, reason: parsed.reason, ttl };
    }
    return { blacklisted: false }; // passed
  } catch (err) {
    logger.error('Error querying Redis blacklist', { ip, error: err.message });
    return { blacklisted: false };
  }
}

/**
 * Add an IP to the active blacklist with an automated expiration TTL.
 * @param {string} ip
 * @param {string} reason
 * @param {number} ttlSeconds Default: 600 seconds (10 minutes)
 */
async function blacklistIp(ip, reason, ttlSeconds = 600) {
  try {
    const key = `blacklist:${ip}`;
    const payload = JSON.stringify({
      ip,
      reason,
      bannedAt: new Date().toISOString(),
      ttlSeconds
    });

    await redis.set(key, payload, 'EX', ttlSeconds);
    logger.security('IP blacklisted in Redis', {
      ip,
      reason,
      ttl_seconds: ttlSeconds,
      action: 'IP_BANNED'
    });
  } catch (err) {
    logger.error('Failed to blacklist IP in Redis', { ip, error: err.message });
  }
}

/**
 * Increment an attempt counter with a sliding TTL window.
 * Useful for brute-force and rate-limit detection.
 * @param {string} key
 * @param {number} windowSeconds
 * @returns {Promise<number>} Current count
 */
async function recordAttempt(key, windowSeconds = 60) {
  try {
    const count = await redis.incr(key);
    if (count === 1) {
      await redis.expire(key, windowSeconds);
    }
    return count;
  } catch (err) {
    logger.error('Failed to record attempt in Redis', { key, error: err.message });
    return 1;
  }
}

/**
 * List all currently banned IPs and remaining TTLs.
 */
async function getActiveBlacklist() {
  try {
    const keys = await redis.keys('blacklist:*');
    if (!keys || keys.length === 0) return [];

    const pipeline = redis.pipeline();
    keys.forEach(k => {
      pipeline.get(k);
      pipeline.ttl(k);
    });

    const results = await pipeline.exec();
    const items = [];

    for (let i = 0; i < keys.length; i++) {
      const rawData = results[i * 2][1];
      const ttl = results[i * 2 + 1][1];
      if (rawData) {
        const parsed = JSON.parse(rawData);
        items.push({ ...parsed, remainingTtlSeconds: ttl });
      }
    }
    return items;
  } catch (err) {
    logger.error('Failed to fetch active blacklist from Redis', { error: err.message });
    return [];
  }
}

async function connect() {
  if (redis.status === 'wait' || redis.status === 'close') {
    await redis.connect();
  }
}

module.exports = {
  redis,
  connect,
  isBlacklisted,
  blacklistIp,
  recordAttempt,
  getActiveBlacklist
};
