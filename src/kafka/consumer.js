const { kafka } = require('./producer');
const { blacklistIp, recordAttempt } = require('../redis/client');
const logger = require('../logger/logger');

const groupId = process.env.KAFKA_GROUP_ID || 'secops-detection-group';
const TOPIC = process.env.KAFKA_TOPIC || 'security.audit.events';

const consumer = kafka.consumer({ groupId });

let isRunning = false;

async function startDetectionEngine() {
  try {
    await consumer.connect();
    await consumer.subscribe({ topic: TOPIC, fromBeginning: false });
    isRunning = true;

    logger.info('Threat Detection Engine (Kafka Consumer) started', {
      groupId,
      topic: TOPIC
    });

    await consumer.run({
      eachMessage: async ({ message }) => {
        try {
          const raw = message.value.toString();
          const event = JSON.parse(raw);

          await evaluateThreatRules(event);
        } catch (err) {
          logger.error('Error processing Kafka event in detection engine', {
            error: err.message
          });
        }
      }
    });
  } catch (err) {
    logger.error('Failed to start Threat Detection Consumer', { error: err.message });
  }
}

/**
 * Anomaly Detection & Active Defense Rule Evaluator.
 * Evaluates events against dynamic security heuristics and enforces Redis bans.
 */
async function evaluateThreatRules(event) {
  const { eventType, ip, severity } = event;
  if (!ip) return;

  // RULE 1: Immediate Ban for Critical Exploits (SQLi, Command Injection, XSS)
  if (eventType === 'SQLI_ATTEMPT' || eventType === 'EXPLOIT_PAYLOAD' || severity === 'CRITICAL') {
    logger.security('CRITICAL EXPLOIT DETECTED - Enforcing immediate 1-hour IP ban', {
      ip,
      eventType,
      action: 'IMMEDIATE_BAN'
    });
    await blacklistIp(ip, `Immediate ban: Exploit pattern detected (${eventType})`, 3600);
    return;
  }

  // RULE 2: Brute Force Sliding Window Detection (5 failures within 60s)
  if (eventType === 'AUTH_FAILURE') {
    const attemptKey = `rate:auth_fail:${ip}`;
    const failures = await recordAttempt(attemptKey, 60);

    logger.info('Evaluating authentication failure threshold', {
      ip,
      currentFailuresInWindow: failures,
      threshold: 5
    });

    if (failures >= 5) {
      logger.security('BRUTE FORCE THRESHOLD EXCEEDED - Enforcing 15-minute IP ban', {
        ip,
        failuresInWindow: failures,
        action: 'BRUTE_FORCE_BAN'
      });
      await blacklistIp(
        ip,
        `Brute force detected: ${failures} auth failures within 60s`,
        900
      );
    }
    return;
  }

  // RULE 3: Unauthorized Access Spikes (Privilege Escalation attempt)
  if (eventType === 'UNAUTHORIZED_ACCESS') {
    const attemptKey = `rate:unauth_access:${ip}`;
    const attempts = await recordAttempt(attemptKey, 60);

    if (attempts >= 10) {
      logger.security('EXCESSIVE UNAUTHORIZED ACCESS DETECTED - Enforcing 10-minute IP ban', {
        ip,
        attemptsInWindow: attempts,
        action: 'UNAUTH_SPIKE_BAN'
      });
      await blacklistIp(
        ip,
        `Reconnaissance / scanning detected: ${attempts} unauthorized requests within 60s`,
        600
      );
    }
  }
}

async function stopDetectionEngine() {
  if (isRunning) {
    await consumer.disconnect();
    isRunning = false;
    logger.info('Threat Detection Engine stopped');
  }
}

module.exports = {
  startDetectionEngine,
  stopDetectionEngine
};
