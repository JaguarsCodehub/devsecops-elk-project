const { Kafka, Partitioners } = require('kafkajs');
const crypto = require('crypto');
const logger = require('../logger/logger');

const broker = process.env.KAFKA_BROKER || 'localhost:9092';
const clientId = process.env.KAFKA_CLIENT_ID || 'secops-guard-client';
const TOPIC = process.env.KAFKA_TOPIC || 'security.audit.events';

const kafka = new Kafka({
  clientId,
  brokers: [broker],
  retry: {
    initialRetryTime: 300,
    retries: 10
  }
});

const producer = kafka.producer({
  createPartitioner: Partitioners.DefaultPartitioner
});

let isConnected = false;

async function connectProducer() {
  if (!isConnected) {
    try {
      await producer.connect();
      isConnected = true;
      logger.info('Connected Kafka Producer', { broker, topic: TOPIC });
    } catch (err) {
      logger.error('Failed to connect Kafka Producer', { error: err.message });
      throw err;
    }
  }
}

/**
 * Publish a structured security audit event to the Kafka topic.
 * @param {Object} event
 * @param {string} event.eventType e.g. 'AUTH_FAILURE', 'BRUTE_FORCE_SUSPECT', 'SQLI_ATTEMPT', 'UNAUTHORIZED_ACCESS'
 * @param {string} event.severity 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
 * @param {string} event.ip Source IP address
 * @param {string} [event.username] Username if applicable
 * @param {string} [event.path] Endpoint URL path
 * @param {string} [event.userAgent] User-Agent header
 * @param {Object} [event.metadata] Additional forensic metadata
 */
async function publishSecurityEvent(event) {
  try {
    if (!isConnected) {
      await connectProducer();
    }

    const eventPayload = {
      eventId: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      service: process.env.SERVICE_NAME || 'secops-guard',
      ...event
    };

    await producer.send({
      topic: TOPIC,
      messages: [
        {
          key: event.ip || 'anonymous',
          value: JSON.stringify(eventPayload)
        }
      ]
    });

    logger.security('Security event published to Kafka', {
      topic: TOPIC,
      eventId: eventPayload.eventId,
      eventType: event.eventType,
      severity: event.severity,
      ip: event.ip
    });

    return eventPayload;
  } catch (err) {
    logger.error('Failed to publish security event to Kafka', {
      error: err.message,
      event
    });
  }
}

async function disconnectProducer() {
  if (isConnected) {
    await producer.disconnect();
    isConnected = false;
    logger.info('Disconnected Kafka Producer');
  }
}

module.exports = {
  kafka,
  connectProducer,
  publishSecurityEvent,
  disconnectProducer
};
