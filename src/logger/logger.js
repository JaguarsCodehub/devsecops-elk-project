/**
 * High-performance structured JSON logger.
 * Emits NDJSON formatted logs to stdout, where Filebeat tails and ships to Logstash/Elasticsearch.
 */

const SERVICE_NAME = process.env.SERVICE_NAME || 'secops-guard';

function log(level, message, metadata = {}) {
  const entry = {
    "@timestamp": new Date().toISOString(),
    service: SERVICE_NAME,
    level,
    message,
    ...metadata
  };

  // Ensure output is single line JSON for Filebeat filestream parser
  process.stdout.write(JSON.stringify(entry) + '\n');
}

module.exports = {
  info: (message, metadata) => log('INFO', message, metadata),
  warn: (message, metadata) => log('WARN', message, metadata),
  error: (message, metadata) => log('ERROR', message, metadata),
  security: (message, metadata) => log('SECURITY', message, {
    security_event: true,
    ...metadata
  })
};
