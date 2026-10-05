#!/usr/bin/env bash
# ==============================================================================
# SecOps-Guard Attack Simulation & Active Defense Validation
# Fires simulated threats to validate Kafka event streaming, Redis dynamic bans,
# and ELK / Kibana SIEM dashboard updates.
# ==============================================================================

set -euo pipefail

TARGET_HOST="${1:-http://localhost}"
echo "=========================================================="
echo "🎯 Target Host: ${TARGET_HOST}"
echo "=========================================================="

echo -e "\n[Step 1] Checking application health..."
curl -s "${TARGET_HOST}/health" | grep -q "healthy" && echo "✅ Service is HEALTHY." || { echo "❌ Service unreachable!"; exit 1; }

echo -e "\n[Step 2] Simulating Credential Brute Force (5 failed attempts)..."
ATTACKER_IP="203.0.113.88"
for i in {1..5}; do
  echo "  Attempt $i from IP: $ATTACKER_IP"
  curl -s -X POST "${TARGET_HOST}/api/auth/login" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: $ATTACKER_IP" \
    -d "{\"username\": \"admin\", \"password\": \"wrong_pass_$i\"}" > /dev/null
  sleep 0.3
done

echo -e "\n[Step 3] Waiting 2 seconds for Kafka Consumer & Redis to process rule..."
sleep 2

echo -e "\n[Step 4] Testing Active Defense: Expecting HTTP 403 Forbidden for banned IP..."
BLOCKED_RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "${TARGET_HOST}/api/auth/login" \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: $ATTACKER_IP" \
  -d '{"username": "admin", "password": "any_password"}')

echo "${BLOCKED_RESPONSE}"
if echo "${BLOCKED_RESPONSE}" | grep -q "HTTP_STATUS:403"; then
  echo "🛡️ SUCCESS: Offending IP $ATTACKER_IP was AUTOMATICALLY BANNED in Redis by Kafka Detection Engine!"
else
  echo "⚠️ Expected 403 Forbidden, please check Kafka and Redis logs."
fi

echo -e "\n[Step 5] Simulating Critical SQL Injection Attack..."
SQLI_IP="198.51.100.99"
curl -s -X POST "${TARGET_HOST}/api/auth/login" \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: $SQLI_IP" \
  -d '{"username": "admin'\'' OR '\''1'\''='\''1'\'' --", "password": "foo"}' || true

echo -e "\n[Step 6] Querying Active Redis Blacklist via API..."
curl -s "${TARGET_HOST}/api/security/blacklist"

echo -e "\n=========================================================="
echo "🎉 Attack simulation complete!"
echo "Check your Kibana Dashboard (http://<host>:5601) to view:"
echo " 1. 'secops-logs-*' index in Discover"
echo " 2. Real-time Threat Severity Bar Chart"
echo " 3. Metricbeat Container CPU/Memory usage"
echo "=========================================================="
