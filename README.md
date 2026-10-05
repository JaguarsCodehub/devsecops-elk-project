# 🛡️ SecOps-Guard

> **Real-Time DevSecOps SIEM & Threat Anomaly Detection Pipeline**  
> Powered by **GitLab CI/CD**, **Apache Kafka (KRaft)**, **Redis**, and the **Elastic Stack (Elasticsearch 9.1.0, Logstash, Kibana, Filebeat, Metricbeat)**.

---

## 📌 Overview

**SecOps-Guard** demonstrates a production-grade, end-to-end DevSecOps lifecycle:
1. **Shift-Left Security in CI/CD:** Static secret auditing with **Gitleaks**, SAST vulnerability scanning with **Semgrep**, and container CVE scanning with **Trivy**.
2. **Event-Driven Security Architecture:** An API Gateway routes real-time security events to **Apache Kafka (KRaft mode)**.
3. **Active Defense with Redis:** A streaming anomaly detection engine evaluates threats in real-time (e.g. brute force, credential stuffing, SQL injection attempts) and dynamically bans offending IPs in **Redis** with automated TTL expiration.
4. **SIEM & Infrastructure Observability:** **Filebeat** tails container logs using modern `filestream` container parsers -> **Logstash** enriches and tags attack categories -> **Elasticsearch** indexes -> **Kibana** visualizes security dashboards, while **Metricbeat** reports host & container health.

---

## 🏛️ Architecture Flow

```
[ Traffic / Attacks ]
        │
        ▼
[ SecOps Gateway ] ──(1. Check Blacklist)──▶ [ Redis 7 ]
        │                                         ▲
        │ (2. Stream Events)                      │ (4. Dynamic Ban with TTL)
        ▼                                         │
[ Kafka (KRaft) ] ──────(3. Consume)──────▶ [ Detection Engine ]
        │
        ├──▶ [ Filebeat ] ──▶ [ Logstash ] ──▶ [ Elasticsearch ]
        │                                             ▲
        └──▶ [ Metricbeat ] ──────────────────────────┤
                                                      ▼
                                                 [ Kibana 9.1.0 ]
```

---

## 🚀 Quickstart (Local Development)

### 1. Prerequisites
- Docker Engine & Docker Compose v2
- Node.js 20+ (for local scripts/development)

### 2. Configure Environment
```bash
cp .env.example .env
```
*(Customize `REDIS_PASSWORD` as desired)*

### 3. Start the Complete Stack
```bash
docker compose up -d
```

### 4. Verify Services
- **SecOps API Gateway:** `http://localhost/health`
- **Kibana SIEM UI:** `http://localhost:5601`
- **Elasticsearch Cluster Health:** `http://localhost:9200/_cluster/health`

### 5. Run Attack Simulation & Validate Defense
```bash
bash scripts/simulate-attacks.sh http://localhost
```
This script will:
- Fire 5 rapid failed login attempts.
- Verify that the Kafka detection engine flagged brute force and automatically blacklisted the IP in Redis.
- Confirm subsequent requests receive **HTTP 403 Forbidden**.
- Emit a SQL injection exploit event and query the active blacklist API.

---

## 🔒 GitLab CI/CD Security Pipeline

The `.gitlab-ci.yml` pipeline enforces 3 automated security stages on every commit:
- **`security-audit`**:
  - `gitleaks`: Scans commits for secret leaks and private keys.
  - `semgrep`: Performs automated SAST analysis on application code.
- **`build-and-scan`**:
  - Builds the unprivileged multi-stage Alpine Docker image.
  - Runs `trivy image` and halts the build if any `HIGH` or `CRITICAL` vulnerabilities exist.
  - Pushes verified images to the GitLab Container Registry.
- **`deploy`**:
  - Automatically provisions or updates containers on AWS EC2 (`t3.xlarge`) over SSH.

---

## 📊 Kibana SIEM Visualizations

In Kibana (`http://<host>:5601`):
1. **Discover:** Create a Data View for `secops-logs-*` with `@timestamp` as the timestamp field.
2. **Dashboard Visualizations:**
   - **Threat Severity Breakdown:** Donut chart grouped by `severity.keyword`.
   - **Active Attack Patterns:** Horizontal bar chart grouped by `event_type.keyword`.
   - **Top Targeted Accounts:** Bar chart on `target_user.keyword`.
   - **Host & Container Telemetry:** Access Metricbeat prebuilt dashboards automatically created in Kibana.

---

## 📜 License
MIT
