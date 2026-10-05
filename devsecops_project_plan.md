# SecOps-Guard: Production-Grade DevSecOps SIEM & Threat Detection Pipeline

A production-grade, cost-optimized DevSecOps implementation leveraging **GitLab CI/CD**, **AWS EC2 (`t3.xlarge`)**, **Docker Compose**, **Apache Kafka (KRaft)**, **Redis**, and an **ELK + Beats Stack (Elasticsearch, Logstash, Kibana, Filebeat, Metricbeat)** with automated shift-left security scanning (**Gitleaks, Semgrep, Trivy**).

---

## 1. Executive Summary & Architecture Rationale

* **Cloud Footprint:** Single AWS EC2 instance (`t3.xlarge` - 4 vCPUs, 16 GB RAM on Ubuntu 22.04 LTS).
  * *Cost optimization:* Can run as an **AWS Spot Instance** (~$0.05/hour) to reduce compute costs by ~70%.
* **Managed Services Elimination:**
  * **No AWS EKS:** Avoids the fixed $73/month cluster management fee. Orchestration is managed cleanly with Docker Compose.
  * **No AWS ECR:** Uses **GitLab Container Registry**, which is free and natively integrated with GitLab CI/CD.
  * **No AWS MSK, OpenSearch Service, or ElastiCache:** Apache Kafka (KRaft mode), Elasticsearch, Kibana, Logstash, Beats, and Redis all run in isolated containers on the host, communicating over a private Docker bridge network (`secops-net`).
* **Shift-Left Security Model:**
  * Stage 1: Secret detection (**Gitleaks**) + SAST (**Semgrep**) + Code Quality audit.
  * Stage 2: Container image vulnerability scanning (**Trivy**) with build-blocking thresholds (`HIGH,CRITICAL`).
  * Stage 3: Automated SSH deployment with environment isolation and zero exposed databases.
* **Runtime Observability & Threat Defense (SecOps / SIEM):**
  * **Active Defense:** Kafka event streaming decouples security event ingestion from anomaly detection. When threat thresholds are breached, the detection engine dynamically blacklists offending IPs in Redis with TTL expiration.
  * **Log Ingestion & Enrichment:** Filebeat tails container logs -> Logstash enriches security logs (risk scoring, attack classification, timestamp alignment) -> Elasticsearch indexes into `secops-audit-*`.
  * **Infrastructure Telemetry:** Metricbeat collects container CPU/RAM/network metrics and provides automated Kibana dashboards.

---

## 2. High-Level Architecture Diagram

```
[ Incoming Traffic / Simulated Attacks ]
                  │
                  ▼
       [ AWS EC2 (t3.xlarge) ]
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│ Docker Network (`secops-net`)                                                               │
│                                                                                             │
│  ┌───────────────────────┐   (1. Check Blacklist)    ┌───────────────────────────────────┐  │
│  │ SecOps App Gateway    │──────────────────────────▶│ Redis 7 (Port 6379)               │  │
│  │ (Port 8000 -> 80)     │◀──────────────────────────│ • IP Blacklist with TTL           │  │
│  └──────────┬────────────┘       (Allowed / Denied)  │ • Sliding Window Rate-Limiting    │  │
│             │                                        └─────────────────▲─────────────────┘  │
│             │ (2. Stream Audit Events)                                 │                    │
│             ▼                                                          │ (4. Dynamic Ban)   │
│  ┌───────────────────────┐                           ┌─────────────────┴─────────────────┐  │
│  │ Kafka Broker (KRaft)  │──────────────────────────▶│ Threat Detection Worker          │  │
│  │ Topic:                │   (3. Consume & Analyze)  │ • Sliding window rule evaluation  │  │
│  │ `security.audit.events`                           │ • Brute force & exploit detector  │  │
│  └───────────────────────┘                           └───────────────────────────────────┘  │
│                                                                                             │
│  ── OBSERVABILITY & SIEM TIER ────────────────────────────────────────────────────────────  │
│                                                                                             │
│  ┌───────────────────────┐      ┌─────────────────────────┐      ┌───────────────────────┐  │
│  │ Filebeat 9.1.0        │─────▶│ Logstash 9.1.0          │─────▶│ Elasticsearch 9.1.0   │  │
│  │ (Docker filestream)   │      │ (Ingest pipeline, tags) │      │ (Port 9200)           │  │
│  └───────────────────────┘      └─────────────────────────┘      └───────────┬───────────┘  │
│                                                                              │              │
│  ┌───────────────────────┐                                                   │              │
│  │ Metricbeat 9.1.0      │───────────────────────────────────────────────────┤              │
│  │ (Host & Container IO) │                                                   ▼              │
│  └───────────────────────┘                                       ┌───────────────────────┐  │
│                                                                  │ Kibana 9.1.0          │  │
│                                                                  │ (Port 5601 - SIEM UI) │  │
│                                                                  └───────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Host Memory Allocation on `t3.xlarge` (16 GB RAM)

| Service | Container Name | RAM / Heap Allocation | Purpose |
| :--- | :--- | :--- | :--- |
| **Elasticsearch** | `elasticsearch` | `3 GB` (`ES_JAVA_OPTS=-Xms3g -Xmx3g`) | Audit log index and fast search engine |
| **Kibana** | `kibana` | `~1.2 GB` | SIEM visual dashboards & threat maps |
| **Logstash** | `logstash` | `512 MB` (`LS_JAVA_OPTS=-Xms512m -Xmx512m`) | Log enrichment and transformation |
| **Apache Kafka** | `kafka` | `1 GB` (`KAFKA_HEAP_OPTS=-Xms1g -Xmx1g`) | KRaft-mode event broker |
| **Redis** | `redis` | `256 MB` | In-memory IP blacklist and rate limit state |
| **SecOps App & Engine** | `secops-app` | `300 MB` | API Gateway + Anomaly Detection Worker |
| **Filebeat** | `filebeat` | `150 MB` | Container log harvester |
| **Metricbeat** | `metricbeat` | `150 MB` | System & container resource monitoring |
| **Host OS & Buffers** | Host OS | `~2.0 GB` | Ubuntu kernel, Docker daemon, page cache |
| **Available Headroom** | Spare | **~7.5 GB** | Safe operating margin against OOM |

---

## 4. Network & Security Hardening (AWS Security Group)

Only ingress ports necessary for administration and the web interfaces are exposed to the public internet:

| Protocol | Port | Ingress Source | Justification |
| :--- | :--- | :--- | :--- |
| **SSH** | `22` | `<YOUR_DEV_PUBLIC_IP>/32` | Host administration (restricted strictly to admin IP) |
| **HTTP** | `80` | `0.0.0.0/0` | Reverse proxy / User-facing SecOps API Gateway |
| **Kibana** | `5601` | `<YOUR_DEV_PUBLIC_IP>/32` | SIEM dashboard access (restricted to admin IP or VPN) |
| **Elasticsearch**| `9200` | **None (Blocked externally)** | Internal cluster traffic inside Docker network |
| **Logstash** | `5044` | **None (Blocked externally)** | Internal Beats ingestion |
| **Kafka** | `9092` | **None (Blocked externally)** | Internal event bus |
| **Redis** | `6379` | **None (Blocked externally)** | Internal key/value state store (password-protected) |

---

## 5. End-to-End Shift-Left GitLab CI/CD Pipeline

```
[ git push to main ]
         │
         ▼
[ Stage 1: security-audit ]
   ├── Gitleaks: Secrets & credentials scanning
   └── Semgrep: SAST vulnerability scanning (OWASP Top 10)
         │ (Pass)
         ▼
[ Stage 2: build-and-scan ]
   ├── Multi-Stage Docker Build (Node.js 20 Alpine unprivileged)
   ├── Trivy Image Scan (Fails on HIGH,CRITICAL CVEs)
   └── Push verified image to GitLab Container Registry
         │ (Pass)
         ▼
[ Stage 3: deploy ]
   └── Automated SSH Deployment to EC2 host (/opt/secops-guard)
```

---

## 6. Directory Layout & Deliverables

```
devsecops-kafka-events-docker/
├── .gitlab-ci.yml                     # Multi-stage security pipeline
├── docker-compose.yml                 # Full stack orchestration (App, Kafka, Redis, ELK, Beats)
├── Dockerfile                         # Hardened multi-stage unprivileged build
├── package.json                       # Node.js dependencies
├── .env.example                       # Documented environment template
├── src/
│   ├── app.js                         # API Gateway (Auth, simulate attack, blacklist checks)
│   ├── kafka/
│   │   ├── producer.js                # Structured security audit event publisher
│   │   └── consumer.js                # Anomaly detection engine (sliding window evaluator)
│   ├── redis/
│   │   └── client.js                  # Redis blacklist & rate limiter client
│   └── logger/
│       └── logger.js                  # High-performance structured JSON logger
├── elk/
│   ├── beats/
│   │   ├── filebeat.yml               # Modern filestream container autodiscover
│   │   └── metricbeat.yml             # Docker & system metrics with setup dashboards
│   └── logstash/
│       ├── config/
│       │   ├── logstash.yml           # Logstash settings
│       │   └── pipelines.yml          # Pipeline registrations
│       ├── pipeline/
│       │   └── secops-logs.conf       # Ingest, JSON parse, threat tagging & ES output
│       └── templates/
│           └── secops-template.json   # Index template with explicit keyword mappings
└── scripts/
    ├── simulate-attacks.sh            # Fires simulated brute-force, SQLi & credential stuffing
    └── setup-host.sh                  # One-click Ubuntu 22.04 initialization script
```