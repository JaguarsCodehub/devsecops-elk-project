# ==============================================================================
# Multi-Stage Hardened Dockerfile for SecOps-Guard
# Complies with CIS Docker Benchmark & Trivy Security Hardening
# ==============================================================================

# Stage 1: Build & Dependency Resolution
FROM node:20-alpine AS builder

WORKDIR /usr/src/app

# Install dependencies using clean install
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

# Copy source code
COPY src/ ./src/

# Stage 2: Hardened Runtime Container
FROM node:20-alpine AS runner

WORKDIR /usr/src/app

ENV NODE_ENV=production \
    PORT=8000

# Install curl for container health check
RUN apk --no-cache add curl

# Copy dependencies and application from builder
COPY --from=builder /usr/src/app/node_modules ./node_modules
COPY --from=builder /usr/src/app/src ./src
COPY package.json ./

# Switch to standard unprivileged non-root user
USER node

EXPOSE 8000

# Container Healthcheck
HEALTHCHECK --interval=20s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

CMD ["node", "src/app.js"]
