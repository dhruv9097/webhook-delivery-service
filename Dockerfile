# Debian slim rather than Alpine: Prisma's query engine links against OpenSSL,
# and musl builds are a recurring source of "engine not found" failures.

FROM node:22-slim AS deps
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev || npm install --omit=dev

FROM node:22-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production
RUN apt-get update && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY prisma ./prisma
RUN npx prisma generate

COPY src ./src
COPY scripts ./scripts

# mock-receiver/ is deliberately NOT copied. It is an unauthenticated HTTP
# server with runtime mode-control and a /reset endpoint, used only by the test
# suite. Nothing starts it in production, but an artifact should not contain
# what it must never run. Compose builds it from a separate stage below.

# Drop privileges. The node image ships an unprivileged `node` user.
USER node

# No shell wrapper and no npm: PID 1 is node itself, so SIGTERM reaches the
# process directly and graceful shutdown actually runs. `npm start` would
# swallow the signal.
CMD ["node", "src/server.js"]

# Test-only image, referenced by docker-compose's mock-receiver service. Kept in
# this Dockerfile for convenience, but it is a separate build target so it never
# becomes part of the runtime image.
FROM node:22-slim AS mock-receiver
WORKDIR /app
COPY mock-receiver ./mock-receiver
USER node
CMD ["node", "mock-receiver/index.js"]
