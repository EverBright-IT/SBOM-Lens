# Build:  docker build -f deploy/Dockerfile -t sbomlens .
# Run:    docker run --rm -p 8080:80 sbomlens
FROM node:22-alpine AS build
WORKDIR /app
# Manifests first so the npm ci layer survives source-only changes.
# ALL workspace manifests must be here — a missing one makes npm ci skip that
# workspace's deps, and the root typecheck (all workspaces) fails later.
COPY package.json package-lock.json ./
COPY packages/core/package.json packages/core/
COPY apps/web/package.json apps/web/
COPY apps/vscode/package.json apps/vscode/
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:1.31-alpine
# The nginx image lags the alpine security repos by a few packages between
# rebuilds (trivy gate: HIGH/CRITICAL with an available fix fails the tag
# pipeline) — pull the fixed versions at build time.
RUN apk upgrade --no-cache
COPY deploy/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/apps/web/dist /usr/share/nginx/html
EXPOSE 80
