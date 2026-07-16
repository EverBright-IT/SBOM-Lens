# Build:  docker build -f deploy/Dockerfile -t sbomlens .
# Run:    docker run --rm -p 8080:80 sbomlens
FROM node:22-alpine AS build
WORKDIR /app
# Manifests first so the npm ci layer survives source-only changes. Only the
# workspaces this image actually ships are listed: the root, the SPDX domain,
# and the web app.
COPY package.json package-lock.json ./
COPY packages/core/package.json packages/core/
COPY apps/web/package.json apps/web/
RUN npm ci
COPY . .
# Deliberately NOT `npm run build`: that runs the root typecheck across every
# workspace, which tied this image to the VS Code extensions it does not
# contain — adding a workspace then broke the image build (twice). Linting,
# typechecking and testing the whole repo is the `test` CI job's business and
# runs on the same pipeline; here we typecheck and build what we serve.
RUN npm run typecheck -w @sbomlens/web && npm run build -w @sbomlens/web

FROM nginx:1.31-alpine
# The nginx image lags the alpine security repos by a few packages between
# rebuilds (trivy gate: HIGH/CRITICAL with an available fix fails the tag
# pipeline) — pull the fixed versions at build time.
RUN apk upgrade --no-cache
COPY deploy/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/apps/web/dist /usr/share/nginx/html
EXPOSE 80
