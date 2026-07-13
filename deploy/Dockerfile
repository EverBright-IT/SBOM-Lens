# Build:  docker build -f deploy/Dockerfile -t sbomlens .
# Run:    docker run --rm -p 8080:80 sbomlens
FROM node:22-alpine AS build
WORKDIR /app
# Manifests first so the npm ci layer survives source-only changes.
COPY package.json package-lock.json ./
COPY packages/core/package.json packages/core/
COPY apps/web/package.json apps/web/
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:1.27-alpine
COPY deploy/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/apps/web/dist /usr/share/nginx/html
EXPOSE 80
