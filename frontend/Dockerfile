FROM node:22.20.0-alpine AS build
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --ignore-scripts
COPY frontend/ ./
RUN npm run build
FROM caddy:2.10.2-alpine
COPY --from=build /build/dist /srv
COPY deploy/Caddyfile /etc/caddy/Caddyfile
RUN mkdir -p /config/caddy /data/caddy && chown -R 10001:10001 /config /data /srv
USER 10001:10001
EXPOSE 8080
