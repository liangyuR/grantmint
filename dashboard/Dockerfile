ARG NODE_IMAGE=node:22-alpine
ARG CADDY_IMAGE=caddy:2-alpine
FROM ${NODE_IMAGE} AS build
WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM ${CADDY_IMAGE}
COPY Caddyfile /etc/caddy/Caddyfile
COPY --from=build /build/dist /srv
