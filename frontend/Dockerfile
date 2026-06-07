FROM node:20.18-alpine AS build

WORKDIR /app

# Install deps from lockfile first (cached when source changes)
COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

# Unprivileged nginx: runs as uid 101 (nginx) out of the box, pid in /tmp,
# temp/cache dirs pre-chowned. Our server block listens on 3000 (>1024) so no
# NET_BIND_SERVICE capability is needed.
FROM nginxinc/nginx-unprivileged:1.27-alpine

COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 3000

CMD ["nginx", "-g", "daemon off;"]
