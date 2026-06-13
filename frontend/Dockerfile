# Build stage
FROM node:18-alpine AS builder

WORKDIR /app

# Copy dependency files
COPY package*.json ./

# Clean install dependencies
RUN npm ci

# Copy source code and build
COPY . .
RUN npm run build

# Production stage (Non-root Nginx)
FROM nginxinc/nginx-unprivileged:alpine

# Copy built assets
COPY --from=builder /app/dist /usr/share/nginx/html

# Expose default unprivileged port
EXPOSE 8080

CMD ["nginx", "-g", "daemon off;"]
