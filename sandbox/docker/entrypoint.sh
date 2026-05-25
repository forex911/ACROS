#!/bin/sh
set -e

# Entrypoint for sandbox worker runtime image
# Runs as non-root user (configured in Dockerfile.node)

# Ensure runtime temp dirs exist and are writable
mkdir -p /app/tmp
chmod 700 /app/tmp || true

# If a health endpoint is desired, the app should expose /health on configured port
# Start application (adjust path if needed)
if [ -f /app/server.js ]; then
  exec node /app/server.js
else
  # fallback to npm start if present
  exec npm start
fi
