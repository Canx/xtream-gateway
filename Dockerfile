FROM node:22-alpine

WORKDIR /app

# Copy application source
COPY server.js ./

# Create empty fallback config if not mounted
RUN echo "[]" > ./providers.json

# Environment defaults
ENV PORT=8888 \
    NODE_ENV=production

EXPOSE 8888

USER node

CMD ["node", "server.js"]
