FROM node:20-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv \
    build-essential \
    chromium \
    fonts-liberation fonts-noto-color-emoji \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium

WORKDIR /app

COPY webapp/package.json webapp/package-lock.json* ./webapp/
RUN cd webapp && npm ci --omit=dev

COPY requirements.txt ./
RUN python3 -m venv /app/venv && /app/venv/bin/pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PATH="/app/venv/bin:$PATH"

RUN mkdir -p /app/webapp/generated_reports /app/data

VOLUME ["/app/data", "/app/webapp/generated_reports"]

EXPOSE 3000

WORKDIR /app/webapp
CMD ["node", "server.js"]
