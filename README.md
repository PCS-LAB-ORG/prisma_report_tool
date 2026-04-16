# Prisma Cloud Vulnerability Reporter

A self-hosted dashboard for tracking vulnerabilities, compliance, and scan history across one or more Prisma Cloud tenants.

---

## Prerequisites

- **Git**
- **Docker** and **Docker Compose**
- **Prisma Cloud** access key and secret key for each tenant

---

## 1. Clone the Repository

```bash
git clone https://github.com/PCS-LAB-ORG/prisma_report_tool.git prisma-cloud-reports
cd prisma-cloud-reports
```

---

## 2. Create the Credentials File

The application reads Prisma Cloud credentials from `~/.prismacloud/credentials.json`. Create the directory and file:

```bash
mkdir -p ~/.prismacloud
```

Then create `~/.prismacloud/credentials.json`. Each object in the array is one Prisma Cloud tenant:

**Single tenant:**

```json
[
  {
    "name": "Production Cloud",
    "identity": "your-access-key-id",
    "secret": "your-secret-key",
    "url": "https://api.prismacloud.io",
    "verify": true
  }
]
```

**Multiple tenants:**

```json
[
  {
    "name": "Production Cloud",
    "identity": "access-key-for-tenant-1",
    "secret": "secret-key-for-tenant-1",
    "url": "https://api.prismacloud.io",
    "verify": true
  },
  {
    "name": "Staging Self-Hosted",
    "identity": "access-key-for-tenant-2",
    "secret": "secret-key-for-tenant-2",
    "url": "https://api2.prismacloud.io",
    "verify": true
  }
]
```

> The `name` field is used as the display name in the UI. Tenant configuration is handled automatically -- no other config files are needed.

---

## 3. Build and Start

```bash
docker compose build
docker compose up -d
```

The app will be available at **http://localhost:3000**.

---

## 4. Sync Data

On first launch there is no vulnerability data yet. Open the app and go to **Settings** to:

1. Click **Run Sync Now** to pull vulnerabilities from Prisma Cloud
2. Watch progress in the live log viewer
3. Optionally set up a recurring schedule (e.g. daily at midnight)

---

## Stopping the Application

```bash
docker compose down
```

This stops and removes the container. Your data is preserved in the `./data` directory and will be available the next time you start the app.

---

## Useful Commands

| Command                    | Description                              |
|----------------------------|------------------------------------------|
| `docker compose build`     | Rebuild the image after code changes     |
| `docker compose up -d`     | Start in the background                  |
| `docker compose down`      | Stop and remove the container            |
| `docker compose logs -f`   | Stream container logs                    |
| `docker compose restart`   | Restart without rebuilding               |

---

## Project Structure

```
├── docker-compose.yml      # Container configuration
├── Dockerfile              # Image build instructions
├── fetch_vulns.py          # Prisma Cloud API sync script
├── requirements.txt        # Python dependencies
├── data/                   # Persisted databases (created at runtime)
└── webapp/
    ├── server.js           # Express API server
    └── public/             # Frontend (dashboard, explorer, reports)
```
