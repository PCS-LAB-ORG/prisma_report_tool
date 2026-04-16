# Prisma Cloud Vulnerability Reporter

A self-hosted dashboard for tracking vulnerabilities, compliance, and scan history across one or more Prisma Cloud tenants.

---

## Prerequisites

- **Git** -- to clone the repository
- **Docker** and **Docker Compose** -- to build and run the application
- **Prisma Cloud** access key and secret key for each tenant you want to monitor

---

## 1. Clone the Repository

```bash
git clone https://github.com/PCS-LAB-ORG/prisma_report_tool.git
cd prisma_report_tool
```

Expected output:

```
$ git clone https://github.com/PCS-LAB-ORG/prisma_report_tool.git
Cloning into 'prisma_report_tool'...
remote: Enumerating objects: 45, done.
remote: Counting objects: 100% (45/45), done.
remote: Compressing objects: 100% (38/38), done.
Receiving objects: 100% (45/45), 128.50 KiB | 2.14 MiB/s, done.

$ cd prisma_report_tool
```

---

## 2. Create the Credentials File

The application reads Prisma Cloud API credentials from `~/.prismacloud/credentials.json`. Start by creating the directory:

```bash
mkdir -p ~/.prismacloud
```

Then create the file with your editor of choice (e.g. `vi`, `nano`, `code`):

```bash
vi ~/.prismacloud/credentials.json
```

The file is a JSON array. Each object represents one Prisma Cloud tenant.

**Single tenant example:**

```json
[
  {
    "name": "Production Cloud",
    "identity": "your-access-key-id",
    "secret": "your-secret-key",
    "url": "https://api.prismacloud.io",
    "verify": "true",
    "proxies": null,
    "project_flag": "false"
  }
]
```

**Multiple tenants example:**

```json
[
  {
    "name": "Production Cloud",
    "identity": "access-key-for-tenant-1",
    "secret": "secret-key-for-tenant-1",
    "url": "https://api.prismacloud.io",
    "verify": "true",
    "proxies": null,
    "project_flag": "false"
  },
  {
    "name": "Staging Self-Hosted",
    "identity": "access-key-for-tenant-2",
    "secret": "secret-key-for-tenant-2",
    "url": "https://api2.prismacloud.io",
    "verify": "true",
    "proxies": null,
    "project_flag": "false"
  }
]
```

| Field      | Description                                                        |
|------------|--------------------------------------------------------------------|
| `name`     | Display name shown in the UI tenant selector                       |
| `identity` | Your Prisma Cloud Access Key ID                                    |
| `secret`   | Your Prisma Cloud Secret Key                                       |
| `url`      | API URL for your tenant (found in Prisma Cloud under **Settings**) |
| `verify`   | Set to `true` for SSL verification (recommended)                   |

> Tenant configuration is handled automatically from this file -- no other config files are needed.

---

## 3. Build and Start the Application

First, build the Docker image. This downloads all dependencies and packages the app:

```bash
docker compose build
```

Expected output:

```
$ docker compose build
[+] Building 42.3s (12/12) FINISHED
 => [internal] load build definition from Dockerfile                0.0s
 => [internal] load .dockerignore                                   0.0s
 => [internal] load metadata for docker.io/library/node:20-slim     1.2s
 => [1/7] FROM docker.io/library/node:20-slim@sha256:abc123...      3.4s
 => [2/7] WORKDIR /app                                              0.1s
 => [3/7] COPY package.json ./                                      0.1s
 => [4/7] RUN npm install --production                             18.6s
 => [5/7] COPY requirements.txt ./                                  0.1s
 => [6/7] RUN pip install -r requirements.txt                      12.1s
 => [7/7] COPY . .                                                  0.3s
 => exporting to image                                              6.4s
 => => naming to docker.io/library/prisma_report_tool-app           0.0s
```

Then start the container in the background:

```bash
docker compose up -d
```

Expected output:

```
$ docker compose up -d
[+] Running 2/2
 ✔ Network prisma_report_tool_default  Created                      0.1s
 ✔ Container prisma_report_tool-app-1  Started                      0.4s
```

You can verify the container is running:

```bash
docker compose ps
```

```
$ docker compose ps
NAME                         STATUS          PORTS
prisma_report_tool-app-1     Up 10 seconds   0.0.0.0:3000->3000/tcp
```

### Accessing the Dashboard

The app listens on **port 3000**. Open a browser and navigate to:

| Scenario                               | URL                              |
|----------------------------------------|----------------------------------|
| Running on your local machine          | `http://localhost:3000`          |
| Running on a remote server / VM        | `http://<server-ip>:3000`        |
| Example: server at 10.0.1.50           | `http://10.0.1.50:3000`         |
| Example: server at 192.168.1.100       | `http://192.168.1.100:3000`     |

> Replace `<server-ip>` with the IP address or hostname of the machine running Docker. If you're running this on a cloud VM, use the public IP. Make sure port 3000 is open in your firewall or security group.

---

## 4. Sync Data

On first launch there is no vulnerability data yet. Open the app and go to **Settings** to:

1. Click **Run Sync Now** to pull vulnerabilities from Prisma Cloud
2. Watch progress in the live log viewer
3. Optionally set up a recurring schedule (e.g. daily at midnight)

---

## Stopping the Application

To stop and remove the container:

```bash
docker compose down
```

Expected output:

```
$ docker compose down
[+] Running 2/2
 ✔ Container prisma_report_tool-app-1  Removed                     1.2s
 ✔ Network prisma_report_tool_default  Removed                     0.3s
```

Your data is preserved in the `./data` directory and will be available the next time you start the app.

To start back up again:

```bash
docker compose up -d
```

---

## Updating to a New Version

Pull the latest code and rebuild:

```bash
git pull
docker compose build
docker compose down && docker compose up -d
```

Your existing data in `./data` is preserved across updates.

---

## Useful Commands

| Command                    | Description                              |
|----------------------------|------------------------------------------|
| `docker compose build`     | Rebuild the image after code changes     |
| `docker compose up -d`     | Start the container in the background    |
| `docker compose down`      | Stop and remove the container            |
| `docker compose ps`        | Show running container status            |
| `docker compose logs -f`   | Stream live container logs               |
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
