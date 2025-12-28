# Traefik to UniFi

## Description

This project aims to integrate Traefik with UniFi, allowing for routes populated in Traefik to be updated in the static DNS of UniFi.
## Installation

1. Clone the repository: `git clone https://github.com/ThomasLomas/traefik-to-unifi.git`
2. Install the required dependencies: `pip install -r requirements.txt`
3. Set up the necessary environment variables:

### Required Environment Variables:

> Either `UNIFI_USERNAME` and `UNIFI_PASSWORD` or `UNIFI_API_KEY` should be used.

- `UNIFI_URL`: The URL of the UniFi controller
- `UNIFI_USERNAME`: The username for accessing the UniFi controller
- `UNIFI_PASSWORD`: The password for accessing the UniFi controller
- `UNIFI_API_KEY`: The api key for accessing the UniFi controller
- `TRAEFIK_API_URL`: The URL of the Traefik reverse proxy API
- `TRAEFIK_IP`: For A records this should be the IP of the Traefik reverse proxy API. For CNAME records this should be the hostname resolving to the IP.

### Optional Environment Variables (with defaults):

- `DNS_RECORD_TYPE`: Either A or CNAME. Defaults to A.
- `LOG_LEVEL`: Either CRITICAL, ERROR, WARNING, INFO, DEBUG. Defaults to INFO.
- `FULL_SYNC_INTERVAL`: Trigger a full sync every N runs. Defaults to 5.
- `IGNORE_SSL_WARNINGS`: Set to "true" to ignore SSL warnings. Defaults to "false".
- `DNS_OUTPUT_FILE`: Path to write a JSON file tracking all synced DNS entries. If not set, no file is written.

### DNS Output File (Optional):

When `DNS_OUTPUT_FILE` is set, the application writes a JSON file after each sync containing all current DNS entries. This is useful for:

- Auditing which routes are synced to UniFi
- Integration with monitoring or documentation tools
- Debugging DNS sync issues

Example output (`/data/dns-entries.json`):

```json
{
  "last_updated": "2025-12-28T21:45:00.000000+00:00",
  "traefik_ip": "10.0.10.50",
  "dns_record_type": "A",
  "total_entries": 3,
  "entries": [
    {
      "hostname": "grafana.example.com",
      "target": "10.0.10.50",
      "type": "A"
    },
    {
      "hostname": "lidarr.example.com",
      "target": "10.0.10.50",
      "type": "A"
    },
    {
      "hostname": "sonarr.example.com",
      "target": "10.0.10.50",
      "type": "A"
    }
  ]
}
```

**Note:** Make sure to mount a volume for persistence:
```yaml
volumes:
  - /path/to/data:/data
environment:
  - DNS_OUTPUT_FILE=/data/dns-entries.json
```

### Docker Label Filtering (Optional):

Filter which containers get DNS entries by checking Docker container labels. This is useful when you only want certain containers to have UniFi DNS records (similar to how [cloudflare-companion](https://github.com/tiredofit/docker-traefik-cloudflare-companion) works).

- `DOCKER_FILTER_LABEL`: The Docker label name to check (e.g., `traefik.unifi-dns`).
- `DOCKER_FILTER_VALUE`: The required label value (e.g., `true`). If not set, any value is accepted.

**Note:** When using Docker label filtering, you must mount the Docker socket:
```yaml
volumes:
  - /var/run/docker.sock:/var/run/docker.sock
```

#### Example: Only create DNS for containers with `traefik.unifi-dns=true`

Container labels:
```yaml
# This container WILL get UniFi DNS
labels:
  - traefik.enable=true
  - traefik.http.routers.myapp.rule=Host(`myapp.example.com`)
  - traefik.unifi-dns=true  # ← This label triggers UniFi DNS creation

# This container will NOT get UniFi DNS (no traefik.unifi-dns label)
labels:
  - traefik.enable=true
  - traefik.http.routers.public.rule=Host(`public.example.com`)
  - traefik.constraint=proxy-public  # ← Only for Cloudflare, not UniFi
```

traefik-to-unifi configuration:
```yaml
environment:
  - DOCKER_FILTER_LABEL=traefik.unifi-dns
  - DOCKER_FILTER_VALUE=true
```

## Usage

### 1. Using a published image

You can pull the latest image from Docker Hub:

```bash
docker pull ghcr.io/thomaslomas/traefik-to-unifi:latest
```

Then run the container with the required environment variables:

```bash
docker run -e TRAEFIK_API_URL=http://traefik:8080/api/ \
           -e TRAEFIK_IP=192.168.1.10 \
           -e UNIFI_URL=https://unifi:8443/ \
           -e UNIFI_USERNAME=admin \
           -e UNIFI_PASSWORD=supersecret \
           ghcr.io/thomaslomas/traefik-to-unifi:latest
```

### 2. Running with Docker (without docker-compose)

#### 1. Build the Docker image:

```bash
docker build -t traefik-to-unifi .
```

#### 2. Run the container using a `.env` file:

Create a `.env` file with the required environment variables:

```.env
TRAEFIK_API_URL=http://traefik:8080/api/
TRAEFIK_IP=192.168.1.10
UNIFI_URL=https://unifi:8443/
UNIFI_USERNAME=admin
UNIFI_PASSWORD=supersecret
```

```bash
docker run --env-file .env traefik-to-unifi
```

Or by passing environment variables directly:

```bash
docker run -e TRAEFIK_API_URL=http://traefik:8080/api/ \
           -e TRAEFIK_IP=192.168.1.10 \
           -e UNIFI_URL=https://unifi:8443/ \
           -e UNIFI_USERNAME=admin \
           -e UNIFI_PASSWORD=supersecret \
           traefik-to-unifi
```

### 3. Running with Docker Compose

Build the image and start the service:

```bash
docker compose build
docker compose up
```

Make sure your `.env` file is next to `docker-compose.yml` so that secrets are loaded automatically.

## Development

This project uses Poetry for dependency management and includes automated code quality checks.

### Setup Development Environment

1. Install dependencies and set up pre-commit hooks:
   ```bash
   make dev-setup
   ```

### Code Quality

This project uses several tools to maintain code quality:

- **Ruff** - Fast Python linter and formatter
- **Black** - Code formatter
- **Pre-commit** - Git hooks for automatic checks

#### Available Commands

```bash
# Check code style and formatting
make lint

# Auto-fix formatting issues
make format

# Run all CI checks locally
make ci

# Run pre-commit hooks on all files
make pre-commit
```

#### GitHub Actions

All pull requests automatically run a single CI workflow that includes:

- Code linting with Ruff
- Format checking with Black and Ruff
- Pre-commit hook validation
- Security scanning with Trivy

The CI will fail if code doesn't meet the formatting and linting standards.

## Contributing

Contributions are welcome! Please follow the guidelines outlined in [CONTRIBUTING.md](./CONTRIBUTING.md).

Before submitting a pull request:

1. Run `make ci` to ensure your changes pass all checks
2. Make sure your code is properly formatted with `make format`
3. Add tests for new functionality

## License

This project is licensed under the [MIT License](./LICENSE).
