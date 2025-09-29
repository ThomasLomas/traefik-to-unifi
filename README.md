# Traefik to Unifi

## Description

This project aims to integrate Traefik with UniFi, allowing for routes populated in Traefik to be updated in the static DNS of Unifi.

## Installation

1. Clone the repository: `git clone https://github.com/ThomasLomas/traefik-to-unifi.git`
2. Install the required dependencies: `pip install -r requirements.txt`
3. Set up the necessary environment variables:

### Required Environment Variables:

- `UNIFI_URL`: The URL of the UniFi controller
- `UNIFI_USERNAME`: The username for accessing the UniFi controller
- `UNIFI_PASSWORD`: The password for accessing the UniFi controller
- `TRAEFIK_API_URL`: The URL of the Traefik reverse proxy API
- `TRAEFIK_IP`: For A records this should be the IP of the Traefik reverse proxy API. For CNAME records this should be the hostname resolving to the IP.

### Optional Environment Variables (with defaults):

- `DNS_RECORD_TYPE`: Either A or CNAME. Defaults to A.
- `LOG_LEVEL`: Either CRITICAL, ERROR, WARNING, INFO, DEBUG. Defaults to INFO.
- `FULL_SYNC_INTERVAL`: Trigger a full sync every N runs. Defaults to 5.
- `IGNORE_SSL_WARNINGS`: Set to "true" to ignore SSL warnings. Defaults to "false".

## Usage

### 1. Using a published image

You can pull the latest image from Docker Hub:

```bash
docker pull thomaslomas/traefik-to-unifi:latest
```

Then run the container with the required environment variables:

```bash
docker run -e TRAEFIK_API_URL=http://traefik:8080/api/ \
           -e TRAEFIK_IP=192.168.1.10 \
           -e UNIFI_URL=https://unifi:8443/ \
           -e UNIFI_USERNAME=admin \
           -e UNIFI_PASSWORD=supersecret \
           thomaslomas/traefik-to-unifi:latest
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
