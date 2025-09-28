# Traefik to Unifi

## Description

This project aims to integrate Traefik with UniFi, allowing for routes populated in Traefik to be updated in the static DNS of Unifi.

## Installation

1. Clone the repository: `git clone https://github.com/ThomasLomas/traefik-to-unifi.git`
2. Install the required dependencies: `pip install -r requirements.txt`
3. Set up the necessary environment variables:

- `UNIFI_URL`: The URL of the UniFi controller
- `UNIFI_USERNAME`: The username for accessing the UniFi controller
- `UNIFI_PASSWORD`: The password for accessing the UniFi controller
- `TRAEFIK_API_URL`: The URL of the Traefik reverse proxy API
- `TRAEFIK_IP`: The IP of the Traefik reverse proxy API

## Usage

Install dependencies using `poetry install`.

You can run the application either via the Docker container or directly with:

```bash
poetry run python app.py
```

Make sure all required environment variables (listed above) are set.

### Example `.env` file
You should create a `.env` file containing your secrets. This file **should not be committed** to git.

```
TRAEFIK_API_URL=http://traefik:8080/api/
TRAEFIK_IP=192.168.1.10
UNIFI_URL=https://unifi:8443/
UNIFI_USERNAME=admin
UNIFI_PASSWORD=supersecret
```

### Running with Docker (without docker-compose)

1. Build the Docker image:

```bash
docker build -t traefik-to-unifi .
```

2. Run the container using a `.env` file:

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

### Running with Docker Compose

Build the image and start the service:

```bash
docker compose build
docker compose up
```

Make sure your `.env` file is next to `docker-compose.yml` so the secrets are loaded automatically.

## Contributing

Contributions are welcome! Please follow the guidelines outlined in [CONTRIBUTING.md](./CONTRIBUTING.md).

## License

This project is licensed under the [MIT License](./LICENSE).
