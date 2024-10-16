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

Install dependencies with `poetry install`

Either via the Docker container or run `poetry run python app.py`. Be sure to have the environment variables listed above available.

## Contributing

Contributions are welcome! Please follow the guidelines outlined in [CONTRIBUTING.md](./CONTRIBUTING.md).

## License

This project is licensed under the [MIT License](./LICENSE).
