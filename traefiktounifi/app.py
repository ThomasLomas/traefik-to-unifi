"""Module for synchronizing Traefik hostnames with Unifi static DNS entries."""

import json
import logging
import os
import re

import docker
import requests
import urllib3


class TraefikToUnifi:
    """Synchronizes Traefik hostnames with Unifi static DNS entries."""

    def __init__(self):
        """Initializes the TraefikToUnifi instance."""

        # class variables to track state between syncs
        self.traefik_domains_json_last_run = "[]"
        self.number_of_syncs_without_change = 0
        self.is_first_run = True

        # Load environment variables
        self.traefik_ip = os.environ.get("TRAEFIK_IP")
        self.traefik_api_url = os.environ.get("TRAEFIK_API_URL")
        self.unifi_url = os.environ.get("UNIFI_URL")
        self.unifi_username = os.environ.get("UNIFI_USERNAME")
        self.unifi_password = os.environ.get("UNIFI_PASSWORD")
        self.unifi_api_key = os.environ.get("UNIFI_API_KEY")

        # Load optional environment variables with defaults
        self.ignore_ssl_warnings = os.environ.get("IGNORE_SSL_WARNINGS", "false") in (
            "1",
            "true",
            "True",
            "TRUE",
        )
        self.dns_record_type = os.environ.get("DNS_RECORD_TYPE", "A")
        self.full_sync_interval = int(os.environ.get("FULL_SYNC_INTERVAL", "5"))

        # Docker label filtering (similar to cloudflare-companion)
        # When set, only containers with matching labels will have DNS entries created
        self.docker_filter_label = os.environ.get("DOCKER_FILTER_LABEL")
        self.docker_filter_value = os.environ.get("DOCKER_FILTER_VALUE")
        self.docker_client = None

        if self.docker_filter_label:
            logging.info(
                f"Docker label filtering enabled: {self.docker_filter_label}={self.docker_filter_value or '*'}"
            )
            try:
                self.docker_client = docker.from_env()
                logging.info("Docker client initialized successfully.")
            except docker.errors.DockerException as e:
                logging.error(f"Failed to initialize Docker client: {e}")
                logging.warning(
                    "Docker label filtering will be disabled. "
                    "Ensure Docker socket is mounted at /var/run/docker.sock"
                )
                self.docker_filter_label = None

        if self.ignore_ssl_warnings:
            # we show our own warning on startup, no warning on each request required
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            logging.warning(
                "Ignoring SSL warnings as per configuration. This is insecure and should only be used for testing purposes. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#tls-warnings"
            )

        # Validate required environment variables
        for key, value in {
            "UNIFI_URL": self.unifi_url,
            "TRAEFIK_IP": self.traefik_ip,
            "TRAEFIK_API_URL": self.traefik_api_url,
        }.items():
            if value is None:
                raise ValueError(f"Required environment variable {key} is not set.")

        if (
            not self.unifi_username or not self.unifi_password
        ) and not self.unifi_api_key:
            raise ValueError(
                "Either UNIFI_USERNAME and UNIFI_PASSWORD or UNIFI_API_KEY should be set."
            )

        # Validate optional environment variables
        if self.dns_record_type not in ("A", "CNAME"):
            raise ValueError(
                f"Invalid DNS_RECORD_TYPE: {self.dns_record_type}. Allowed values are 'A' or 'CNAME'."
            )

        if self.full_sync_interval < 2:
            raise ValueError(
                f"Invalid FULL_SYNC_INTERVAL: {self.full_sync_interval}. Must be 2 or greater."
            )

        logging.debug(f"UNIFI_URL={self.unifi_url}")
        logging.debug(f"TRAEFIK_API_URL={self.traefik_api_url}")
        logging.debug(f"FULL_SYNC_INTERVAL={self.full_sync_interval}")

    def get_docker_hostnames_with_label(self):
        """
        Query Docker for containers with the specified label and extract their hostnames.
        Returns a set of hostnames that should be included in DNS.
        """
        if not self.docker_client or not self.docker_filter_label:
            return None  # No filtering, include all

        allowed_hostnames = set()

        try:
            containers = self.docker_client.containers.list()
            logging.debug(f"Found {len(containers)} running containers.")

            for container in containers:
                labels = container.labels
                label_value = labels.get(self.docker_filter_label)

                # Check if container has the filter label
                if label_value is None:
                    continue

                # If a specific value is required, check it matches
                if self.docker_filter_value and label_value != self.docker_filter_value:
                    continue

                logging.debug(
                    f"Container {container.name} has matching label "
                    f"{self.docker_filter_label}={label_value}"
                )

                # Extract hostnames from Traefik router labels
                for label_name, label_val in labels.items():
                    # Match traefik.http.routers.*.rule labels containing Host()
                    if (
                        label_name.startswith("traefik.http.routers.")
                        and label_name.endswith(".rule")
                        and "Host(" in str(label_val)
                    ):
                        # Extract hostname from Host(`hostname`) pattern
                        match = re.search(r"Host\(`([^`]+)`\)", str(label_val))
                        if match:
                            hostname = match.group(1)
                            allowed_hostnames.add(hostname)
                            logging.debug(
                                f"Found hostname {hostname} in container {container.name}"
                            )

        except docker.errors.APIError as e:
            logging.error(f"Docker API error: {e}")
            return None  # On error, fall back to no filtering

        logging.info(
            f"Docker label filter found {len(allowed_hostnames)} allowed hostnames."
        )
        return allowed_hostnames

    def sync(self):
        """
        Synchronizes Traefik hostnames with Unifi static DNS entries.
        - Fetches routers from Traefik API
        - Extracts hostnames from router rules
        - Filters by Docker labels if configured
        - Compares them with existing Unifi static DNS entries
        - Adds missing hosts or updates outdated ones
        """

        logging.info("Starting synchronization...")

        # Get allowed hostnames from Docker labels (if filtering is enabled)
        allowed_hostnames = self.get_docker_hostnames_with_label()

        # Request routers from Traefik API
        traefik_domains = self.fetch_traefik_domains(allowed_hostnames)

        if not traefik_domains:
            logging.warning("No hostnames found in Traefik routers.")
            return

        # Detect changes compared to previous run
        traefik_domains_json = json.dumps(traefik_domains, indent=4)
        traefik_domains_json_changed = (
            traefik_domains_json != self.traefik_domains_json_last_run
        )

        if traefik_domains_json_changed:
            self.number_of_syncs_without_change = 0
            if self.is_first_run:
                logging.debug(
                    f"Extracted {len(traefik_domains)} hostnames in Traefik routers in first run."
                )
            else:
                logging.debug(
                    f"Extracted {len(traefik_domains)} hostnames in Traefik routers and detected changes since last run."
                )
        else:
            self.number_of_syncs_without_change += 1
            logging.info(
                f"No changes since last sync - {self.number_of_syncs_without_change} time(s) since last full sync."
            )

        self.is_first_run = False
        self.traefik_domains_json_last_run = traefik_domains_json

        # Do not sync with UniFi if there are no changes in the Traefik hostnames, but for safety do it every 5th run so that manually modified dns records get fixed too.
        if not traefik_domains_json_changed:
            if self.number_of_syncs_without_change < self.full_sync_interval:
                logging.info("Skipping UniFi update due to no changes.")
                return

            # reset counter and do full sync
            logging.info(
                "Performing full sync with UniFi despite no changes in Traefik hostnames."
            )
            self.number_of_syncs_without_change = 0

        # Login to UniFi
        unifi_session = requests.Session()
        if self.ignore_ssl_warnings:
            unifi_session.verify = False

        if not self.unifi_api_key:
            logging.debug(f"Logging in to UniFi {self.unifi_url} ...")
            unifi_login_response = unifi_session.post(
                f"{self.unifi_url}api/auth/login",
                json={"username": self.unifi_username, "password": self.unifi_password},
            )

            if unifi_login_response.status_code != 200:
                raise ValueError(
                    f"Failed to login to UniFi API. Status code: {unifi_login_response.status_code}"
                )

            logging.debug("Login successful, updating CSRF token.")
            unifi_session.headers.update(
                {"X-Csrf-Token": unifi_login_response.headers["X-Csrf-Token"]}
            )
        else:
            logging.debug("Using UniFi API Key for authentication.")
            unifi_session.headers.update({"X-API-KEY": self.unifi_api_key})

        # Fetch existing static DNS entries from UniFi
        logging.debug("Fetching existing static DNS entries from UniFi...")
        get_static_dns_entries_response = unifi_session.get(
            f"{self.unifi_url}proxy/network/v2/api/site/default/static-dns"
        )

        if get_static_dns_entries_response.status_code != 200:
            raise ValueError(
                f"Failed to get static DNS entries from UniFi API. Status code: {get_static_dns_entries_response.status_code}"
            )

        unifi_static_dns_entries = [
            (entry["key"], entry["value"], entry["_id"])
            for entry in get_static_dns_entries_response.json()
        ]

        entries_to_update = []
        hosts_to_add = []

        # Compare Traefik hostnames with UniFi static DNS entries
        for dns_name in traefik_domains:
            already_exists = False
            for entry in unifi_static_dns_entries:
                if entry[0] == dns_name:
                    already_exists = True
                    if entry[1] != self.traefik_ip:
                        logging.info(
                            f"DNS name {dns_name} already exists but with different value {entry[1]}. Scheduling update to {self.traefik_ip}."
                        )
                        entries_to_update.append((entry[0], entry[2]))
                    break

            if not already_exists:
                logging.info(
                    f"Scheduling addition of DNS name {dns_name} to UniFi static DNS entries."
                )
                hosts_to_add.append(dns_name)

        logging.info(
            f"DNS entries to update: {len(entries_to_update)}, "
            f"new DNS entries to add: {len(hosts_to_add)}"
        )

        if not entries_to_update and not hosts_to_add:
            logging.debug("No changes required for UniFi static DNS entries.")
        else:
            logging.info(
                f"Updating DNS entries using DNS record type: {self.dns_record_type}"
            )

        # Update existing entries
        for key, entry_id in entries_to_update:
            update_static_dns_entry_response = unifi_session.put(
                f"{self.unifi_url}proxy/network/v2/api/site/default/static-dns/{entry_id}",
                json={
                    "enabled": True,
                    "key": key,
                    "record_type": self.dns_record_type,
                    "value": self.traefik_ip,
                    "_id": entry_id,
                },
            )

            if update_static_dns_entry_response.status_code == 200:
                logging.info(f"Successfully updated DNS entry {key} in Unifi API.")
            else:
                logging.error(
                    f"Failed to update static DNS entry {key} in UniFi API. Status code: {update_static_dns_entry_response.status_code}"
                )

        # Add new entries
        for host in hosts_to_add:
            add_static_dns_entry_response = unifi_session.post(
                f"{self.unifi_url}proxy/network/v2/api/site/default/static-dns",
                json={
                    "enabled": True,
                    "key": host,
                    "record_type": self.dns_record_type,
                    "value": self.traefik_ip,
                },
            )

            if add_static_dns_entry_response.status_code == 200:
                logging.info(f"Successfully added DNS entry {host} in UniFi API.")
            else:
                logging.error(
                    f"Failed to add static DNS entry {host} in UniFi API. Status code: {add_static_dns_entry_response.status_code}"
                )

        logging.info("Synchronization completed.")

    def fetch_traefik_domains(self, allowed_hostnames=None):
        """
        Fetches and returns hostnames from Traefik routers.

        Args:
            allowed_hostnames: Optional set of hostnames to filter by.
                              If None, all hostnames are returned.
                              If a set, only hostnames in the set are returned.
        """

        logging.debug("Extracting hostnames from Traefik...")

        traefik_session = requests.Session()

        if self.ignore_ssl_warnings:
            traefik_session.verify = False

        traefik_routers_response = traefik_session.get(
            f"{self.traefik_api_url}http/routers"
        )

        if traefik_routers_response.status_code != 200:
            raise ValueError(
                f"Failed to query Traefik API. Status code: {traefik_routers_response.status_code}"
            )

        traefik_domains = []

        for router in traefik_routers_response.json():
            if "rule" in router and "Host(" in router["rule"]:
                logging.debug(f"Router: {router['name']} with rule: {router['rule']}")
                match = re.search(r"Host\(`([^`]+)`\)", router["rule"])

                if not match:
                    logging.debug(f"No DNS name found in the rule {router['rule']}.")
                    continue

                dns_name = match.group(1)

                # Apply Docker label filter if configured
                if allowed_hostnames is not None:
                    if dns_name not in allowed_hostnames:
                        logging.debug(
                            f"Skipping hostname {dns_name} - not in allowed list from Docker labels."
                        )
                        continue
                    logging.debug(
                        f"Including hostname {dns_name} - matches Docker label filter."
                    )

                logging.debug(f"Extracted hostname from Traefik: {dns_name}")
                traefik_domains.append(dns_name)

        return traefik_domains
