import os
import requests
import re
import json
import logging

# global variables for optimized syncs
traefik_domains_json_last_run = "[]"
number_of_syncs_without_change = 0
is_first_run = True

def sync():
    """
    Synchronizes Traefik hostnames with Unifi static DNS entries.
    - Fetches routers from Traefik API
    - Extracts hostnames from router rules
    - Compares them with existing Unifi static DNS entries
    - Adds missing hosts or updates outdated ones
    """

    global traefik_domains_json_last_run
    global number_of_syncs_without_change
    global is_first_run

    logging.info("Starting synchronization...")

    # Load environment variables
    traefik_ip = os.environ.get("TRAEFIK_IP")
    traefik_api_url = os.environ.get("TRAEFIK_API_URL")
    unifi_url = os.environ.get("UNIFI_URL")
    unifi_username = os.environ.get("UNIFI_USERNAME")
    unifi_password = os.environ.get("UNIFI_PASSWORD")
    ignore_ssl_warnings = os.environ.get("IGNORE_SSL_WARNINGS")
    dns_record_type = os.environ.get("DNS_RECORD_TYPE", "A")

    # Validate required environment variables
    for key, value in {
        "UNIFI_URL": unifi_url,
        "UNIFI_USERNAME": unifi_username,
        "UNIFI_PASSWORD": unifi_password,
        "TRAEFIK_IP": traefik_ip,
        "TRAEFIK_API_URL": traefik_api_url,
    }.items():
        if value is None:
            raise ValueError(f"Required environment variable {key} is not set.")

    # Validate optional environment variables    
    if dns_record_type not in ("A", "CNAME"):
        raise ValueError(f"Invalid DNS_RECORD_TYPE: {dns_record_type}. Allowed values are 'A' or 'CNAME'.")

    if is_first_run:
        logging.debug(f"UNIFI_URL={unifi_url}")
        logging.debug(f"TRAEFIK_API_URL={traefik_api_url}")

        if ignore_ssl_warnings:
            # we show our own warning on startup, no warning on each request requried
            requests.packages.urllib3.disable_warnings()
            logging.warning(
                f"IGNORE_SSL_WARNINGS={ignore_ssl_warnings} - "
                "Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#tls-warnings")

    logging.debug("Extracting hostnames from Traefik...")
    # Request routers from Traefik API
    traefik_routers_response = requests.get(f"{traefik_api_url}http/routers", verify=not ignore_ssl_warnings)

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
            logging.debug(f"Extracted hostname from Traefik: {dns_name}")

            traefik_domains.append(dns_name)

    if not traefik_domains:
        logging.warning("No hostnames found in Traefik routers.")
        return

    # Detect changes compared to previous run
    traefik_domains_json = json.dumps(traefik_domains, indent=4)
    traefik_domains_json_changed = traefik_domains_json != traefik_domains_json_last_run;

    if traefik_domains_json_changed:
        number_of_syncs_without_change = 0
        if is_first_run:
            logging.debug(f"Extracted {len(traefik_domains)} hostnames in Traefik routers in first run.")
        else:
            logging.debug(f"Extracted {len(traefik_domains)} hostnames in Traefik routers and Detected changes since last run.")
    else:
        number_of_syncs_without_change += 1
        logging.info(
            f"No changes since last sync ({number_of_syncs_without_change} time(s) since last full sync)."
        )

    is_first_run = False
    traefik_domains_json_last_run = traefik_domains_json

    # Do not sync with unifi if there are no changes in the Traefik hostnames, but for saftey do it every 5th run so that manually modified dns records get fixed too.
    if not traefik_domains_json_changed:

        if number_of_syncs_without_change < 5:
            logging.debug("Skipping Unifi update due to no changes.")
            return
        
        # reset counter and do full sync
        logging.debug("Performing full sync with Unifi despite no changes in Traefik hostnames.")
        number_of_syncs_without_change = 0

    # Login to Unifi
    unifi_session = requests.Session()
    if ignore_ssl_warnings:
        unifi_session.verify = False

    logging.debug(f"Logging in to Unifi {unifi_url} ...")
    unifi_login_response = unifi_session.post(
        f"{unifi_url}api/auth/login",
        json={"username": unifi_username, "password": unifi_password},
    )

    if unifi_login_response.status_code != 200:
        raise ValueError(
            f"Failed to login to Unifi API. Status code: {unifi_login_response.status_code}"
        )

    logging.debug("Login successful, updating CSRF token.")
    unifi_session.headers.update(
        {"X-Csrf-Token": unifi_login_response.headers["X-Csrf-Token"]}
    )

    # Fetch existing static DNS entries from Unifi
    logging.debug("Fetching existing static DNS entries from Unifi...")
    get_static_dns_entries_response = unifi_session.get(
        f"{unifi_url}proxy/network/v2/api/site/default/static-dns"
    )

    if get_static_dns_entries_response.status_code != 200:
        raise ValueError(
            f"Failed to get static DNS entries from Unifi API. Status code: {get_static_dns_entries_response.status_code}"
        )

    unifi_static_dns_entries = [
        (entry["key"], entry["value"], entry["_id"])
        for entry in get_static_dns_entries_response.json()
    ]

    entries_to_update = []
    hosts_to_add = []

    # Compare Traefik hostnames with Unifi static DNS entries
    for dns_name in traefik_domains:
        already_exists = False
        for entry in unifi_static_dns_entries:
            if entry[0] == dns_name:
                already_exists = True
                if entry[1] != traefik_ip:
                    logging.info(
                        f"DNS name {dns_name} already exists but with different value {entry[1]}. Schedule update to {traefik_ip}."
                    )
                    entries_to_update.append((entry[0], entry[2]))
                break

        if not already_exists:
            logging.info(f"Schedule adding DNS name {dns_name} to Unifi static DNS entries.")
            hosts_to_add.append(dns_name)

    logging.info(
        f"DNS entries to update: {len(entries_to_update)}, "
        f"new DNS entries to add: {len(hosts_to_add)}"
    )

    if not entries_to_update and not hosts_to_add:
        logging.debug("No changes required for Unifi static DNS entries.")
    else:
        logging.info(f"Updating DNS entries using DNS record type: {dns_record_type}")


    # Update existing entries
    for key, entry_id in entries_to_update:
        update_static_dns_entry_response = unifi_session.put(
            f"{unifi_url}proxy/network/v2/api/site/default/static-dns/{entry_id}",
            json={
                "enabled": True,
                "key": key,
                "record_type": dns_record_type,
                "value": traefik_ip,
                "_id": entry_id,
            },
        )

        if update_static_dns_entry_response.status_code == 200:
            logging.info(f"Successfully updated DNS entry {key} in Unifi API.")
        else:
            logging.error(
                f"Failed to update static DNS entry {key} in Unifi API. Status code: {update_static_dns_entry_response.status_code}"
            )

    # Add new entries
    for host in hosts_to_add:
        add_static_dns_entry_response = unifi_session.post(
            f"{unifi_url}proxy/network/v2/api/site/default/static-dns",
            json={
                "enabled": True,
                "key": host,
                "record_type": dns_record_type,
                "value": traefik_ip,
            },
        )

        if add_static_dns_entry_response.status_code == 200:
            logging.info(f"Successfully added DNS entry {host} in Unifi API.")
        else:
            logging.error(
                f"Failed to add static DNS entry {host} in Unifi API. Status code: {add_static_dns_entry_response.status_code}"
            )

    logging.debug("Synchronization completed.")
