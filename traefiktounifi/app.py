import os
import requests
import re


def sync():
    traefik_ip = os.environ.get("TRAEFIK_IP")
    traefik_api_url = os.environ.get("TRAEFIK_API_URL")
    unifi_url = os.environ.get("UNIFI_URL")
    unifi_username = os.environ.get("UNIFI_USERNAME")
    unifi_password = os.environ.get("UNIFI_PASSWORD")
    ignore_ssl_warnings = os.environ.get("INGNORE_SSL_WARNINGS")

    if unifi_url is None:
        raise ValueError("UNIFI_URL environment variable is not set.")

    if unifi_username is None:
        raise ValueError("UNIFI_USERNAME environment variable is not set.")

    if unifi_password is None:
        raise ValueError("UNIFI_PASSWORD environment variable is not set.")

    if traefik_ip is None:
        raise ValueError("TRAEFIK_IP environment variable is not set.")

    if traefik_api_url is None:
        raise ValueError("TRAEFIK_API_URL environment variable is not set.")

    if ignore_ssl_warnings is None:
        ignore_ssl_warnings = False

    print(f"The value of UNIFI_URL is: {unifi_url}")
    print(f"The value of TRAEFIK_API_URL is: {traefik_api_url}")

    traefik_routers_response = requests.get(f"{traefik_api_url}http/routers")

    if traefik_routers_response.status_code != 200:
        raise ValueError(
            f"Failed to make request to Traefik API. Status code: {traefik_routers_response.status_code}"
        )

    traefik_domains = []

    for router in traefik_routers_response.json():
        if "rule" in router and "Host(" in router["rule"]:
            print(f"Router: {router['name']} with rule: {router['rule']}")

            match = re.search(r"Host\(`([^`]+)`\)", router["rule"])
            if not match:
                print("No DNS name found in the rule.")
                continue

            dns_name = match.group(1)
            print(f"Extracted DNS name: {dns_name}")

            traefik_domains.append(dns_name)

    if not traefik_domains:
        print("No DNS names found in Traefik routers.")
        exit(0)

    unifi_session = requests.Session()

    if ignore_ssl_warnings:
        requests.packages.urllib3.disable_warnings()
        unifi_session.verify = False

    unifi_login_response = unifi_session.post(
        f"{unifi_url}api/auth/login",
        json={"username": unifi_username, "password": unifi_password},
    )

    if unifi_login_response.status_code != 200:
        raise ValueError(
            f"Failed to login to Unifi API. Status code: {unifi_login_response.status_code}"
        )

    unifi_session.headers.update(
        {"X-Csrf-Token": unifi_login_response.headers["X-Csrf-Token"]}
    )

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

    for dns_name in traefik_domains:
        print(f"Checking DNS name {dns_name} in Unifi static DNS entries.")

        already_exists = False
        for entry in unifi_static_dns_entries:
            if entry[0] == dns_name:
                already_exists = True
                if entry[1] != traefik_ip:
                    print(
                        f"DNS name {dns_name} already exists but with different IP address {entry[1]}. Updating it to {traefik_ip}."
                    )
                    entries_to_update.append((entry[0], entry[2]))
                break

        if not already_exists:
            print(f"Adding DNS name {dns_name} to Unifi static DNS entries.")
            hosts_to_add.append(dns_name)

    for entry in entries_to_update:
        update_static_dns_entry_response = unifi_session.put(
            f"{unifi_url}proxy/network/v2/api/site/default/static-dns/{entry[1]}",
            json={
                "enabled": True,
                "key": entry[0],
                "record_type": "A",
                "value": traefik_ip,
                "_id": entry[1],
            },
        )

        if update_static_dns_entry_response.status_code == 200:
            print(f"Updated static DNS entry {entry[0]} in Unifi API.")
        else:
            print(
                f"Failed to update static DNS entry in Unifi API. Status code: {update_static_dns_entry_response.status_code}"
            )

    for host in hosts_to_add:
        add_static_dns_entry_response = unifi_session.post(
            f"{unifi_url}proxy/network/v2/api/site/default/static-dns",
            json={
                "enabled": True,
                "key": host,
                "record_type": "A",
                "value": traefik_ip,
            },
        )

        if add_static_dns_entry_response.status_code == 200:
            print(f"Added static DNS entry {host} in Unifi API.")
        else:
            print(
                f"Failed to add static DNS entry in Unifi API. Status code: {add_static_dns_entry_response.status_code}"
            )
