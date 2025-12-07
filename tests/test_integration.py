"""Integration tests for traefiktounifi."""

import pytest
import responses

from traefiktounifi.app import TraefikToUnifi


class TestIntegrationFullWorkflow:
    """Integration tests for full workflow scenarios."""

    @responses.activate
    def test_full_workflow_add_and_update(self, monkeypatch):
        """Test a complete workflow of adding and updating DNS entries."""
        monkeypatch.setenv("UNIFI_URL", "https://unifi.example.com/")
        monkeypatch.setenv("UNIFI_API_KEY", "api-key-12345")
        monkeypatch.setenv("TRAEFIK_IP", "192.168.1.10")
        monkeypatch.setenv("TRAEFIK_API_URL", "http://traefik.example.com/api/")
        monkeypatch.setenv("FULL_SYNC_INTERVAL", "2")

        app = TraefikToUnifi()

        # First sync: Add initial domains
        responses.add(
            responses.GET,
            "http://traefik.example.com/api/http/routers",
            json=[
                {"name": "router1", "rule": "Host(`app1.example.com`)"},
                {"name": "router2", "rule": "Host(`app2.example.com`)"},
            ],
            status=200,
        )
        responses.add(
            responses.GET,
            "https://unifi.example.com/proxy/network/v2/api/site/default/static-dns",
            json=[],
            status=200,
        )
        responses.add(
            responses.POST,
            "https://unifi.example.com/proxy/network/v2/api/site/default/static-dns",
            json={"_id": "entry1"},
            status=200,
        )
        responses.add(
            responses.POST,
            "https://unifi.example.com/proxy/network/v2/api/site/default/static-dns",
            json={"_id": "entry2"},
            status=200,
        )

        app.sync()
        assert len(responses.calls) == 4

        # Second sync: No changes, should skip UniFi update
        responses.add(
            responses.GET,
            "http://traefik.example.com/api/http/routers",
            json=[
                {"name": "router1", "rule": "Host(`app1.example.com`)"},
                {"name": "router2", "rule": "Host(`app2.example.com`)"},
            ],
            status=200,
        )

        app.sync()
        assert len(responses.calls) == 5  # Just Traefik call

        # Third sync: Add a new domain
        responses.add(
            responses.GET,
            "http://traefik.example.com/api/http/routers",
            json=[
                {"name": "router1", "rule": "Host(`app1.example.com`)"},
                {"name": "router2", "rule": "Host(`app2.example.com`)"},
                {"name": "router3", "rule": "Host(`app3.example.com`)"},
            ],
            status=200,
        )
        responses.add(
            responses.GET,
            "https://unifi.example.com/proxy/network/v2/api/site/default/static-dns",
            json=[
                {"key": "app1.example.com", "value": "192.168.1.10", "_id": "entry1"},
                {"key": "app2.example.com", "value": "192.168.1.10", "_id": "entry2"},
            ],
            status=200,
        )
        responses.add(
            responses.POST,
            "https://unifi.example.com/proxy/network/v2/api/site/default/static-dns",
            json={"_id": "entry3"},
            status=200,
        )

        app.sync()
        assert len(responses.calls) == 8  # +3 calls

    @responses.activate
    def test_full_workflow_with_ip_change(self, monkeypatch):
        """Test workflow when Traefik IP changes."""
        monkeypatch.setenv("UNIFI_URL", "https://unifi.example.com/")
        monkeypatch.setenv("UNIFI_API_KEY", "api-key-12345")
        monkeypatch.setenv("TRAEFIK_IP", "192.168.1.10")
        monkeypatch.setenv("TRAEFIK_API_URL", "http://traefik.example.com/api/")

        app = TraefikToUnifi()

        # Mock Traefik API
        responses.add(
            responses.GET,
            "http://traefik.example.com/api/http/routers",
            json=[{"name": "router1", "rule": "Host(`example.com`)"}],
            status=200,
        )

        # Mock UniFi with old IP
        responses.add(
            responses.GET,
            "https://unifi.example.com/proxy/network/v2/api/site/default/static-dns",
            json=[{"key": "example.com", "value": "192.168.1.99", "_id": "entry1"}],
            status=200,
        )

        # Mock UniFi PUT to update IP
        responses.add(
            responses.PUT,
            "https://unifi.example.com/proxy/network/v2/api/site/default/static-dns/entry1",
            json={"_id": "entry1"},
            status=200,
        )

        app.sync()

        # Verify the PUT request was made
        put_request = [call for call in responses.calls if call.request.method == "PUT"]
        assert len(put_request) == 1
        assert b"192.168.1.10" in put_request[0].request.body

    @responses.activate
    def test_full_workflow_with_cname_records(self, monkeypatch):
        """Test workflow with CNAME DNS record type."""
        monkeypatch.setenv("UNIFI_URL", "https://unifi.example.com/")
        monkeypatch.setenv("UNIFI_API_KEY", "api-key-12345")
        monkeypatch.setenv("TRAEFIK_IP", "traefik.example.com")
        monkeypatch.setenv("TRAEFIK_API_URL", "http://traefik.example.com/api/")
        monkeypatch.setenv("DNS_RECORD_TYPE", "CNAME")

        app = TraefikToUnifi()

        # Mock Traefik API
        responses.add(
            responses.GET,
            "http://traefik.example.com/api/http/routers",
            json=[{"name": "router1", "rule": "Host(`app.example.com`)"}],
            status=200,
        )

        # Mock UniFi GET (empty)
        responses.add(
            responses.GET,
            "https://unifi.example.com/proxy/network/v2/api/site/default/static-dns",
            json=[],
            status=200,
        )

        # Mock UniFi POST
        responses.add(
            responses.POST,
            "https://unifi.example.com/proxy/network/v2/api/site/default/static-dns",
            json={"_id": "entry1"},
            status=200,
        )

        app.sync()

        # Verify POST request contains CNAME record type
        post_request = [
            call for call in responses.calls if call.request.method == "POST"
        ]
        assert len(post_request) == 1
        assert b'"record_type": "CNAME"' in post_request[0].request.body
        assert b'"value": "traefik.example.com"' in post_request[0].request.body

    @responses.activate
    def test_error_handling_traefik_api_failure(self, monkeypatch):
        """Test error handling when Traefik API fails."""
        monkeypatch.setenv("UNIFI_URL", "https://unifi.example.com/")
        monkeypatch.setenv("UNIFI_API_KEY", "api-key-12345")
        monkeypatch.setenv("TRAEFIK_IP", "192.168.1.10")
        monkeypatch.setenv("TRAEFIK_API_URL", "http://traefik.example.com/api/")

        app = TraefikToUnifi()

        # Mock Traefik API failure
        responses.add(
            responses.GET,
            "http://traefik.example.com/api/http/routers",
            json={"error": "Internal server error"},
            status=500,
        )

        with pytest.raises(ValueError, match="Failed to query Traefik API"):
            app.sync()

    @responses.activate
    def test_error_handling_unifi_api_failure(self, monkeypatch):
        """Test error handling when UniFi API fails."""
        monkeypatch.setenv("UNIFI_URL", "https://unifi.example.com/")
        monkeypatch.setenv("UNIFI_API_KEY", "api-key-12345")
        monkeypatch.setenv("TRAEFIK_IP", "192.168.1.10")
        monkeypatch.setenv("TRAEFIK_API_URL", "http://traefik.example.com/api/")

        app = TraefikToUnifi()

        # Mock Traefik API success
        responses.add(
            responses.GET,
            "http://traefik.example.com/api/http/routers",
            json=[{"name": "router1", "rule": "Host(`example.com`)"}],
            status=200,
        )

        # Mock UniFi API failure
        responses.add(
            responses.GET,
            "https://unifi.example.com/proxy/network/v2/api/site/default/static-dns",
            json={"error": "Unauthorized"},
            status=401,
        )

        with pytest.raises(ValueError, match="Failed to get static DNS entries"):
            app.sync()

    @responses.activate
    def test_periodic_full_sync(self, monkeypatch):
        """Test that periodic full sync happens even without changes."""
        monkeypatch.setenv("UNIFI_URL", "https://unifi.example.com/")
        monkeypatch.setenv("UNIFI_API_KEY", "api-key-12345")
        monkeypatch.setenv("TRAEFIK_IP", "192.168.1.10")
        monkeypatch.setenv("TRAEFIK_API_URL", "http://traefik.example.com/api/")
        monkeypatch.setenv("FULL_SYNC_INTERVAL", "3")

        app = TraefikToUnifi()

        # First sync
        responses.add(
            responses.GET,
            "http://traefik.example.com/api/http/routers",
            json=[{"name": "router1", "rule": "Host(`example.com`)"}],
            status=200,
        )
        responses.add(
            responses.GET,
            "https://unifi.example.com/proxy/network/v2/api/site/default/static-dns",
            json=[{"key": "example.com", "value": "192.168.1.10", "_id": "entry1"}],
            status=200,
        )
        app.sync()
        assert len(responses.calls) == 2

        # Second sync - no changes
        responses.add(
            responses.GET,
            "http://traefik.example.com/api/http/routers",
            json=[{"name": "router1", "rule": "Host(`example.com`)"}],
            status=200,
        )
        app.sync()
        assert len(responses.calls) == 3  # Only Traefik

        # Third sync - no changes
        responses.add(
            responses.GET,
            "http://traefik.example.com/api/http/routers",
            json=[{"name": "router1", "rule": "Host(`example.com`)"}],
            status=200,
        )
        app.sync()
        assert len(responses.calls) == 4  # Only Traefik

        # Fourth sync - full sync should trigger
        responses.add(
            responses.GET,
            "http://traefik.example.com/api/http/routers",
            json=[{"name": "router1", "rule": "Host(`example.com`)"}],
            status=200,
        )
        responses.add(
            responses.GET,
            "https://unifi.example.com/proxy/network/v2/api/site/default/static-dns",
            json=[{"key": "example.com", "value": "192.168.1.10", "_id": "entry1"}],
            status=200,
        )
        app.sync()
        assert len(responses.calls) == 6  # Traefik + UniFi
