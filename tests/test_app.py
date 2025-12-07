"""Unit tests for the app module (TraefikToUnifi class)."""

from unittest.mock import patch

import pytest
import responses

from traefiktounifi.app import TraefikToUnifi


class TestTraefikToUnifiInit:
    """Test TraefikToUnifi initialization."""

    def test_init_with_username_password(self, monkeypatch):
        """Test initialization with username and password."""
        monkeypatch.setenv("UNIFI_URL", "https://unifi.example.com/")
        monkeypatch.setenv("UNIFI_USERNAME", "admin")
        monkeypatch.setenv("UNIFI_PASSWORD", "password")
        monkeypatch.setenv("TRAEFIK_IP", "192.168.1.10")
        monkeypatch.setenv("TRAEFIK_API_URL", "http://traefik.example.com/api/")

        app = TraefikToUnifi()

        assert app.unifi_url == "https://unifi.example.com/"
        assert app.unifi_username == "admin"
        assert app.unifi_password == "password"
        assert app.traefik_ip == "192.168.1.10"
        assert app.traefik_api_url == "http://traefik.example.com/api/"
        assert app.dns_record_type == "A"
        assert app.full_sync_interval == 5
        assert app.ignore_ssl_warnings is False

    def test_init_with_api_key(self, monkeypatch):
        """Test initialization with API key."""
        monkeypatch.setenv("UNIFI_URL", "https://unifi.example.com/")
        monkeypatch.setenv("UNIFI_API_KEY", "api-key-12345")
        monkeypatch.setenv("TRAEFIK_IP", "192.168.1.10")
        monkeypatch.setenv("TRAEFIK_API_URL", "http://traefik.example.com/api/")

        app = TraefikToUnifi()

        assert app.unifi_api_key == "api-key-12345"
        assert app.unifi_username is None
        assert app.unifi_password is None

    def test_init_with_custom_dns_record_type(self, monkeypatch):
        """Test initialization with CNAME DNS record type."""
        monkeypatch.setenv("UNIFI_URL", "https://unifi.example.com/")
        monkeypatch.setenv("UNIFI_API_KEY", "api-key-12345")
        monkeypatch.setenv("TRAEFIK_IP", "traefik.example.com")
        monkeypatch.setenv("TRAEFIK_API_URL", "http://traefik.example.com/api/")
        monkeypatch.setenv("DNS_RECORD_TYPE", "CNAME")

        app = TraefikToUnifi()

        assert app.dns_record_type == "CNAME"

    def test_init_with_custom_full_sync_interval(self, monkeypatch):
        """Test initialization with custom full sync interval."""
        monkeypatch.setenv("UNIFI_URL", "https://unifi.example.com/")
        monkeypatch.setenv("UNIFI_API_KEY", "api-key-12345")
        monkeypatch.setenv("TRAEFIK_IP", "192.168.1.10")
        monkeypatch.setenv("TRAEFIK_API_URL", "http://traefik.example.com/api/")
        monkeypatch.setenv("FULL_SYNC_INTERVAL", "10")

        app = TraefikToUnifi()

        assert app.full_sync_interval == 10

    def test_init_with_ignore_ssl_warnings(self, monkeypatch):
        """Test initialization with SSL warnings disabled."""
        monkeypatch.setenv("UNIFI_URL", "https://unifi.example.com/")
        monkeypatch.setenv("UNIFI_API_KEY", "api-key-12345")
        monkeypatch.setenv("TRAEFIK_IP", "192.168.1.10")
        monkeypatch.setenv("TRAEFIK_API_URL", "http://traefik.example.com/api/")
        monkeypatch.setenv("IGNORE_SSL_WARNINGS", "true")

        with patch("traefiktounifi.app.urllib3.disable_warnings") as mock_disable:
            app = TraefikToUnifi()
            mock_disable.assert_called_once()

        assert app.ignore_ssl_warnings is True

    def test_init_missing_unifi_url(self, monkeypatch):
        """Test initialization fails without UNIFI_URL."""
        monkeypatch.setenv("UNIFI_API_KEY", "api-key-12345")
        monkeypatch.setenv("TRAEFIK_IP", "192.168.1.10")
        monkeypatch.setenv("TRAEFIK_API_URL", "http://traefik.example.com/api/")

        with pytest.raises(ValueError, match="UNIFI_URL"):
            TraefikToUnifi()

    def test_init_missing_traefik_ip(self, monkeypatch):
        """Test initialization fails without TRAEFIK_IP."""
        monkeypatch.setenv("UNIFI_URL", "https://unifi.example.com/")
        monkeypatch.setenv("UNIFI_API_KEY", "api-key-12345")
        monkeypatch.setenv("TRAEFIK_API_URL", "http://traefik.example.com/api/")

        with pytest.raises(ValueError, match="TRAEFIK_IP"):
            TraefikToUnifi()

    def test_init_missing_traefik_api_url(self, monkeypatch):
        """Test initialization fails without TRAEFIK_API_URL."""
        monkeypatch.setenv("UNIFI_URL", "https://unifi.example.com/")
        monkeypatch.setenv("UNIFI_API_KEY", "api-key-12345")
        monkeypatch.setenv("TRAEFIK_IP", "192.168.1.10")

        with pytest.raises(ValueError, match="TRAEFIK_API_URL"):
            TraefikToUnifi()

    def test_init_missing_auth_credentials(self, monkeypatch):
        """Test initialization fails without authentication credentials."""
        monkeypatch.setenv("UNIFI_URL", "https://unifi.example.com/")
        monkeypatch.setenv("TRAEFIK_IP", "192.168.1.10")
        monkeypatch.setenv("TRAEFIK_API_URL", "http://traefik.example.com/api/")

        with pytest.raises(
            ValueError,
            match="Either UNIFI_USERNAME and UNIFI_PASSWORD or UNIFI_API_KEY",
        ):
            TraefikToUnifi()

    def test_init_invalid_dns_record_type(self, monkeypatch):
        """Test initialization fails with invalid DNS record type."""
        monkeypatch.setenv("UNIFI_URL", "https://unifi.example.com/")
        monkeypatch.setenv("UNIFI_API_KEY", "api-key-12345")
        monkeypatch.setenv("TRAEFIK_IP", "192.168.1.10")
        monkeypatch.setenv("TRAEFIK_API_URL", "http://traefik.example.com/api/")
        monkeypatch.setenv("DNS_RECORD_TYPE", "INVALID")

        with pytest.raises(ValueError, match="Invalid DNS_RECORD_TYPE"):
            TraefikToUnifi()

    def test_init_invalid_full_sync_interval(self, monkeypatch):
        """Test initialization fails with invalid full sync interval."""
        monkeypatch.setenv("UNIFI_URL", "https://unifi.example.com/")
        monkeypatch.setenv("UNIFI_API_KEY", "api-key-12345")
        monkeypatch.setenv("TRAEFIK_IP", "192.168.1.10")
        monkeypatch.setenv("TRAEFIK_API_URL", "http://traefik.example.com/api/")
        monkeypatch.setenv("FULL_SYNC_INTERVAL", "1")

        with pytest.raises(ValueError, match="Invalid FULL_SYNC_INTERVAL"):
            TraefikToUnifi()


class TestFetchTraefikDomains:
    """Test fetch_traefik_domains method."""

    @responses.activate
    def test_fetch_traefik_domains_success(self, monkeypatch):
        """Test fetching domains from Traefik API."""
        monkeypatch.setenv("UNIFI_URL", "https://unifi.example.com/")
        monkeypatch.setenv("UNIFI_API_KEY", "api-key-12345")
        monkeypatch.setenv("TRAEFIK_IP", "192.168.1.10")
        monkeypatch.setenv("TRAEFIK_API_URL", "http://traefik.example.com/api/")

        app = TraefikToUnifi()

        responses.add(
            responses.GET,
            "http://traefik.example.com/api/http/routers",
            json=[
                {
                    "name": "router1",
                    "rule": "Host(`example.com`)",
                },
                {
                    "name": "router2",
                    "rule": "Host(`test.com`) && PathPrefix(`/api`)",
                },
                {
                    "name": "router3",
                    "rule": "PathPrefix(`/health`)",
                },
            ],
            status=200,
        )

        domains = app.fetch_traefik_domains()

        assert len(domains) == 2
        assert "example.com" in domains
        assert "test.com" in domains

    @responses.activate
    def test_fetch_traefik_domains_empty(self, monkeypatch):
        """Test fetching domains when no Host rules exist."""
        monkeypatch.setenv("UNIFI_URL", "https://unifi.example.com/")
        monkeypatch.setenv("UNIFI_API_KEY", "api-key-12345")
        monkeypatch.setenv("TRAEFIK_IP", "192.168.1.10")
        monkeypatch.setenv("TRAEFIK_API_URL", "http://traefik.example.com/api/")

        app = TraefikToUnifi()

        responses.add(
            responses.GET,
            "http://traefik.example.com/api/http/routers",
            json=[
                {
                    "name": "router1",
                    "rule": "PathPrefix(`/api`)",
                }
            ],
            status=200,
        )

        domains = app.fetch_traefik_domains()

        assert len(domains) == 0

    @responses.activate
    def test_fetch_traefik_domains_api_error(self, monkeypatch):
        """Test fetching domains when Traefik API returns error."""
        monkeypatch.setenv("UNIFI_URL", "https://unifi.example.com/")
        monkeypatch.setenv("UNIFI_API_KEY", "api-key-12345")
        monkeypatch.setenv("TRAEFIK_IP", "192.168.1.10")
        monkeypatch.setenv("TRAEFIK_API_URL", "http://traefik.example.com/api/")

        app = TraefikToUnifi()

        responses.add(
            responses.GET,
            "http://traefik.example.com/api/http/routers",
            json={"error": "Internal server error"},
            status=500,
        )

        with pytest.raises(ValueError, match="Failed to query Traefik API"):
            app.fetch_traefik_domains()


class TestSync:
    """Test sync method."""

    @responses.activate
    def test_sync_add_new_entries(self, monkeypatch):
        """Test syncing when new DNS entries need to be added."""
        monkeypatch.setenv("UNIFI_URL", "https://unifi.example.com/")
        monkeypatch.setenv("UNIFI_API_KEY", "api-key-12345")
        monkeypatch.setenv("TRAEFIK_IP", "192.168.1.10")
        monkeypatch.setenv("TRAEFIK_API_URL", "http://traefik.example.com/api/")

        app = TraefikToUnifi()

        # Mock Traefik API response
        responses.add(
            responses.GET,
            "http://traefik.example.com/api/http/routers",
            json=[
                {"name": "router1", "rule": "Host(`example.com`)"},
                {"name": "router2", "rule": "Host(`test.com`)"},
            ],
            status=200,
        )

        # Mock UniFi static DNS GET response (empty)
        responses.add(
            responses.GET,
            "https://unifi.example.com/proxy/network/v2/api/site/default/static-dns",
            json=[],
            status=200,
        )

        # Mock UniFi POST responses for adding entries
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

        assert len(responses.calls) == 4  # 1 Traefik + 1 UniFi GET + 2 UniFi POST

    @responses.activate
    def test_sync_update_existing_entries(self, monkeypatch):
        """Test syncing when existing DNS entries need to be updated."""
        monkeypatch.setenv("UNIFI_URL", "https://unifi.example.com/")
        monkeypatch.setenv("UNIFI_API_KEY", "api-key-12345")
        monkeypatch.setenv("TRAEFIK_IP", "192.168.1.10")
        monkeypatch.setenv("TRAEFIK_API_URL", "http://traefik.example.com/api/")

        app = TraefikToUnifi()

        # Mock Traefik API response
        responses.add(
            responses.GET,
            "http://traefik.example.com/api/http/routers",
            json=[{"name": "router1", "rule": "Host(`example.com`)"}],
            status=200,
        )

        # Mock UniFi static DNS GET response with existing entry with wrong IP
        responses.add(
            responses.GET,
            "https://unifi.example.com/proxy/network/v2/api/site/default/static-dns",
            json=[{"key": "example.com", "value": "192.168.1.99", "_id": "entry1"}],
            status=200,
        )

        # Mock UniFi PUT response for updating entry
        responses.add(
            responses.PUT,
            "https://unifi.example.com/proxy/network/v2/api/site/default/static-dns/entry1",
            json={"_id": "entry1"},
            status=200,
        )

        app.sync()

        assert len(responses.calls) == 3  # 1 Traefik + 1 UniFi GET + 1 UniFi PUT

    @responses.activate
    def test_sync_no_changes(self, monkeypatch):
        """Test syncing when no changes are required."""
        monkeypatch.setenv("UNIFI_URL", "https://unifi.example.com/")
        monkeypatch.setenv("UNIFI_API_KEY", "api-key-12345")
        monkeypatch.setenv("TRAEFIK_IP", "192.168.1.10")
        monkeypatch.setenv("TRAEFIK_API_URL", "http://traefik.example.com/api/")

        app = TraefikToUnifi()

        # Mock Traefik API response
        responses.add(
            responses.GET,
            "http://traefik.example.com/api/http/routers",
            json=[{"name": "router1", "rule": "Host(`example.com`)"}],
            status=200,
        )

        # Mock UniFi static DNS GET response with correct entry
        responses.add(
            responses.GET,
            "https://unifi.example.com/proxy/network/v2/api/site/default/static-dns",
            json=[{"key": "example.com", "value": "192.168.1.10", "_id": "entry1"}],
            status=200,
        )

        app.sync()

        assert len(responses.calls) == 2  # 1 Traefik + 1 UniFi GET, no updates

    @responses.activate
    def test_sync_no_traefik_domains(self, monkeypatch):
        """Test syncing when no Traefik domains are found."""
        monkeypatch.setenv("UNIFI_URL", "https://unifi.example.com/")
        monkeypatch.setenv("UNIFI_API_KEY", "api-key-12345")
        monkeypatch.setenv("TRAEFIK_IP", "192.168.1.10")
        monkeypatch.setenv("TRAEFIK_API_URL", "http://traefik.example.com/api/")

        app = TraefikToUnifi()

        # Mock Traefik API response with no Host rules
        responses.add(
            responses.GET,
            "http://traefik.example.com/api/http/routers",
            json=[],
            status=200,
        )

        app.sync()

        # Should only call Traefik API, not UniFi API
        assert len(responses.calls) == 1

    @responses.activate
    def test_sync_skip_when_no_changes_multiple_runs(self, monkeypatch):
        """Test that sync skips UniFi update when no changes for multiple runs."""
        monkeypatch.setenv("UNIFI_URL", "https://unifi.example.com/")
        monkeypatch.setenv("UNIFI_API_KEY", "api-key-12345")
        monkeypatch.setenv("TRAEFIK_IP", "192.168.1.10")
        monkeypatch.setenv("TRAEFIK_API_URL", "http://traefik.example.com/api/")
        monkeypatch.setenv("FULL_SYNC_INTERVAL", "2")

        app = TraefikToUnifi()

        # Mock Traefik API response
        responses.add(
            responses.GET,
            "http://traefik.example.com/api/http/routers",
            json=[{"name": "router1", "rule": "Host(`example.com`)"}],
            status=200,
        )
        responses.add(
            responses.GET,
            "http://traefik.example.com/api/http/routers",
            json=[{"name": "router1", "rule": "Host(`example.com`)"}],
            status=200,
        )
        responses.add(
            responses.GET,
            "http://traefik.example.com/api/http/routers",
            json=[{"name": "router1", "rule": "Host(`example.com`)"}],
            status=200,
        )

        # Mock UniFi static DNS GET responses
        responses.add(
            responses.GET,
            "https://unifi.example.com/proxy/network/v2/api/site/default/static-dns",
            json=[{"key": "example.com", "value": "192.168.1.10", "_id": "entry1"}],
            status=200,
        )
        responses.add(
            responses.GET,
            "https://unifi.example.com/proxy/network/v2/api/site/default/static-dns",
            json=[{"key": "example.com", "value": "192.168.1.10", "_id": "entry1"}],
            status=200,
        )

        # First sync
        app.sync()
        assert len(responses.calls) == 2  # 1 Traefik + 1 UniFi GET

        # Second sync - should skip UniFi
        app.sync()
        assert len(responses.calls) == 3  # +1 Traefik only

        # Third sync - should do full sync (counter reaches FULL_SYNC_INTERVAL)
        app.sync()
        assert len(responses.calls) == 5  # +1 Traefik + 1 UniFi GET

    @responses.activate
    def test_sync_with_username_password_auth(self, monkeypatch):
        """Test syncing with username/password authentication."""
        monkeypatch.setenv("UNIFI_URL", "https://unifi.example.com/")
        monkeypatch.setenv("UNIFI_USERNAME", "admin")
        monkeypatch.setenv("UNIFI_PASSWORD", "password")
        monkeypatch.setenv("TRAEFIK_IP", "192.168.1.10")
        monkeypatch.setenv("TRAEFIK_API_URL", "http://traefik.example.com/api/")

        app = TraefikToUnifi()

        # Mock Traefik API response
        responses.add(
            responses.GET,
            "http://traefik.example.com/api/http/routers",
            json=[{"name": "router1", "rule": "Host(`example.com`)"}],
            status=200,
        )

        # Mock UniFi login
        responses.add(
            responses.POST,
            "https://unifi.example.com/api/auth/login",
            json={"message": "Login successful"},
            headers={"X-Csrf-Token": "test-token-123"},
            status=200,
        )

        # Mock UniFi static DNS GET response
        responses.add(
            responses.GET,
            "https://unifi.example.com/proxy/network/v2/api/site/default/static-dns",
            json=[{"key": "example.com", "value": "192.168.1.10", "_id": "entry1"}],
            status=200,
        )

        app.sync()

        assert len(responses.calls) == 3  # 1 Traefik + 1 UniFi login + 1 UniFi GET
