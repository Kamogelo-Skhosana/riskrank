"""Tests for default target-context inference.

Ticket: R020
"""

import pytest

from riskrank.triage.context import TargetContext, infer_default_context


@pytest.mark.parametrize(
    "endpoint",
    ["/rest/user/login", "/api/Users/login", "/auth/reset-password", "/oauth/token"],
)
def test_auth_endpoints_are_sensitive(endpoint):
    ctx = infer_default_context(endpoint)
    assert ctx.handles_sensitive_data
    assert "authentication" in ctx.notes


@pytest.mark.parametrize("endpoint", ["/checkout", "/rest/basket/1", "/api/Orders", "/payment"])
def test_payment_flows_are_sensitive_and_require_auth(endpoint):
    ctx = infer_default_context(endpoint)
    assert ctx.handles_sensitive_data
    assert ctx.requires_auth
    assert "payment/order" in ctx.notes


@pytest.mark.parametrize("endpoint", ["/ftp", "/ftp/legal.md", "/file-upload", "/downloads/report"])
def test_file_areas_are_sensitive(endpoint):
    ctx = infer_default_context(endpoint)
    assert ctx.handles_sensitive_data
    assert "file storage/transfer" in ctx.notes


@pytest.mark.parametrize(
    ("endpoint", "ext"),
    [
        ("/ftp/package.json.bak", ".bak"),
        ("/backup/db.sql", ".sql"),
        ("/.env", ".env"),
        ("/ftp/incident-support.kdbx", ".kdbx"),
    ],
)
def test_backup_and_secret_files_are_sensitive(endpoint, ext):
    ctx = infer_default_context(endpoint)
    assert ctx.handles_sensitive_data
    assert f"backup/secret-looking file ({ext})" in ctx.notes


def test_api_paths_get_higher_default_sensitivity():
    ctx = infer_default_context("/api/Products")
    assert ctx.handles_sensitive_data
    assert "API endpoint (api)" in ctx.notes


@pytest.mark.parametrize("endpoint", ["/admin", "/administration/users", "/app/dashboard"])
def test_admin_areas_are_sensitive_and_require_auth(endpoint):
    ctx = infer_default_context(endpoint)
    assert ctx.handles_sensitive_data
    assert ctx.requires_auth
    assert "admin area" in ctx.notes


@pytest.mark.parametrize("endpoint", ["/internal/status", "/actuator/health", "/debug"])
def test_internal_endpoints_are_not_public_facing(endpoint):
    assert infer_default_context(endpoint).public_facing is False


@pytest.mark.parametrize(
    "endpoint",
    [
        "/main.js",
        "/styles.css",
        "/assets/public/favicon_js.ico",
        "/assets/public/images/logo.png",
        "/fonts/roboto.woff2",
        # A static file whose path mentions a sensitive word is still static.
        "/assets/login-page.js",
    ],
)
def test_static_assets_are_low_sensitivity(endpoint):
    ctx = infer_default_context(endpoint)
    assert ctx.handles_sensitive_data is False
    assert ctx.requires_auth is False
    assert "static asset" in ctx.notes


def test_plain_page_gets_defaults():
    ctx = infer_default_context("/about")
    assert ctx == TargetContext(
        public_facing=True,
        handles_sensitive_data=False,
        requires_auth=False,
        notes="Inferred: no sensitive patterns matched; default public page.",
    )


def test_root_path():
    assert infer_default_context("/").handles_sensitive_data is False


@pytest.mark.parametrize("endpoint", ["/authors", "/catalogue", "/paypal-info-page"])
def test_matches_whole_words_only(endpoint):
    """'authors' must not match 'auth'; 'catalogue' must not match 'log'."""
    assert infer_default_context(endpoint).handles_sensitive_data is False


def test_matching_is_case_insensitive():
    assert infer_default_context("/REST/User/LOGIN").handles_sensitive_data


def test_accepts_full_urls_and_ignores_query_string():
    ctx = infer_default_context("http://host.docker.internal:3000/rest/user/login?next=/")
    assert ctx.handles_sensitive_data
    assert infer_default_context("/search?q=admin").requires_auth is False


def test_multiple_reasons_are_all_recorded():
    ctx = infer_default_context("/api/admin/users")
    assert ctx.handles_sensitive_data and ctx.requires_auth
    for reason in ("user/personal data", "API endpoint", "admin area"):
        assert reason in ctx.notes
