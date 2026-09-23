"""Tests for target context: inference (R020) and context files (R019).

Tickets: R019, R020
"""

from pathlib import Path

import pytest

from riskrank.triage.context import (
    ContextConfig,
    ContextConfigError,
    TargetContext,
    infer_default_context,
    load_context_config,
    resolve_context,
)


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


# --- R019: context file -------------------------------------------------------

EXAMPLE_FILE = Path(__file__).resolve().parent.parent / "examples" / "context.example.toml"


def write(tmp_path, text: str) -> Path:
    path = tmp_path / "context.toml"
    path.write_text(text, encoding="utf-8")
    return path


def test_example_file_is_valid():
    config = load_context_config(EXAMPLE_FILE)
    assert config.infer is True
    assert [r.pattern for r in config.endpoints][:2] == ["/rest/user/*", "/api/cards*"]


def test_without_config_falls_back_to_inference():
    assert resolve_context("/rest/user/login") == infer_default_context("/rest/user/login")


def test_empty_file_keeps_inference(tmp_path):
    config = load_context_config(write(tmp_path, ""))
    assert resolve_context("/admin", config) == infer_default_context("/admin")


def test_endpoint_rule_overrides_inferred_values(tmp_path):
    config = load_context_config(
        write(
            tmp_path,
            """
[[endpoints]]
pattern = "/admin*"
public_facing = false
requires_auth = true
notes = "VPN-only admin panel."
""",
        )
    )
    ctx = resolve_context("/admin/users", config)
    assert ctx.public_facing is False
    assert ctx.requires_auth is True
    assert ctx.handles_sensitive_data is True  # not overridden -> inferred value kept
    assert "admin area" in ctx.notes  # inferred reason kept
    assert "Context file rule '/admin*': VPN-only admin panel." in ctx.notes


def test_default_section_applies_to_every_endpoint(tmp_path):
    config = load_context_config(write(tmp_path, "[default]\npublic_facing = false\n"))
    assert resolve_context("/about", config).public_facing is False
    assert resolve_context("/api/x", config).public_facing is False


def test_rule_overrides_default(tmp_path):
    config = load_context_config(
        write(
            tmp_path,
            """
[default]
public_facing = false

[[endpoints]]
pattern = "/shop/*"
public_facing = true
""",
        )
    )
    assert resolve_context("/shop/item/1", config).public_facing is True
    assert resolve_context("/other", config).public_facing is False


def test_first_matching_rule_wins(tmp_path):
    config = load_context_config(
        write(
            tmp_path,
            """
[[endpoints]]
pattern = "/api/public/*"
handles_sensitive_data = false

[[endpoints]]
pattern = "/api/*"
handles_sensitive_data = true
""",
        )
    )
    assert resolve_context("/api/public/news", config).handles_sensitive_data is False
    assert resolve_context("/api/users", config).handles_sensitive_data is True


def test_infer_false_starts_from_plain_defaults(tmp_path):
    config = load_context_config(write(tmp_path, "infer = false\n"))
    ctx = resolve_context("/rest/user/login", config)
    assert ctx.handles_sensitive_data is False
    assert "Inferred" not in ctx.notes


def test_patterns_match_case_insensitively_and_full_urls(tmp_path):
    config = load_context_config(
        write(tmp_path, '[[endpoints]]\npattern = "/API/*"\nrequires_auth = true\n')
    )
    assert resolve_context("http://host:3000/api/Things?x=1", config).requires_auth is True


def test_missing_file_raises(tmp_path):
    with pytest.raises(ContextConfigError, match="not found"):
        load_context_config(tmp_path / "nope.toml")


def test_invalid_toml_raises(tmp_path):
    with pytest.raises(ContextConfigError, match="not valid TOML"):
        load_context_config(write(tmp_path, "[[endpoints]\npattern = "))


def test_unknown_field_is_rejected(tmp_path):
    """A typo like 'requires_login' must fail loudly, not be silently ignored."""
    path = write(tmp_path, '[[endpoints]]\npattern = "/x"\nrequires_login = true\n')
    with pytest.raises(ContextConfigError, match=r"endpoints\.0\.requires_login"):
        load_context_config(path)


def test_wrong_type_is_rejected(tmp_path):
    path = write(tmp_path, '[default]\npublic_facing = "maybe"\n')
    with pytest.raises(ContextConfigError, match=r"default\.public_facing"):
        load_context_config(path)


def test_rule_without_pattern_is_rejected(tmp_path):
    with pytest.raises(ContextConfigError, match=r"endpoints\.0\.pattern"):
        load_context_config(write(tmp_path, "[[endpoints]]\nrequires_auth = true\n"))


def test_config_defaults():
    config = ContextConfig()
    assert config.infer is True
    assert config.endpoints == []


def test_unreadable_path_raises(tmp_path):
    """E.g. pointing --context at a directory instead of a file."""
    with pytest.raises(ContextConfigError, match="Could not read context file"):
        load_context_config(tmp_path)
