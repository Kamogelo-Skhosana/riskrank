"""Target context configuration.

Captures what riskrank needs to know about the target to triage
findings meaningfully: which endpoints are public-facing, which
handle sensitive/user data, and which require authentication.

Tickets: R018, R019, R020
"""

import re
from urllib.parse import urlparse

from pydantic import BaseModel


class TargetContext(BaseModel):
    public_facing: bool = True
    handles_sensitive_data: bool = False
    requires_auth: bool = False
    notes: str = ""


# Endpoint keywords, matched against whole words in the URL path (split on
# "/", "-", "_", "." etc.), so "/authors" does NOT match "auth".
AUTH_WORDS = {
    "login",
    "logout",
    "signin",
    "signup",
    "register",
    "auth",
    "oauth",
    "sso",
    "password",
    "passwd",
    "reset",
    "token",
    "session",
    "mfa",
    "2fa",
}
PAYMENT_WORDS = {
    "checkout",
    "payment",
    "payments",
    "pay",
    "billing",
    "card",
    "cards",
    "wallet",
    "order",
    "orders",
    "basket",
    "cart",
    "invoice",
    "invoices",
}
PERSONAL_DATA_WORDS = {
    "user",
    "users",
    "account",
    "accounts",
    "profile",
    "profiles",
    "me",
    "address",
    "addresses",
    "customer",
    "customers",
}
FILE_WORDS = {
    "upload",
    "uploads",
    "file",
    "files",
    "ftp",
    "export",
    "exports",
    "download",
    "downloads",
}
ADMIN_WORDS = {"admin", "administrator", "administration", "manage", "management", "dashboard"}
INTERNAL_WORDS = {"internal", "private", "intranet", "debug", "actuator", "metrics", "health"}
API_WORDS = {"api", "rest", "graphql", "rpc", "v1", "v2", "v3"}

STATIC_EXTENSIONS = {
    ".css",
    ".js",
    ".mjs",
    ".map",
    ".ico",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".webp",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
}
STATIC_DIRS = {"assets", "static", "public", "images", "img", "fonts", "css"}

# Backups, dumps, keys and password vaults: sensitive wherever they appear.
SECRET_FILE_EXTENSIONS = {
    ".bak",
    ".backup",
    ".old",
    ".orig",
    ".swp",
    ".sql",
    ".dump",
    ".db",
    ".sqlite",
    ".env",
    ".key",
    ".pem",
    ".p12",
    ".pfx",
    ".kdbx",
    ".log",
    ".pyc",
}

_WORD_SPLIT = re.compile(r"[^a-z0-9]+")


def _path_of(endpoint: str) -> str:
    """Accept a bare path (/api/login) or a full URL; return the lowercased path."""
    path = urlparse(endpoint).path if "://" in endpoint else endpoint.split("?", 1)[0]
    return (path or "/").lower()


def _extension(path: str) -> str:
    last_segment = path.rstrip("/").rsplit("/", 1)[-1]
    return "." + last_segment.rsplit(".", 1)[-1] if "." in last_segment else ""


def _is_static_asset(path: str) -> bool:
    if _extension(path) in STATIC_EXTENSIONS:
        return True
    first_segment = path.strip("/").split("/", 1)[0]
    return first_segment in STATIC_DIRS


def infer_default_context(endpoint: str) -> TargetContext:
    """Best-effort default context based on simple endpoint naming patterns.

    This is a heuristic, not a guarantee: it gives the triage layer a
    sensible starting point when the user hasn't supplied context for an
    endpoint (R019 lets them override it). The notes field records why
    each flag was set, so the LLM and the reader can see the reasoning.

    Rules (whole-word matches in the path):
      * static assets (.js, .css, images, fonts, /assets/...) -> low sensitivity
      * auth words (login, password, token...) -> sensitive
      * payment words (checkout, basket, order...) -> sensitive, auth required
      * personal-data words (user, account, profile...) -> sensitive
      * file words (ftp, upload, download...) -> sensitive
      * backup/secret file extensions (.bak, .sql, .env, .kdbx...) -> sensitive
      * API paths (/api/, /rest/, /graphql...) -> sensitive by default
      * admin words -> sensitive, auth required
      * internal words (internal, debug, actuator...) -> not public-facing
    """
    path = _path_of(endpoint)
    words = set(_WORD_SPLIT.split(path)) - {""}

    if _is_static_asset(path):
        return TargetContext(
            public_facing=True,
            handles_sensitive_data=False,
            requires_auth=False,
            notes="Inferred: static asset (script/style/image/font); low data sensitivity.",
        )

    sensitive = False
    requires_auth = False
    public_facing = True
    reasons: list[str] = []

    def matched(group: set[str]) -> list[str]:
        return sorted(words & group)

    if hits := matched(AUTH_WORDS):
        sensitive = True
        reasons.append(f"authentication endpoint ({', '.join(hits)})")
    if hits := matched(PAYMENT_WORDS):
        sensitive = requires_auth = True
        reasons.append(f"payment/order flow ({', '.join(hits)})")
    if hits := matched(PERSONAL_DATA_WORDS):
        sensitive = True
        reasons.append(f"user/personal data ({', '.join(hits)})")
    if hits := matched(FILE_WORDS):
        sensitive = True
        reasons.append(f"file storage/transfer ({', '.join(hits)})")
    if (ext := _extension(path)) in SECRET_FILE_EXTENSIONS:
        sensitive = True
        reasons.append(f"backup/secret-looking file ({ext})")
    if hits := matched(API_WORDS):
        sensitive = True
        reasons.append(f"API endpoint ({', '.join(hits)})")
    if hits := matched(ADMIN_WORDS):
        sensitive = requires_auth = True
        reasons.append(f"admin area ({', '.join(hits)})")
    if hits := matched(INTERNAL_WORDS):
        public_facing = False
        reasons.append(f"likely internal-only ({', '.join(hits)})")

    notes = (
        "Inferred: " + "; ".join(reasons) + "."
        if reasons
        else "Inferred: no sensitive patterns matched; default public page."
    )
    return TargetContext(
        public_facing=public_facing,
        handles_sensitive_data=sensitive,
        requires_auth=requires_auth,
        notes=notes,
    )
