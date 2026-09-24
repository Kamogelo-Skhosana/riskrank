"""Responsible-use safeguards: riskrank runs active attacks (ZAP's active
scan sends real injection payloads), so it must only be pointed at systems
the user owns or is authorised to test.

Used by `riskrank scan` before anything is sent to the target.

Tickets: R044, R045
"""

import ipaddress
import sys
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlparse

OWNERSHIP_WARNING = (
    "riskrank runs an ACTIVE scan: it sends real attack payloads (e.g. SQL injection, "
    "XSS) to the target. Only scan applications you own or have explicit, written "
    "permission to test. Scanning other systems without authorisation is illegal in "
    "most countries."
)


@dataclass(frozen=True)
class OwnershipConfirmation:
    """Outcome of confirm_target_ownership()."""

    confirmed: bool
    method: str  # "flag", "prompt", "declined", or "non-interactive"


def confirm_target_ownership(
    target_url: str,
    assume_yes: bool = False,
    ask: Callable[[str], bool] | None = None,
    interactive: bool | None = None,
) -> OwnershipConfirmation:
    """Require explicit confirmation that the user owns/has permission
    to scan target_url before a scan is allowed to run.

    Args:
        target_url: the target about to be scanned.
        assume_yes: the user already confirmed with a flag (--yes), e.g. in
            a script. Their responsibility, stated in the flag's help.
        ask: yes/no prompt function (defaults to typer.confirm, default No).
        interactive: whether a person can answer a prompt. Defaults to
            "is stdin a terminal". When nobody can answer and there's no
            flag, the scan is refused: silence never counts as consent.
    """
    if assume_yes:
        return OwnershipConfirmation(True, "flag")

    if interactive is None:
        interactive = sys.stdin.isatty()
    if not interactive:
        return OwnershipConfirmation(False, "non-interactive")

    if ask is None:
        import typer

        def ask(question: str) -> bool:
            return typer.confirm(question, default=False)

    question = f"Do you own {target_url} or have permission to test it?"
    if ask(question):
        return OwnershipConfirmation(True, "prompt")
    return OwnershipConfirmation(False, "declined")


# --- R045: scan-target allowlist -------------------------------------------------------


class AllowlistError(ValueError):
    """Raised for an allowlist entry that can't be understood."""


@dataclass(frozen=True)
class AllowlistEntry:
    """One SCAN_ALLOWLIST entry. Supported forms:

    juice.local          exactly this host, any port
    juice.local:3000     this host on this port only
    *.example.com        any subdomain of example.com (not example.com itself)
    192.168.1.20         this IP, any port   ([::1] for IPv6)
    10.0.0.0/8           any IP in this range (CIDR)
    """

    raw: str
    host: str | None = None  # exact hostname or IP
    suffix: str | None = None  # "*.example.com" -> ".example.com"
    network: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
    port: int | None = None

    def matches(self, host: str, port: int) -> bool:
        if self.port is not None and self.port != port:
            return False
        if self.network is not None:
            ip = _as_ip(host)
            return ip is not None and ip.version == self.network.version and ip in self.network
        if self.suffix is not None:
            return host.endswith(self.suffix) and len(host) > len(self.suffix)
        return host == self.host


def _normalise_host(host: str) -> str:
    return host.strip().strip("[]").rstrip(".").lower()


def _as_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def parse_allowlist_entry(entry: str) -> AllowlistEntry:
    """Parse one allowlist entry (see AllowlistEntry for the forms)."""
    raw = entry.strip()
    if not raw or "://" in raw or " " in raw:
        raise AllowlistError(
            f"Invalid allowlist entry {entry!r}: use a host like 'app.example.com', "
            "'app.example.com:8080', '*.example.com', an IP, or a CIDR range like "
            "'10.0.0.0/8' (no 'http://')."
        )

    if "/" in raw:  # CIDR range
        try:
            return AllowlistEntry(raw=raw, network=ipaddress.ip_network(raw, strict=False))
        except ValueError as exc:
            raise AllowlistError(f"Invalid allowlist CIDR range {entry!r}: {exc}") from exc

    host_part, port = raw, None
    if raw.startswith("["):  # [IPv6] or [IPv6]:port
        host_part, _, rest = raw[1:].partition("]")
        if rest.startswith(":"):
            port = rest[1:]
    elif raw.count(":") == 1:  # host:port (a bare IPv6 has several colons)
        host_part, port = raw.split(":")

    port_number = None
    if port is not None:
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise AllowlistError(f"Invalid port in allowlist entry {entry!r}.")
        port_number = int(port)

    host = _normalise_host(host_part)
    if host.startswith("*."):
        if len(host) <= 2 or "*" in host[2:]:
            raise AllowlistError(f"Invalid wildcard in allowlist entry {entry!r}.")
        return AllowlistEntry(raw=raw, suffix=host[1:], port=port_number)
    if not host or "*" in host:
        raise AllowlistError(
            f"Invalid allowlist entry {entry!r}: wildcards are only allowed as '*.domain'."
        )
    return AllowlistEntry(raw=raw, host=str(_as_ip(host) or host), port=port_number)


def parse_allowlist(value: str) -> list[AllowlistEntry]:
    """Parse a comma-separated SCAN_ALLOWLIST value; empty means 'no allowlist'."""
    return [parse_allowlist_entry(item) for item in value.split(",") if item.strip()]


def _target_host_port(target_url: str) -> tuple[str, int] | None:
    parsed = urlparse(target_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:  # e.g. port out of range
        return None
    host = _normalise_host(parsed.hostname)
    return str(_as_ip(host) or host), port


def is_target_allowed(target_url: str, allowlist: list[str] | list[AllowlistEntry]) -> bool:
    """Check target_url against the configured allowlist.

    An empty allowlist allows every http(s) target (the ownership
    confirmation still applies). Otherwise the target's host (and port) must
    match at least one entry. Anything that isn't a valid http(s) URL is
    never allowed.
    """
    host_port = _target_host_port(target_url)
    if host_port is None:
        return False
    entries = [e if isinstance(e, AllowlistEntry) else parse_allowlist_entry(e) for e in allowlist]
    if not entries:
        return True
    host, port = host_port
    return any(entry.matches(host, port) for entry in entries)
