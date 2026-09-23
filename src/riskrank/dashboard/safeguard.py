"""Responsible-use safeguards for the dashboard/scan trigger flow.

Tickets: R044, R045
"""


def confirm_target_ownership(target_url: str) -> bool:
    """Require explicit confirmation that the user owns/has permission
    to scan target_url before a scan is allowed to run.

    TODO (R044): implement confirmation prompt/flag; refuse to scan
    without it.
    """
    raise NotImplementedError


def is_target_allowed(target_url: str, allowlist: list[str]) -> bool:
    """Check target_url against the configured allowlist.

    TODO (R045): implement domain matching against allowlist entries.
    """
    raise NotImplementedError
