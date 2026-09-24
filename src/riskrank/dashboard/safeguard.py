"""Responsible-use safeguards: riskrank runs active attacks (ZAP's active
scan sends real injection payloads), so it must only be pointed at systems
the user owns or is authorised to test.

Used by `riskrank scan` before anything is sent to the target.

Tickets: R044, R045
"""

import sys
from collections.abc import Callable
from dataclasses import dataclass

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


def is_target_allowed(target_url: str, allowlist: list[str]) -> bool:
    """Check target_url against the configured allowlist.

    TODO (R045): implement domain matching against allowlist entries.
    """
    raise NotImplementedError
