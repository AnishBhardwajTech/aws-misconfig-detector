"""Check registry.

Each check is a function decorated with @check(...). It receives a ScanContext
and yields (resource, details) tuples, or (resource, details, public) when the
resource is exposed to the internet. The scanner turns those into Findings.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterator

from ..models import Severity


@dataclass(frozen=True)
class CheckSpec:
    id: str
    service: str
    severity: Severity
    title: str
    remediation: str
    scope: str  # "global" (once per account) or "regional" (once per region)
    func: Callable
    auto_remediable: bool = False


REGISTRY: dict[str, CheckSpec] = {}


def check(id: str, service: str, severity: Severity, title: str, remediation: str,
          scope: str = "regional", auto_remediable: bool = False):
    def decorator(func: Callable[..., Iterator]):
        if id in REGISTRY:
            raise ValueError(f"duplicate check id {id}")
        REGISTRY[id] = CheckSpec(id, service, severity, title, remediation, scope, func, auto_remediable)
        return func
    return decorator


def load_all() -> dict[str, CheckSpec]:
    from . import cloudtrail, ec2, iam, kms, s3  # noqa: F401  (registers checks)
    return REGISTRY
