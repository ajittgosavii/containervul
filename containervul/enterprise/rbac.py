"""Role-Based Access Control for the vulnerability platform."""

from __future__ import annotations

from typing import Set

from containervul.models import Role

PERMISSIONS: dict[Role, Set[str]] = {
    Role.VIEWER: {"view_dashboard", "view_reports", "view_analytics"},
    Role.ANALYST: {
        "view_dashboard", "view_reports", "view_analytics",
        "run_scan", "search_cve", "view_audit_log", "use_agent",
    },
    Role.OPERATOR: {
        "view_dashboard", "view_reports", "view_analytics",
        "run_scan", "search_cve", "view_audit_log", "use_agent",
        "execute_remediation", "update_status", "manage_compliance",
    },
    Role.ADMIN: {"*"},  # Wildcard — has all permissions
}


def has_permission(role: Role, permission: str) -> bool:
    """Check if a role has a specific permission."""
    allowed = PERMISSIONS.get(role, set())
    return "*" in allowed or permission in allowed


def get_permissions(role: Role) -> Set[str]:
    """Return the set of permissions for a role."""
    perms = PERMISSIONS.get(role, set())
    if "*" in perms:
        # Collect all permissions from all roles
        all_perms: Set[str] = set()
        for p in PERMISSIONS.values():
            all_perms.update(p)
        all_perms.discard("*")
        return all_perms
    return perms
