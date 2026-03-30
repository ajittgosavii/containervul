"""Audit event logging — structured, queryable security audit trail."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from containervul.models import AuditEvent

logger = logging.getLogger(__name__)


class AuditLogger:
    """Record and query audit events."""

    def __init__(self) -> None:
        self._events: List[AuditEvent] = []

    def log(
        self,
        action: str,
        target: str = "",
        user: str = "system",
        result: str = "success",
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        event = AuditEvent(
            user=user,
            action=action,
            target=target,
            result=result,
            details=details or {},
        )
        self._events.append(event)
        logger.info("AUDIT: user=%s action=%s target=%s result=%s", user, action, target, result)
        return event

    def query(
        self,
        user: Optional[str] = None,
        action: Optional[str] = None,
        since: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[AuditEvent]:
        filtered = self._events
        if user:
            filtered = [e for e in filtered if e.user == user]
        if action:
            filtered = [e for e in filtered if action in e.action]
        if since:
            filtered = [e for e in filtered if e.timestamp >= since]
        return sorted(filtered, key=lambda e: e.timestamp, reverse=True)[:limit]

    def get_all(self) -> List[AuditEvent]:
        return sorted(self._events, key=lambda e: e.timestamp, reverse=True)

    def clear(self) -> None:
        self._events.clear()
