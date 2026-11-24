"""Delivering alerts: email, webhooks (Slack, Teams, SIEM) and Windows desktop notifications.

Channel settings such as SMTP passwords and webhook URLs are stored encrypted with the
vault key. Every delivery attempt is written to ``notification_log``.
"""

from __future__ import annotations

import json
import logging
import smtplib
import ssl
import urllib.request
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import timedelta
from email.message import EmailMessage
from typing import Any, Protocol

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from filevow.crypto import aead
from filevow.db.base import utcnow
from filevow.db.enums import ChannelType, Role
from filevow.db.models import Alert, NotificationChannel, NotificationLog, User

log = logging.getLogger(__name__)

_CONFIG_AAD = b"filevow:notification-channel"
BURST_THRESHOLD = 20
MAX_ATTEMPTS = 3
RETRY_BACKOFF = (timedelta(minutes=1), timedelta(minutes=5), timedelta(minutes=15))


@dataclass(frozen=True)
class Notification:
    subject: str
    body: str
    severity: str


class Channel(Protocol):
    def send(self, notification: Notification) -> None: ...


def encrypt_config(vault_key: bytes, config: dict[str, Any]) -> bytes:
    return aead.seal(json.dumps(config).encode("utf-8"), vault_key, _CONFIG_AAD)


def decrypt_config(vault_key: bytes, blob: bytes) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(aead.unseal(blob, vault_key, _CONFIG_AAD))
    return data


class EmailChannel:
    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config

    def send(self, notification: Notification) -> None:
        cfg = self._config
        message = EmailMessage()
        message["Subject"] = notification.subject
        message["From"] = cfg["sender"]
        message["To"] = ", ".join(cfg["recipients"])
        message.set_content(notification.body)
        context = ssl.create_default_context()
        with smtplib.SMTP(cfg["host"], int(cfg.get("port", 587)), timeout=15) as smtp:
            if cfg.get("starttls", True):
                smtp.starttls(context=context)
            if cfg.get("username"):
                smtp.login(cfg["username"], cfg["password"])
            smtp.send_message(message)


class WebhookChannel:
    def __init__(self, config: dict[str, Any]) -> None:
        self._url = str(config["url"])
        if not self._url.startswith("https://"):
            raise ValueError("webhook URLs must use HTTPS")

    def send(self, notification: Notification) -> None:
        payload = json.dumps(
            {"text": f"{notification.subject}\n{notification.body}", "severity": notification.severity}
        ).encode("utf-8")
        request = urllib.request.Request(  # noqa: S310 - scheme is checked to be https in __init__
            self._url, data=payload, headers={"Content-Type": "application/json"}, method="POST"
        )
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310
            if response.status >= 300:
                raise RuntimeError(f"webhook answered HTTP {response.status}")


class DesktopChannel:
    def send(self, notification: Notification) -> None:
        try:
            from plyer import notification as toast  # optional dependency
        except ImportError:
            log.info("desktop notification (plyer not installed): %s", notification.subject)
            return
        toast.notify(
            title=notification.subject, message=notification.body[:250], app_name="FileVow", timeout=10
        )


def build_channel(row: NotificationChannel, vault_key: bytes) -> Channel:
    config = decrypt_config(vault_key, row.config_enc)
    if row.type is ChannelType.EMAIL:
        return EmailChannel(config)
    if row.type is ChannelType.DESKTOP:
        return DesktopChannel()
    return WebhookChannel(config)  # slack, teams and generic webhooks share one format


def _reaches(channel: NotificationChannel, alert: Alert, admin_ids: set[int]) -> bool:
    """People only hear about their own workspace; alerts about FileVow itself go to admins."""
    if alert.owner_id is not None:
        return channel.owner_id == alert.owner_id
    return channel.owner_id is None or channel.owner_id in admin_ids


def notification_for(alert: Alert) -> Notification:
    return Notification(
        subject=f"[{alert.severity.upper()}] {alert.title}", body=alert.message, severity=str(alert.severity)
    )


def burst_summary(alerts: Sequence[Alert]) -> Notification:
    worst = max(alerts, key=lambda a: a.severity.rank)
    lines = "\n".join(f"- {a.title}" for a in alerts[:15])
    more = f"\n…and {len(alerts) - 15} more" if len(alerts) > 15 else ""
    return Notification(
        subject=f"[{worst.severity.upper()}] {len(alerts)} integrity alerts",
        body=f"{lines}{more}\nOpen FileVow to review.",
        severity=str(worst.severity),
    )


class NotificationDispatcher:
    def __init__(self, session: Session, vault_key: bytes, channel_factory: Any = build_channel) -> None:
        self._session = session
        self._vault_key = vault_key
        self._build = channel_factory

    def dispatch(self, alerts: Sequence[Alert], *, escalation: bool = False) -> int:
        """Send alerts to every eligible channel. Returns the number of successful sends."""
        if not alerts:
            return 0
        query = select(NotificationChannel).where(NotificationChannel.enabled.is_(True))
        if escalation:
            query = query.where(NotificationChannel.is_escalation_contact.is_(True))
        admin_ids = set(self._session.scalars(select(User.id).where(User.role == Role.ADMIN)))
        sent = 0
        for row in self._session.scalars(query):
            eligible = [
                a for a in alerts if a.severity.rank >= row.min_severity.rank and _reaches(row, a, admin_ids)
            ]
            if not eligible:
                continue
            if len(eligible) > BURST_THRESHOLD:
                sent += self._deliver(row, burst_summary(eligible), eligible)
            else:
                sent += sum(self._deliver(row, notification_for(a), [a]) for a in eligible)
        return sent

    def retry_failed(self) -> int:
        """Retry failed deliveries with increasing delays, up to three attempts."""
        latest = (
            select(
                NotificationLog.alert_id,
                NotificationLog.channel_id,
                func.max(NotificationLog.id).label("last"),
            )
            .group_by(NotificationLog.alert_id, NotificationLog.channel_id)
            .subquery()
        )
        candidates = self._session.scalars(
            select(NotificationLog).join(latest, NotificationLog.id == latest.c.last)
        )
        resent = 0
        now = utcnow()
        for entry in candidates.all():
            if entry.status != "failed" or entry.attempt >= MAX_ATTEMPTS:
                continue
            if now - entry.sent_at < RETRY_BACKOFF[entry.attempt - 1]:
                continue
            alert = self._session.get(Alert, entry.alert_id)
            channel = self._session.get(NotificationChannel, entry.channel_id)
            if alert and channel and channel.enabled:
                resent += self._deliver(channel, notification_for(alert), [alert], attempt=entry.attempt + 1)
        return resent

    def _deliver(
        self, row: NotificationChannel, notification: Notification, alerts: Sequence[Alert], attempt: int = 1
    ) -> int:
        try:
            self._build(row, self._vault_key).send(notification)
            status, error = "sent", None
        except Exception as exc:  # any delivery failure is logged and retried later
            status, error = "failed", f"{type(exc).__name__}: {exc}"[:500]
            log.warning("notification via %s failed: %s", row.name, error)
        for alert in alerts:
            self._session.add(
                NotificationLog(
                    alert_id=alert.id, channel_id=row.id, attempt=attempt, status=status, error=error
                )
            )
        return 1 if status == "sent" else 0
