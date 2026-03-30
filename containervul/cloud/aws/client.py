"""AWS session and credential factory."""

from __future__ import annotations

import logging
from typing import Optional

import boto3
from botocore.config import Config as BotoConfig

from containervul.models import CloudAccount
from containervul.exceptions import AuthenticationError

logger = logging.getLogger(__name__)

_BOTO_CONFIG = BotoConfig(retries={"max_attempts": 3, "mode": "adaptive"})


class AWSClientFactory:
    """Create boto3 sessions / clients for a given AWS account."""

    @staticmethod
    def get_session(account: CloudAccount, region: Optional[str] = None) -> boto3.Session:
        """Return a boto3 Session, optionally assuming a cross-account role."""
        region = region or (account.regions[0] if account.regions else "us-east-1")

        if account.role_arn:
            return AWSClientFactory._assume_role_session(account, region)

        kwargs: dict = {"region_name": region}
        if account.credential_profile:
            kwargs["profile_name"] = account.credential_profile

        return boto3.Session(**kwargs)

    @staticmethod
    def get_client(account: CloudAccount, service: str, region: Optional[str] = None):
        session = AWSClientFactory.get_session(account, region)
        return session.client(service, config=_BOTO_CONFIG)

    @staticmethod
    def verify(account: CloudAccount) -> bool:
        try:
            sts = AWSClientFactory.get_client(account, "sts")
            identity = sts.get_caller_identity()
            logger.info("AWS authenticated: %s", identity.get("Arn", ""))
            return True
        except Exception as exc:
            raise AuthenticationError("AWS", str(exc)) from exc

    # ── Private ──────────────────────────────────────────────────────────

    @staticmethod
    def _assume_role_session(account: CloudAccount, region: str) -> boto3.Session:
        sts = boto3.client("sts", region_name=region)
        resp = sts.assume_role(
            RoleArn=account.role_arn,
            RoleSessionName=f"containervul-{account.account_id}",
            DurationSeconds=3600,
        )
        creds = resp["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=region,
        )
