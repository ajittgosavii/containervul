"""ServiceNow REST API client with basic auth, OAuth, retry, and connection pooling."""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

import requests
from requests.auth import HTTPBasicAuth

from containervul.config import settings
from containervul.exceptions import ContainerVulError

logger = logging.getLogger(__name__)


class ServiceNowError(ContainerVulError):
    """ServiceNow API error."""

    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        super().__init__(f"ServiceNow API {status_code}: {message}")


class ServiceNowClient:
    """REST client for ServiceNow Table API, Import Set API, and CMDB API.

    Supports basic auth and OAuth2. Includes retry with exponential backoff
    for 429 (rate limited) and 503 (service unavailable) responses.
    """

    MAX_RETRIES = 3
    BACKOFF_BASE = 2  # seconds

    def __init__(
        self,
        instance: str = "",
        username: str = "",
        password: str = "",
        auth_method: str = "basic",
        oauth_client_id: str = "",
        oauth_client_secret: str = "",
    ):
        self.instance = (instance or settings.servicenow_instance).rstrip("/")
        self._username = username or settings.servicenow_username
        self._password = password or settings.servicenow_password
        self._auth_method = auth_method or settings.servicenow_auth_method
        self._oauth_client_id = oauth_client_id or settings.servicenow_oauth_client_id
        self._oauth_client_secret = oauth_client_secret or settings.servicenow_oauth_client_secret
        self._oauth_token: Optional[str] = None
        self._oauth_expiry: float = 0

        self._session = requests.Session()
        self._session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
        })

    @property
    def is_configured(self) -> bool:
        return bool(self.instance and self._username and self._password)

    # ── Authentication ───────────────────────────────────────────────────

    def _get_auth(self) -> Optional[HTTPBasicAuth]:
        if self._auth_method == "basic":
            return HTTPBasicAuth(self._username, self._password)
        return None

    def _get_auth_headers(self) -> Dict[str, str]:
        if self._auth_method == "oauth":
            if time.time() >= self._oauth_expiry:
                self._refresh_oauth_token()
            return {"Authorization": f"Bearer {self._oauth_token}"}
        return {}

    def _refresh_oauth_token(self) -> None:
        url = f"{self.instance}/oauth_token.do"
        resp = requests.post(url, data={
            "grant_type": "password",
            "client_id": self._oauth_client_id,
            "client_secret": self._oauth_client_secret,
            "username": self._username,
            "password": self._password,
        })
        if resp.status_code != 200:
            raise ServiceNowError(resp.status_code, "OAuth token request failed")
        data = resp.json()
        self._oauth_token = data["access_token"]
        self._oauth_expiry = time.time() + int(data.get("expires_in", 1800)) - 60

    # ── Core request method with retry ───────────────────────────────────

    def _request(
        self,
        method: str,
        path: str,
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        url = f"{self.instance}{path}"
        auth = self._get_auth()
        headers = self._get_auth_headers()

        for attempt in range(self.MAX_RETRIES):
            try:
                resp = self._session.request(
                    method, url,
                    params=params,
                    json=data,
                    auth=auth,
                    headers=headers,
                    timeout=30,
                )

                if resp.status_code in (429, 503) and attempt < self.MAX_RETRIES - 1:
                    wait = self.BACKOFF_BASE ** (attempt + 1)
                    logger.warning("ServiceNow %d, retrying in %ds...", resp.status_code, wait)
                    time.sleep(wait)
                    continue

                if resp.status_code >= 400:
                    error_msg = resp.text[:500]
                    try:
                        error_msg = resp.json().get("error", {}).get("message", error_msg)
                    except Exception:
                        pass
                    raise ServiceNowError(resp.status_code, error_msg)

                result = resp.json()
                return result.get("result", result)

            except ServiceNowError:
                raise
            except requests.RequestException as exc:
                if attempt < self.MAX_RETRIES - 1:
                    time.sleep(self.BACKOFF_BASE ** (attempt + 1))
                    continue
                raise ServiceNowError(0, f"Connection error: {exc}") from exc

        raise ServiceNowError(0, "Max retries exceeded")

    # ── Convenience methods ──────────────────────────────────────────────

    def get(self, path: str, params: Optional[Dict] = None) -> Any:
        return self._request("GET", path, params=params)

    def post(self, path: str, data: Dict) -> Any:
        return self._request("POST", path, data=data)

    def patch(self, path: str, data: Dict) -> Any:
        return self._request("PATCH", path, data=data)

    def delete(self, path: str) -> Any:
        return self._request("DELETE", path)

    # ── Table API helpers ────────────────────────────────────────────────

    def query_table(
        self,
        table: str,
        query: str = "",
        fields: Optional[List[str]] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Dict]:
        params: Dict[str, Any] = {
            "sysparm_limit": limit,
            "sysparm_offset": offset,
        }
        if query:
            params["sysparm_query"] = query
        if fields:
            params["sysparm_fields"] = ",".join(fields)

        result = self.get(f"/api/now/table/{table}", params=params)
        return result if isinstance(result, list) else [result] if result else []

    def get_record(self, table: str, sys_id: str) -> Dict:
        return self.get(f"/api/now/table/{table}/{sys_id}")

    def create_record(self, table: str, data: Dict) -> Dict:
        return self.post(f"/api/now/table/{table}", data)

    def update_record(self, table: str, sys_id: str, data: Dict) -> Dict:
        return self.patch(f"/api/now/table/{table}/{sys_id}", data)

    # ── Connection test ──────────────────────────────────────────────────

    def test_connection(self) -> Dict[str, Any]:
        """Test the ServiceNow connection and return instance info."""
        if not self.is_configured:
            return {"status": "error", "message": "ServiceNow not configured — set instance URL, username, and password"}

        try:
            result = self.get("/api/now/table/sys_user", params={
                "sysparm_limit": 1,
                "sysparm_fields": "user_name,name",
            })
            return {
                "status": "connected",
                "instance": self.instance,
                "auth_method": self._auth_method,
                "message": "Successfully connected to ServiceNow",
            }
        except ServiceNowError as exc:
            return {"status": "error", "message": str(exc)}
        except Exception as exc:
            return {"status": "error", "message": f"Connection failed: {exc}"}
