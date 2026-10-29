"""Process settings.

Local mode keeps the SQLite fixture. Live mode reads Sentinel and the WAF
policy and does not open a database.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    app_env: str = "local"
    database_url: str = "sqlite:///./webapp-data.db"
    secret: str = "local-dev-secret-change-me"
    public_base_url: str = "http://127.0.0.1:8000"
    integration_key: str = "local-integration-key"
    dev_login_password: str = "local-dev"
    product_cap: int = 100
    block_rule_name: str = "SentinelAutoBlock"
    block_rule_priority: int = 10
    require_approval: bool = True
    seed_fixture: bool = True
    approver_email: str = "admin@mngenvmcap591832.onmicrosoft.com"
    poc_admins: str = ""
    live_azure: bool = False
    subscription_id: str = ""
    resource_group: str = ""
    workspace_name: str = ""
    waf_policy_id: str = ""
    block_api_key: str = ""
    block_policy_tag: str = "ase-sentinel-block-list"

    @classmethod
    def from_env(cls) -> Settings:
        app_env = os.environ.get("APP_ENV", "local")
        local = app_env == "local"
        return cls(
            app_env=app_env,
            database_url=os.environ.get(
                "DATABASE_URL",
                "sqlite:///./webapp-data.db" if local else "",
            ),
            secret=os.environ.get("APP_SECRET", "local-dev-secret-change-me" if local else ""),
            public_base_url=os.environ.get("PUBLIC_BASE_URL", "http://127.0.0.1:8000"),
            integration_key=os.environ.get("INTEGRATION_API_KEY", "local-integration-key" if local else ""),
            dev_login_password=os.environ.get("DEV_LOGIN_PASSWORD", "local-dev" if local else ""),
            product_cap=int(os.environ.get("MAXIMUM_BLOCK_ENTRIES", "100")),
            block_rule_name=os.environ.get("BLOCK_RULE_NAME", "SentinelAutoBlock"),
            block_rule_priority=int(os.environ.get("BLOCK_RULE_PRIORITY", "10")),
            require_approval=os.environ.get("REQUIRE_APPROVAL", "true").lower() != "false",
            seed_fixture=os.environ.get("SEED_FIXTURE", "true" if local else "false").lower() == "true",
            approver_email=os.environ.get(
                "APPROVER_EMAIL",
                "admin@mngenvmcap591832.onmicrosoft.com",
            ),
            poc_admins=os.environ.get("POC_ADMIN_USERS", ""),
            live_azure=os.environ.get("LIVE_AZURE", "").lower() == "true",
            subscription_id=os.environ.get("AZURE_SUBSCRIPTION_ID", ""),
            resource_group=os.environ.get("AZURE_RESOURCE_GROUP", ""),
            workspace_name=os.environ.get("SENTINEL_WORKSPACE_NAME", ""),
            waf_policy_id=os.environ.get("WAF_POLICY_RESOURCE_ID", ""),
            block_api_key=os.environ.get("BLOCK_API_KEY", ""),
            block_policy_tag=os.environ.get("BLOCK_POLICY_TAG", "ase-sentinel-block-list"),
        )

    def validate(self) -> None:
        if self.live_azure:
            self._validate_live()
            return
        if self.app_env != "local":
            if not self.database_url or self.database_url.startswith("sqlite"):
                raise RuntimeError("production requires DATABASE_URL for Azure SQL")
            if not self.secret or self.secret.startswith("local-dev"):
                raise RuntimeError("production requires APP_SECRET")
            if not self.integration_key or self.integration_key.startswith("local-"):
                raise RuntimeError("production requires INTEGRATION_API_KEY")
            if self.dev_login_password:
                raise RuntimeError("production must not set DEV_LOGIN_PASSWORD")

    def _validate_live(self) -> None:
        missing = [
            name
            for name, value in (
                ("AZURE_SUBSCRIPTION_ID", self.subscription_id),
                ("AZURE_RESOURCE_GROUP", self.resource_group),
                ("SENTINEL_WORKSPACE_NAME", self.workspace_name),
                ("WAF_POLICY_RESOURCE_ID", self.waf_policy_id),
                ("BLOCK_API_KEY", self.block_api_key),
            )
            if not value
        ]
        if missing:
            raise RuntimeError("live Azure mode requires " + ", ".join(missing))
        if not self.waf_policy_id.startswith("/subscriptions/"):
            raise RuntimeError("WAF_POLICY_RESOURCE_ID must be an ARM resource id")
        if self.app_env != "local" and self.dev_login_password:
            raise RuntimeError("production must not set DEV_LOGIN_PASSWORD")
