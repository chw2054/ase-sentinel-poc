"""Process settings.

The operations app reads Sentinel and one WAF policy. It does not open a database.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    app_env: str = "local"
    secret: str = "local-dev-secret-change-me"
    dev_login_password: str = "local-dev"
    block_rule_name: str = "SentinelAutoBlock"
    block_rule_priority: int = 10
    poc_admins: str = ""
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
            secret=os.environ.get("APP_SECRET", "local-dev-secret-change-me" if local else ""),
            dev_login_password=os.environ.get("DEV_LOGIN_PASSWORD", "local-dev" if local else ""),
            block_rule_name=os.environ.get("BLOCK_RULE_NAME", "SentinelAutoBlock"),
            block_rule_priority=int(os.environ.get("BLOCK_RULE_PRIORITY", "10")),
            poc_admins=os.environ.get("POC_ADMIN_USERS", ""),
            subscription_id=os.environ.get("AZURE_SUBSCRIPTION_ID", ""),
            resource_group=os.environ.get("AZURE_RESOURCE_GROUP", ""),
            workspace_name=os.environ.get("SENTINEL_WORKSPACE_NAME", ""),
            waf_policy_id=os.environ.get("WAF_POLICY_RESOURCE_ID", ""),
            block_api_key=os.environ.get("BLOCK_API_KEY", ""),
            block_policy_tag=os.environ.get("BLOCK_POLICY_TAG", "ase-sentinel-block-list"),
        )

    def validate(self) -> None:
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
