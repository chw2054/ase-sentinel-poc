"""Sentinel WAF auto-block decision engine.

The core does not import Azure Functions or perform I/O. Callers inject the
WAF and incident-comment clients.
"""

from sentinel_waf_block.engine import Engine
from sentinel_waf_block.models import Config, Incident, Result

__all__ = ["Config", "Engine", "Incident", "Result"]
