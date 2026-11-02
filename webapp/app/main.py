"""Application factory. Importing this module does not call Azure."""

from __future__ import annotations

import sys

from fastapi import FastAPI

from app.config import Settings


def create_app(settings: Settings | None = None, azure=None) -> FastAPI:
    settings = settings or Settings.from_env()
    settings.validate()
    from app.live import build_live_app

    return build_live_app(settings, azure)


def _export_app() -> FastAPI | None:
    # Pytest imports this module while collecting tests. Those tests pass their
    # own Settings into create_app. A process without the Azure settings still
    # fails here, which is what gunicorn hits on the live site.
    if "pytest" in sys.modules:
        return None
    return create_app()


app = _export_app()
