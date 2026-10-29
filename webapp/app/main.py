"""Application factory. Importing this module does not call Azure."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles

from app.api import install_errors, router
from app.config import Settings
from app.ops import Ops, seed
from app.orm import session_factory
from app.ui import ui
from app.waf import MemoryWaf, fixture_policy


def create_app(settings: Settings | None = None, azure=None) -> FastAPI:
    settings = settings or Settings.from_env()
    settings.validate()
    if settings.live_azure:
        from app.live import build_live_app

        return build_live_app(settings, azure)
    return _sql_app(settings)


def _sql_app(settings: Settings) -> FastAPI:
    app = FastAPI(title="ASE Sentinel operations", version="1.0.0")
    app.state.settings = settings
    app.state.waf = MemoryWaf(fixture_policy())
    app.state.ops = Ops(settings, app.state.waf)
    app.state.sessions = session_factory(settings.database_url)

    @app.middleware("http")
    async def sessions(request: Request, call_next):
        db = app.state.sessions()
        request.state.db = db
        try:
            response = await call_next(request)
            db.commit()
            return response
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    install_errors(app)
    app.include_router(router)
    app.include_router(ui)
    app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")
    if settings.seed_fixture:
        db = app.state.sessions()
        try:
            seed(db, app.state.ops)
            db.commit()
        finally:
            db.close()
    return app


app = create_app()
