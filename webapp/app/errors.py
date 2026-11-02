"""Request errors shared by sign-in and the live pages."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Request
from fastapi.responses import JSONResponse


@dataclass(frozen=True)
class Principal:
    name: str
    roles: frozenset[str]
    kind: str = "user"


class OpsError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


def install_errors(app) -> None:
    @app.exception_handler(OpsError)
    async def handle(request: Request, exc: OpsError) -> JSONResponse:
        return JSONResponse(status_code=exc.status, content={"error": {"code": exc.code, "message": str(exc)}})
