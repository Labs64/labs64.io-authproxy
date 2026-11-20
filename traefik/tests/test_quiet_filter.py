import logging
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from traefik_authproxy import _QuietPathsFilter


@pytest.fixture
def filt():
    return _QuietPathsFilter()


def _make_record(msg: str) -> logging.LogRecord:
    return logging.LogRecord(
        name="uvicorn.access",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg=msg,
        args=(),
        exc_info=None,
    )


# --- suppressed paths ---

@pytest.mark.parametrize("path", ["/docs", "/openapi.json", "/redoc", "/health", "/health/ready"])
def test_suppressed_paths(filt, path):
    record = _make_record(f'127.0.0.1:1234 - "GET {path} HTTP/1.1" 200 OK')
    assert filt.filter(record) is False


def test_suppressed_prefix(filt):
    record = _make_record('127.0.0.1:1234 - "GET /docs HTTP/1.1" 200 OK')
    assert filt.filter(record) is False


# --- allowed paths ---

@pytest.mark.parametrize("path", ["/auth", "/reload", "/docsadmin", "/not-docs"])
def test_allowed_paths(filt, path):
    record = _make_record(f'127.0.0.1:1234 - "GET {path} HTTP/1.1" 200 OK')
    assert filt.filter(record) is True


def test_allowed_post_auth(filt):
    record = _make_record('10.42.0.1:57994 - "POST /auth HTTP/1.1" 200 OK')
    assert filt.filter(record) is True
