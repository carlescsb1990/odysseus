"""Regression guard for issue #2553 — AUTH_ENABLED=false 403 on send.

With `AUTH_ENABLED=false` there is no logged-in user, so `effective_user`
returns None. `_verify_session_owner` used to raise `403 Authentication
required` unconditionally in that case, breaking every per-session action
(including sending a chat message) in single-user/no-auth deployments.

`resolve_session_owner` mirrors `require_user`: when auth is operator-disabled
the caller is the anonymous single-user owner (""); a genuinely
unauthenticated request still 403s.
"""
import pytest
from fastapi import HTTPException

from src.auth_helpers import resolve_session_owner


def test_real_user_passes_through(monkeypatch):
    monkeypatch.delenv("AUTH_ENABLED", raising=False)
    assert resolve_session_owner("alice") == "alice"


def test_auth_disabled_returns_anonymous_owner(monkeypatch):
    monkeypatch.setenv("AUTH_ENABLED", "false")
    # No user + auth off → "" (sessions are stored with owner "" in this mode).
    assert resolve_session_owner(None) == ""
    assert resolve_session_owner("") == ""


def test_auth_enabled_anonymous_raises_403(monkeypatch):
    monkeypatch.setenv("AUTH_ENABLED", "true")
    with pytest.raises(HTTPException) as exc:
        resolve_session_owner(None)
    assert exc.value.status_code == 403


def test_default_unset_treated_as_enabled(monkeypatch):
    # AUTH_ENABLED defaults to "true" when unset — anonymous still 403s.
    monkeypatch.delenv("AUTH_ENABLED", raising=False)
    with pytest.raises(HTTPException) as exc:
        resolve_session_owner(None)
    assert exc.value.status_code == 403


def test_real_user_wins_even_when_auth_disabled(monkeypatch):
    # A resolved user is always honored, regardless of the auth flag.
    monkeypatch.setenv("AUTH_ENABLED", "false")
    assert resolve_session_owner("bob") == "bob"
