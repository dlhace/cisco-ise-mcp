"""In-memory MCP session store.

v1: memory-only. Sessions are lost on restart.
TODO(phase2): pluggable backend (e.g. Redis) for multi-instance CF deployments.
Implement a SessionBackend protocol and select via env; SessionStore already hides
the storage behind a small API so tools/providers won't change.
"""
from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field

from .base import AuthContext


@dataclass
class Session:
    session_id: str
    username: str
    auth: AuthContext
    created_at: float
    last_used_at: float
    ttl_seconds: int
    idle_timeout_seconds: int

    def is_expired(self, now: float) -> bool:
        if self.ttl_seconds and now - self.created_at > self.ttl_seconds:
            return True
        if self.idle_timeout_seconds and now - self.last_used_at > self.idle_timeout_seconds:
            return True
        return False

    def public(self) -> dict:
        return {
            "session_id": self.session_id,
            "username": self.username,
            "mode": self.auth.mode,
            "created_at": int(self.created_at),
            "last_used_at": int(self.last_used_at),
            "ttl_seconds": self.ttl_seconds,
            "idle_timeout_seconds": self.idle_timeout_seconds,
        }


class SessionStore:
    def __init__(self, ttl_seconds: int, idle_timeout_seconds: int, *, clock=time.time):
        self._ttl = ttl_seconds
        self._idle = idle_timeout_seconds
        self._clock = clock
        self._lock = threading.Lock()  # ponytail: one global lock; fine for single-instance v1
        self._sessions: dict[str, Session] = {}

    def create(self, username: str, auth: AuthContext) -> Session:
        now = self._clock()
        sid = secrets.token_urlsafe(32)
        sess = Session(
            session_id=sid,
            username=username,
            auth=auth,
            created_at=now,
            last_used_at=now,
            ttl_seconds=self._ttl,
            idle_timeout_seconds=self._idle,
        )
        with self._lock:
            self._sessions[sid] = sess
        return sess

    def get(self, session_id: str | None) -> Session | None:
        if not session_id:
            return None
        now = self._clock()
        with self._lock:
            sess = self._sessions.get(session_id)
            if sess is None:
                return None
            if sess.is_expired(now):
                del self._sessions[session_id]
                return None
            sess.last_used_at = now
            return sess

    def delete(self, session_id: str | None) -> bool:
        if not session_id:
            return False
        with self._lock:
            return self._sessions.pop(session_id, None) is not None

    def purge_expired(self) -> int:
        now = self._clock()
        with self._lock:
            dead = [sid for sid, s in self._sessions.items() if s.is_expired(now)]
            for sid in dead:
                del self._sessions[sid]
        return len(dead)

    def __len__(self) -> int:
        return len(self._sessions)
