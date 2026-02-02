# app/services/session_store.py
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional
import time

from app.models import Message


@dataclass
class SessionState:
    session_id: str
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    scam_detected: bool = False
    risk_score: int = 0
    matched_signals: List[str] = field(default_factory=list)

    total_messages_exchanged: int = 0
    conversation: List[Message] = field(default_factory=list)

    # (Day 3/4 we’ll fill this)
    extracted_intelligence: dict = field(default_factory=lambda: {
        "bankAccounts": [],
        "upiIds": [],
        "phishingLinks": [],
        "phoneNumbers": [],
        "suspiciousKeywords": []
    })

    agent_notes: str = ""
    status: str = "ACTIVE"  # ACTIVE / COMPLETED
    callback_sent: bool = False
    callback_attempts: int = 0


class InMemorySessionStore:
    """
    Simple in-memory store for hackathon.
    Works on single Render instance. (Good enough for evaluation.)
    """
    def __init__(self):
        self._store: Dict[str, SessionState] = {}

    def get_or_create(self, session_id: str) -> SessionState:
        s = self._store.get(session_id)
        if not s:
            s = SessionState(session_id=session_id)
            self._store[session_id] = s
        return s

    def update_timestamp(self, s: SessionState) -> None:
        s.updated_at = time.time()

    def append_message(self, s: SessionState, msg: Message) -> None:
        s.conversation.append(msg)
        s.total_messages_exchanged += 1
        self.update_timestamp(s)

    def get(self, session_id: str) -> Optional[SessionState]:
        return self._store.get(session_id)
    
    def merge_intelligence(self, s: SessionState, intel: dict) -> None:
        """
        Merge extracted intel into the session's extracted_intelligence dict (dedupe).
        """
        for key in ["bankAccounts", "upiIds", "phishingLinks", "phoneNumbers", "suspiciousKeywords"]:
            existing = s.extracted_intelligence.get(key, [])
            for item in intel.get(key, []):
                if item and item not in existing:
                    existing.append(item)
            s.extracted_intelligence[key] = existing

        self.update_timestamp(s)
    def should_finalize(self, s) -> bool:
        """
        Decide if we should send the GUVI final callback.
        Rules:
        - Scam detected
        - Not already sent
        - Has at least one high-value intel: UPI OR link OR phone OR bank account
        - Enough engagement (min messages)
        """
        if s.callback_sent:
            return False
        if not s.scam_detected:
            return False

        has_high_value = bool(
            s.extracted_intelligence.get("upiIds")
            or s.extracted_intelligence.get("phishingLinks")
            or s.extracted_intelligence.get("phoneNumbers")
            or s.extracted_intelligence.get("bankAccounts")
        )

        # you can tune this later (2 is good for “engagement depth”)
        min_turns = 2
        return has_high_value and s.total_messages_exchanged >= min_turns
    def append_message_dict(self, s, m: dict) -> None:
        sender = m.get("sender", "scammer")
        text = m.get("text", "")
        timestamp = m.get("timestamp", "1970-01-01T00:00:00Z")
        # reuse your existing append_message logic if it expects a Message object,
        # otherwise store dicts consistently.
        s.conversation.append({"sender": sender, "text": text, "timestamp": timestamp})
        s.total_messages_exchanged += 1
        self.update_timestamp(s)



