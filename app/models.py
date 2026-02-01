# app/models.py
from __future__ import annotations
from pydantic import BaseModel, Field
from typing import List, Optional, Literal, Any, Dict


class Message(BaseModel):
    sender: Literal["scammer", "user"]
    text: str
    timestamp: str


class Metadata(BaseModel):
    channel: Optional[str] = None
    language: Optional[str] = None
    locale: Optional[str] = None


class HoneypotRequest(BaseModel):
    # Some testers may send session_id instead of sessionId
    sessionId: Optional[str] = None
    session_id: Optional[str] = None

    # Some testers may send "message" correctly, or send it as "incomingMessage"
    message: Optional[Message] = None
    incomingMessage: Optional[Message] = None

    # Some testers may omit this field
    conversationHistory: List[Message] = Field(default_factory=list)

    metadata: Optional[Metadata] = None

    # Allow extra fields without failing
    class Config:
        extra = "allow"

    def normalized_session_id(self) -> str:
        return self.sessionId or self.session_id or "unknown-session"

    def normalized_message(self) -> Message:
        if self.message:
            return self.message
        if self.incomingMessage:
            return self.incomingMessage
        # fallback (should not happen if tester sends something)
        return Message(sender="scammer", text="", timestamp="1970-01-01T00:00:00Z")


class HoneypotResponse(BaseModel):
    status: str
    reply: str
