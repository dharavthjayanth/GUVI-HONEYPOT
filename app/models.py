from typing import List, Literal, Optional
from pydantic import BaseModel, Field


SenderType = Literal["scammer", "user"]


class Message(BaseModel):
    sender: SenderType
    text: str = Field(..., min_length=1, max_length=5000)
    timestamp: str = Field(..., description="ISO-8601 timestamp string")


class Metadata(BaseModel):
    channel: Optional[str] = None       # SMS / WhatsApp / Email / Chat
    language: Optional[str] = None      # English / Hindi / etc.
    locale: Optional[str] = None        # IN / etc.


class HoneypotRequest(BaseModel):
    sessionId: str = Field(..., min_length=3, max_length=128)
    message: Message
    conversationHistory: List[Message] = Field(default_factory=list)
    metadata: Optional[Metadata] = None


class HoneypotResponse(BaseModel):
    status: Literal["success", "error"]
    reply: str
