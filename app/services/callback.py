# app/services/callback.py
from __future__ import annotations

import logging
import time
from typing import Dict, Any, Optional

import requests

logger = logging.getLogger("honeypot.callback")

GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"


def build_agent_notes(*, matched_signals: list[str], extracted: Dict[str, list[str]]) -> str:
    parts = []
    if matched_signals:
        parts.append(f"Signals: {', '.join(matched_signals[:8])}.")
    if extracted.get("upiIds"):
        parts.append("UPI requested/shared.")
    if extracted.get("phishingLinks"):
        parts.append("Link(s) shared.")
    if extracted.get("phoneNumbers"):
        parts.append("Phone number shared.")
    if extracted.get("bankAccounts"):
        parts.append("Bank account number shared.")
    if not parts:
        parts.append("Scam behavior observed with urgency and verification prompts.")
    return " ".join(parts)


def send_guvi_final_result(
    *,
    session_id: str,
    scam_detected: bool,
    total_messages_exchanged: int,
    extracted_intelligence: Dict[str, list[str]],
    agent_notes: str,
    timeout_seconds: int = 5,
    max_retries: int = 2,
) -> bool:
    """
    Sends the mandatory final callback to GUVI.
    Retries a few times on network errors.
    Returns True if success, False otherwise.
    """
    payload: Dict[str, Any] = {
        "sessionId": session_id,
        "scamDetected": scam_detected,
        "totalMessagesExchanged": total_messages_exchanged,
        "extractedIntelligence": extracted_intelligence,
        "agentNotes": agent_notes,
    }

    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.post(
                GUVI_CALLBACK_URL,
                json=payload,
                timeout=timeout_seconds,
            )
            # Treat any 2xx as success
            if 200 <= resp.status_code < 300:
                logger.info(f"GUVI callback success | sessionId={session_id} | status={resp.status_code}")
                return True

            logger.warning(
                f"GUVI callback non-2xx | sessionId={session_id} | status={resp.status_code} | body={resp.text[:200]}"
            )

        except Exception as e:
            logger.error(f"GUVI callback error | sessionId={session_id} | attempt={attempt} | err={e}")

        # small backoff
        time.sleep(min(1.5 * attempt, 4.0))

    return False
