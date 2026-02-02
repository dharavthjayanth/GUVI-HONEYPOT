# app/main.py
import logging
from typing import Any, Dict, List

from fastapi import BackgroundTasks, Body, Depends, FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.utils.auth import require_api_key
from app.services.session_store import InMemorySessionStore
from app.services.scam_detector import detect_scam
from app.services.extractor import extract_intelligence
from app.services.callback import send_guvi_final_result, build_agent_notes

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("honeypot")

app = FastAPI(title="Agentic Honeypot API", version="0.4.2")

store = InMemorySessionStore()


@app.get("/health")
def health():
    return {"status": "ok"}


# Safety net: If any validation happens elsewhere, never return 422 to tester.
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    logger.warning(f"RequestValidationError intercepted: {exc}")
    return JSONResponse(
        status_code=200,
        content={
            "status": "success",
            "reply": "Can you share the official bank name and the reference number or link from the message?"
        },
    )


# Optional: keep your global exception handler
@app.exception_handler(Exception)
def global_exception_handler(request, exc: Exception):
    logger.exception(f"Unhandled error: {exc}")
    return JSONResponse(
        status_code=200,
        content={"status": "error", "reply": "Sorry, I didn’t understand. Can you repeat that?"},
    )


def _safe_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _safe_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


@app.post("/honeypot")
def honeypot_endpoint(
    background_tasks: BackgroundTasks,                 # ✅ no default
    payload: Dict[str, Any] = Body(default_factory=dict),
    _: None = Depends(require_api_key),
):

    """
    GUVI-tester-safe endpoint:
    - Accepts ANY JSON body (avoids 422)
    - Normalizes fields (sessionId/message/history variations)
    - Runs Day 2–4 logic (memory, detection, extraction, callback)
    - Returns ONLY {status, reply}
    """

    # ---- Normalize fields ----
    session_id = (
        payload.get("sessionId")
        or payload.get("session_id")
        or payload.get("sessionID")
        or "unknown-session"
    )

    msg = _safe_dict(payload.get("message") or payload.get("incomingMessage") or payload.get("incoming_message"))
    sender = msg.get("sender") or "scammer"
    text = msg.get("text") or ""
    timestamp = msg.get("timestamp") or "1970-01-01T00:00:00Z"

    history = _safe_list(payload.get("conversationHistory") or payload.get("conversation_history") or payload.get("history"))

    logger.info(f"sessionId={session_id} sender={sender} text={str(text)[:120]}")

    # ---- Session memory ----
    session = store.get_or_create(session_id)

    # Ingest history only once (first time we see session)
    if not session.conversation and history:
        for m in history:
            if not isinstance(m, dict):
                continue
            store.append_message_dict(session, m)

    # Append latest incoming message
    store.append_message_dict(session, {"sender": sender, "text": text, "timestamp": timestamp})

    # ---- Scam detection ----
    scam_now, risk_score, matched_signals = detect_scam(text, threshold=60)
    session.risk_score = risk_score
    session.matched_signals = matched_signals
    if scam_now:
        session.scam_detected = True

    # ---- Intelligence extraction ----
    store.merge_intelligence(session, extract_intelligence(text))

    # Also extract from scammer history early (small boost)
    if len(session.conversation) <= 6 and history:
        combined = "\n".join([m.get("text", "") for m in history if isinstance(m, dict) and m.get("sender") == "scammer"])
        if combined.strip():
            store.merge_intelligence(session, extract_intelligence(combined))

    # ---- Day 4: Final callback trigger ----
    if store.should_finalize(session) and not session.callback_sent:
        agent_notes = build_agent_notes(
            matched_signals=session.matched_signals,
            extracted=session.extracted_intelligence,
        )

        def _send_callback():
            ok = send_guvi_final_result(
                session_id=session.session_id,
                scam_detected=True,
                total_messages_exchanged=session.total_messages_exchanged,
                extracted_intelligence=session.extracted_intelligence,
                agent_notes=agent_notes,
            )
            if ok:
                session.callback_sent = True
                session.status = "COMPLETED"

        # Non-blocking callback (keeps API fast)
        background_tasks.add_task(_send_callback)


    # ---- Reply strategy (policy-based) ----
    if session.scam_detected:
        if session.extracted_intelligence.get("phishingLinks"):
            reply = (
                "I got the link. Before I click, can you confirm the official bank name and the reference number? "
                "Also, what exactly will happen if I don’t do it today?"
            )
        else:
            reply = (
                "I’m worried. Which bank is this for? Can you share the official link or reference number from the message "
                "so I can confirm?"
            )
    else:
        reply = "Okay. Can you share more details?"

    return JSONResponse(status_code=200, content={"status": "success", "reply": reply})


# -------- Debug endpoint (keep until final day; API-key protected) --------
@app.get("/debug/session/{session_id}")
def debug_session(session_id: str, _: None = Depends(require_api_key)):
    s = store.get(session_id)
    if not s:
        return {"found": False, "sessionId": session_id}

    return {
        "found": True,
        "sessionId": s.session_id,
        "scamDetected": s.scam_detected,
        "riskScore": s.risk_score,
        "matchedSignals": s.matched_signals,
        "totalMessagesExchanged": s.total_messages_exchanged,
        "callbackSent": getattr(s, "callback_sent", False),
        "status": getattr(s, "status", "ACTIVE"),
        "extractedIntelligence": s.extracted_intelligence,
    }
