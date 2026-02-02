# app/main.py
import logging
from fastapi import Depends, FastAPI, BackgroundTasks
from fastapi.responses import JSONResponse
from fastapi import Request, BackgroundTasks, Depends
from fastapi.responses import JSONResponse
from app.models import HoneypotRequest, HoneypotResponse
from app.utils.auth import require_api_key

from app.services.session_store import InMemorySessionStore
from app.services.scam_detector import detect_scam
from app.services.extractor import extract_intelligence
from app.services.callback import send_guvi_final_result, build_agent_notes

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("honeypot")

app = FastAPI(title="Agentic Honeypot API", version="0.4.0")
store = InMemorySessionStore()


@app.get("/health")
def health():
    return {"status": "ok"}






@app.post("/honeypot")
async def honeypot_endpoint(
    request: Request,
    background_tasks: BackgroundTasks,
    _: None = Depends(require_api_key),
):
    """
    GUVI-tester-safe endpoint:
    - Accepts ANY JSON body (prevents 422 RequestValidationError)
    - Normalizes into our internal structure
    - Returns ONLY {status, reply}
    """
    try:
        body = await request.json()
        if not isinstance(body, dict):
            body = {}
    except Exception:
        body = {}

    # ---- Normalize fields (handle variations) ----
    session_id = (
        body.get("sessionId")
        or body.get("session_id")
        or body.get("sessionID")
        or "unknown-session"
    )

    msg_obj = body.get("message") or body.get("incomingMessage") or {}
    sender = msg_obj.get("sender") or "scammer"
    text = msg_obj.get("text") or ""
    timestamp = msg_obj.get("timestamp") or "1970-01-01T00:00:00Z"

    conversation_history = body.get("conversationHistory") or body.get("history") or []
    if not isinstance(conversation_history, list):
        conversation_history = []

    # ---- Now run your existing logic using normalized values ----
    logger.info(f"sessionId={session_id} sender={sender} text={str(text)[:120]}")

    session = store.get_or_create(session_id)

    # ingest history if first time
    if not session.conversation and conversation_history:
        for m in conversation_history:
            try:
                if isinstance(m, dict):
                    store.append_message_dict(session, m)  # We'll add this helper below
            except Exception:
                continue

    # append latest message (as dict)
    store.append_message_dict(session, {"sender": sender, "text": text, "timestamp": timestamp})

    # scam detection
    scam_now, risk_score, matched_signals = detect_scam(text, threshold=60)
    session.risk_score = risk_score
    session.matched_signals = matched_signals
    if scam_now:
        session.scam_detected = True

    # extraction
    store.merge_intelligence(session, extract_intelligence(text))

    # callback trigger
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

        background_tasks.add_task(_send_callback)

    # reply strategy
    if session.scam_detected:
        reply = "I’m worried. Which bank is this for? Can you share the official link or reference number so I can confirm?"
    else:
        reply = "Okay. Can you share more details?"

    return JSONResponse(status_code=200, content={"status": "success", "reply": reply})



@app.exception_handler(Exception)
def global_exception_handler(request, exc: Exception):
    logger.exception(f"Unhandled error: {exc}")
    return JSONResponse(
        status_code=200,
        content={"status": "error", "reply": "Sorry, I didn’t understand. Can you repeat that?"},
    )
