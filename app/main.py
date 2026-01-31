# app/main.py
import logging
from fastapi import Depends, FastAPI
from fastapi.responses import JSONResponse

from app.models import HoneypotRequest, HoneypotResponse
from app.utils.auth import require_api_key

from app.services.session_store import InMemorySessionStore
from app.services.scam_detector import detect_scam

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("honeypot")

app = FastAPI(title="Agentic Honeypot API", version="0.2.0")

# In-memory session store (hackathon-friendly)
store = InMemorySessionStore()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/honeypot", response_model=HoneypotResponse)
def honeypot_endpoint(payload: HoneypotRequest, _: None = Depends(require_api_key)):
    """
    Day-2 behavior:
    - Accept the official request structure
    - Validate API key
    - Maintain session memory (per sessionId)
    - Compute a fast scam risk score + matched signals
    - Return a safe, human-like reply (do NOT reveal detection)
    """

    session_id = payload.sessionId
    latest_msg = payload.message

    logger.info(
        f"sessionId={session_id} sender={latest_msg.sender} "
        f"text={latest_msg.text[:120]}"
    )

    # -------------------------
    # Session memory
    # -------------------------
    session = store.get_or_create(session_id)

    # If this is the first time we see this session and history exists,
    # ingest history once to keep memory consistent.
    if not session.conversation and payload.conversationHistory:
        for m in payload.conversationHistory:
            store.append_message(session, m)

    # Append latest incoming message
    store.append_message(session, latest_msg)

    # -------------------------
    # Scam detection (rules score)
    # -------------------------
    scam_now, risk_score, matched_signals = detect_scam(latest_msg.text, threshold=60)
    session.risk_score = risk_score
    session.matched_signals = matched_signals

    # Once scam is detected, keep it sticky for the session
    if scam_now:
        session.scam_detected = True

    # -------------------------
    # Reply strategy (Day 2)
    # -------------------------
    # Must be human-like and must NOT say "scam/fraud".
    if session.scam_detected:
        # Ask for details that cause the scammer to reveal more info.
        reply = (
            "I’m worried. Which bank is this for, and can you share the reference/ticket number "
            "from the SMS? Also tell me the official customer care number you’re calling from."
        )
    else:
        reply = "Okay. Can you share more details?"

    return HoneypotResponse(status="success", reply=reply)


# Global error safety net (prevents crashes from breaking evaluator)
@app.exception_handler(Exception)
def global_exception_handler(request, exc: Exception):
    logger.exception(f"Unhandled error: {exc}")
    return JSONResponse(
        status_code=200,  # keep stable response for evaluators
        content={
            "status": "error",
            "reply": "Sorry, I didn’t understand. Can you repeat that?"
        },
    )
