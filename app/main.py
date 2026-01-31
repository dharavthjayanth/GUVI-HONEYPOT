# app/main.py
import logging
from fastapi import Depends, FastAPI
from fastapi.responses import JSONResponse

from app.models import HoneypotRequest, HoneypotResponse
from app.utils.auth import require_api_key

from app.services.session_store import InMemorySessionStore
from app.services.scam_detector import detect_scam
from app.services.extractor import extract_intelligence

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("honeypot")

app = FastAPI(title="Agentic Honeypot API", version="0.3.0")

store = InMemorySessionStore()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/honeypot", response_model=HoneypotResponse)
def honeypot_endpoint(payload: HoneypotRequest, _: None = Depends(require_api_key)):
    """
    Day-3 behavior:
    - Session memory per sessionId
    - Scam risk scoring
    - Intelligence extraction (UPI/phone/links/accounts/keywords)
    - Still returns ONLY {status, reply} (evaluator-safe)
    """

    session_id = payload.sessionId
    latest_msg = payload.message

    logger.info(f"sessionId={session_id} sender={latest_msg.sender} text={latest_msg.text[:120]}")

    # -------- Session memory --------
    session = store.get_or_create(session_id)

    # Ingest history only once (first time we see session)
    if not session.conversation and payload.conversationHistory:
        for m in payload.conversationHistory:
            store.append_message(session, m)

    # Append latest incoming message
    store.append_message(session, latest_msg)

    # -------- Scam detection --------
    scam_now, risk_score, matched_signals = detect_scam(latest_msg.text, threshold=60)
    session.risk_score = risk_score
    session.matched_signals = matched_signals
    if scam_now:
        session.scam_detected = True

    # -------- Intelligence extraction (Day 3) --------
    # Extract primarily from scammer messages (more signal), but history may include links too.
    # We'll extract from latest message always; plus history if session is still small.
    intel_latest = extract_intelligence(latest_msg.text)
    store.merge_intelligence(session, intel_latest)

    # Optional: early turns extract from conversationHistory too (only once / small)
    if len(session.conversation) <= 6 and payload.conversationHistory:
        combined = "\n".join([m.text for m in payload.conversationHistory if m.sender == "scammer"])
        if combined.strip():
            intel_hist = extract_intelligence(combined)
            store.merge_intelligence(session, intel_hist)

    # -------- Reply strategy --------
    # Keep human-like; do not reveal detection.
    if session.scam_detected:
        # Ask 1–2 things; do NOT ask everything at once (keeps engagement going)
        reply = (
            "I’m worried. Which bank is this for? Also, can you share the official link or reference number "
            "from the message so I can confirm?"
        )
    else:
        reply = "Okay. Can you share more details?"

    return HoneypotResponse(status="success", reply=reply)


@app.exception_handler(Exception)
def global_exception_handler(request, exc: Exception):
    logger.exception(f"Unhandled error: {exc}")
    return JSONResponse(
        status_code=200,
        content={"status": "error", "reply": "Sorry, I didn’t understand. Can you repeat that?"},
    )

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
        "extractedIntelligence": s.extracted_intelligence,
    }
