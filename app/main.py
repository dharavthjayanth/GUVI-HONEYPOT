# app/main.py
import logging
from fastapi import Depends, FastAPI, BackgroundTasks
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


@app.post("/honeypot", response_model=HoneypotResponse)
def honeypot_endpoint(
    payload: HoneypotRequest,
    background_tasks: BackgroundTasks,
    _: None = Depends(require_api_key),
):
    session_id = payload.normalized_session_id()
    latest_msg = payload.normalized_message()


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

    # -------- Intelligence extraction --------
    intel_latest = extract_intelligence(latest_msg.text)
    store.merge_intelligence(session, intel_latest)

    # Optional: early turns extract from history too (small boost)
    if len(session.conversation) <= 6 and payload.conversationHistory:
        combined = "\n".join([m.text for m in payload.conversationHistory if m.sender == "scammer"])
        if combined.strip():
            store.merge_intelligence(session, extract_intelligence(combined))

    # -------- Day 4: Final callback trigger --------
    # Send callback only when we have enough engagement + high-value intel
    if store.should_finalize(session):
        agent_notes = build_agent_notes(
            matched_signals=session.matched_signals,
            extracted=session.extracted_intelligence,
        )

        # Mark as attempted to avoid duplicate spamming on fast repeated calls
        session.callback_attempts += 1

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

        # Run callback after response (keeps /honeypot fast)
        background_tasks.add_task(_send_callback)

    # -------- Reply strategy --------
    # Keep human-like and never reveal detection.
    if session.scam_detected:
        # Ask 1–2 things at a time (keeps engagement longer)
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

    return HoneypotResponse(status="success", reply=reply)


@app.exception_handler(Exception)
def global_exception_handler(request, exc: Exception):
    logger.exception(f"Unhandled error: {exc}")
    return JSONResponse(
        status_code=200,
        content={"status": "error", "reply": "Sorry, I didn’t understand. Can you repeat that?"},
    )
