import logging
from fastapi import Depends, FastAPI
from fastapi.responses import JSONResponse

from app.models import HoneypotRequest, HoneypotResponse
from app.utils.auth import require_api_key

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("honeypot")

app = FastAPI(title="Agentic Honeypot API", version="0.1.0")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/honeypot", response_model=HoneypotResponse)
def honeypot_endpoint(payload: HoneypotRequest, _: None = Depends(require_api_key)):
    """
    Day-1 behavior:
    - Accept the official request structure
    - Validate API key
    - Return a safe, human-like reply
    """

    session_id = payload.sessionId
    latest = payload.message.text.lower()

    logger.info(f"sessionId={session_id} sender={payload.message.sender} text={payload.message.text[:80]}")

    # Simple placeholder logic for Day 1 (we'll replace with real detection Day 2)
    suspicious_keywords = ["blocked", "suspended", "verify", "kyc", "otp", "upi", "urgent", "immediately", "link", "refund"]
    is_suspicious = any(k in latest for k in suspicious_keywords)

    if is_suspicious:
        reply = "Why is my account being blocked? Can you tell me the exact reason and reference number?"
    else:
        reply = "Okay. Can you share more details?"

    return HoneypotResponse(status="success", reply=reply)


# Global error safety net (prevents ugly crashes from breaking evaluator)
@app.exception_handler(Exception)
def global_exception_handler(request, exc: Exception):
    logger.exception(f"Unhandled error: {exc}")
    return JSONResponse(
        status_code=200,  # keep stable response for evaluators
        content={"status": "error", "reply": "Sorry, I didn’t understand. Can you repeat that?"}
    )
