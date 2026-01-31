# app/services/scam_detector.py
from __future__ import annotations
import re
from typing import List, Tuple

# Fast rule-based scoring (optimized for low latency + stability)
KEYWORD_SIGNALS = {
    "account_blocked": (["account blocked", "blocked today", "suspended", "freeze"], 25),
    "urgent_pressure": (["urgent", "immediately", "within", "today", "now"], 15),
    "verify_kyc": (["verify", "verification", "kyc", "update kyc"], 15),
    "otp_pin": (["otp", "pin", "password", "cvv"], 30),
    "upi_request": (["upi", "upi id", "collect request", "pay", "payment"], 25),
    "bank_impersonation": (["bank", "customer care", "support", "rb i", "sbi", "hdfc", "icici", "axis"], 15),
    "reward_offer": (["prize", "lottery", "cashback", "free offer", "gift"], 15),
}

URL_RE = re.compile(r"(https?://\S+)|(\bbit\.ly/\S+|\btinyurl\.com/\S+)", re.IGNORECASE)
PHONE_RE = re.compile(r"\b(\+?91[\-\s]?)?[6-9]\d{9}\b")


def score_message(text: str) -> Tuple[int, List[str]]:
    t = (text or "").lower()
    score = 0
    matched: List[str] = []

    # Keyword scoring
    for signal_name, (phrases, points) in KEYWORD_SIGNALS.items():
        if any(p in t for p in phrases):
            score += points
            matched.append(signal_name)

    # Links are high risk
    if URL_RE.search(t):
        score += 25
        matched.append("contains_link")

    # Phone number present (often shared by scammer)
    if PHONE_RE.search(t):
        score += 10
        matched.append("contains_phone")

    # Clamp score
    score = max(0, min(score, 100))
    return score, matched


def detect_scam(text: str, threshold: int = 60) -> Tuple[bool, int, List[str]]:
    score, matched = score_message(text)
    return (score >= threshold), score, matched
