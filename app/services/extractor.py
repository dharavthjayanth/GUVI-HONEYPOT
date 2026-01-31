# app/services/extractor.py
from __future__ import annotations
import re
from typing import Dict, List, Set


# --- Regex patterns (practical for IN scams) ---
URL_RE = re.compile(
    r"(https?://[^\s]+)|(\bbit\.ly/[^\s]+|\btinyurl\.com/[^\s]+)",
    re.IGNORECASE,
)

# Indian phone: allows +91, spaces/dashes; main 10-digit starting 6-9
PHONE_RE = re.compile(r"\b(?:\+?91[\s\-]?)?[6-9]\d{9}\b")

# UPI: handle@bank (common)
UPI_RE = re.compile(r"\b[a-z0-9.\-_]{2,}@[a-z0-9]{2,}\b", re.IGNORECASE)

# Bank account-ish: 9 to 18 digits (avoid OTP 4-6 digits by min length)
BANK_ACCT_RE = re.compile(r"\b\d{9,18}\b")

# IFSC: e.g., HDFC0001234
IFSC_RE = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b", re.IGNORECASE)


# keywords we want to log as suspicious (extend anytime)
SUSPICIOUS_KEYWORDS = [
    "urgent",
    "immediately",
    "verify",
    "verification",
    "kyc",
    "otp",
    "pin",
    "password",
    "cvv",
    "account blocked",
    "blocked",
    "suspend",
    "suspended",
    "freeze",
    "upi",
    "upi id",
    "collect request",
    "payment",
    "refund",
    "click",
    "link",
    "download",
    "apk",
    "customer care",
    "support",
    "helpline",
]


def _normalize_phone(p: str) -> str:
    # Keep digits only
    digits = re.sub(r"\D", "", p)
    # Convert 91XXXXXXXXXX -> +91XXXXXXXXXX
    if len(digits) == 12 and digits.startswith("91"):
        return f"+{digits}"
    # 10-digit local
    if len(digits) == 10:
        return f"+91{digits}"
    return p.strip()


def _normalize_url(u: str) -> str:
    return u.strip().strip(").,;]}>\"'")


def extract_intelligence(text: str) -> Dict[str, List[str]]:
    """
    Extract intelligence from a single text.
    Returns a dict with keys matching GUVI callback schema fields:
      - bankAccounts, upiIds, phishingLinks, phoneNumbers, suspiciousKeywords
    """
    t = text or ""

    # ---- URLs ----
    urls: List[str] = []
    for m in URL_RE.finditer(t):
        val = m.group(0)
        if val:
            urls.append(_normalize_url(val))

    # ---- Phones ----
    phones_found = [m.group(0) for m in PHONE_RE.finditer(t)]
    phones = [_normalize_phone(p) for p in phones_found]

    # ---- UPI IDs ----
    upis = [m.group(0).lower() for m in UPI_RE.finditer(t)]

    # ---- IFSC (optional, used as keyword signal) ----
    ifscs = [m.group(0).upper() for m in IFSC_RE.finditer(t)]

    # ---- Bank Accounts ----
    # Avoid false positives where phone numbers are captured as bank accounts.
    # Build a set of phone digits to exclude.
    phones_raw_digits: Set[str] = set(re.sub(r"\D", "", p) for p in phones_found)

    accts: List[str] = []
    for m in BANK_ACCT_RE.finditer(t):
        num = m.group(0)
        digits = re.sub(r"\D", "", num)

        # Exclude phone-like numbers:
        # - exact phone digits seen
        # - 10-digit numbers (likely phone)
        # - 12-digit starting with 91 (likely phone with country code)
        if (
            digits in phones_raw_digits
            or len(digits) == 10
            or (len(digits) == 12 and digits.startswith("91"))
        ):
            continue

        accts.append(num)

    # ---- Suspicious Keywords ----
    lower = t.lower()
    kws = [k for k in SUSPICIOUS_KEYWORDS if k in lower]

    # Add IFSC presence as a keyword (useful behavior note)
    if ifscs and "ifsc_shared" not in kws:
        kws.append("ifsc_shared")

    return {
        "bankAccounts": accts,
        "upiIds": upis,
        "phishingLinks": urls,
        "phoneNumbers": phones,
        "suspiciousKeywords": kws,
    }
