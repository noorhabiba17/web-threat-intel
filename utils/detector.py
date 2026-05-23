"""
Hybrid threat detector: 4 ML models (TF-IDF + LogisticRegression / MultinomialNB /
RandomForest / ComplementNB) + hand-crafted heuristic features. Runs all four
models, shows individual results, and picks the best verdict by consensus.
"""
import os
import re
import math
import json
import joblib
import ipaddress
from typing import Any, Optional
from urllib.parse import ParseResult, urlparse

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "model")

SHORTENERS: set[str] = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "adf.ly", "cutt.ly", "rebrand.ly", "shorte.st"}
SUSPICIOUS_KW: list[str] = ["login", "verify", "update", "secure", "account", "bank", "confirm", "wallet", "gift", "free", "bonus", "prize", "invoice", "password", "signin", "webscr"]
SPAM_KW: list[str] = ["winner", "congratulations", "lottery", "claim", "prize", "free", "urgent", "limited offer", "click here", "act now", "risk-free", "cash", "credit", "loan", "viagra", "crypto", "investment", "guaranteed", "cheap", "earn money", "work from home", "subscribe", "unsubscribe"]
PHISH_PHRASES: list[str] = ["verify your account", "update your password", "suspended", "unusual activity", "confirm your identity", "tax refund", "reset your password"]
EMAIL_PHISH_PHRASES: list[str] = [
    "verify your account", "update your payment", "suspended", "unusual activity",
    "confirm your identity", "tax refund", "reset your password", "click here to confirm",
    "account will be closed", "security alert", "unauthorized login", "review your account",
    "invoice attached", "payment received", "shipping confirmation", "action required",
    "your account has been compromised", "reactivate your account", "billing update",
]
BRANDS: list[str] = [
    "google", "gmail", "youtube", "facebook", "instagram", "whatsapp", "twitter", "x.com",
    "linkedin", "amazon", "flipkart", "paypal", "netflix", "apple", "icloud", "microsoft",
    "outlook", "office365", "adobe", "dropbox", "github", "gitlab", "stackoverflow",
    "reddit", "telegram", "signal", "whatsapp", "zoom", "teams", "slack",
    "gov", "irs", "income tax", "bank", "sbi", "hdfc", "icici",
    "dhl", "fedex", "ups", "usps", "indiapost",
]
SUSPICIOUS_TLDS: set[str] = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".work", ".bid", ".rest", ".loan", ".download", ".date", ".men", ".zip", ".review"}
EMAIL_URGENT_PATTERNS: list[str] = [
    "immediately", "within 24 hours", "as soon as possible", "urgent", "time sensitive",
    "expires", "deadline", "act now", "limited time", "don't miss", "last warning",
    "final notice", "overdue", "suspended", "terminated", "deactivated",
]
ALGO_LABELS: dict[str, str] = {
    "lr": "Logistic Regression",
    "nb": "Multinomial Naive Bayes",
    "rf": "Random Forest",
    "cnb": "Complement Naive Bayes",
}


def _safe_load(name: str) -> Any:
    p = os.path.join(MODEL_DIR, name)
    return joblib.load(p) if os.path.exists(p) else None


def _load_models(prefix: str) -> dict[str, Any]:
    """Load all 4 models for a given prefix (url/txt/email)."""
    vec = _safe_load(f"{prefix}_vec.pkl")
    models: dict[str, Any] = {}
    for suffix in ("lr", "nb", "rf", "cnb"):
        m = _safe_load(f"{prefix}_{suffix}.pkl")
        if m:
            models[suffix] = m
    return vec, models


class Detector:
    def __init__(self) -> None:
        self.url_vec, self.url_models = _load_models("url")
        self.txt_vec, self.txt_models = _load_models("txt")
        self.email_vec, self.email_models = _load_models("email")

    # ---------- URL ----------
    def url_features(self, url: str) -> tuple[float, list[str]]:
        u = url.strip()
        reasons: list[str] = []
        score: float = 0.0
        try:
            parsed: Optional[ParseResult] = urlparse(u if "://" in u else "http://" + u)
        except Exception:
            parsed = None
        host: str = (parsed.hostname or "") if parsed else ""
        low = u.lower()
        host_low = host.lower()

        if len(u) > 75:
            score += 10
            reasons.append(f"Unusually long URL ({len(u)} chars)")
        if "@" in u:
            score += 20
            reasons.append("Contains '@' symbol — can hide real destination")
        if u.count(".") > 4:
            score += 10
            reasons.append("Excessive number of dots in URL")
        if "-" in host and host.count("-") >= 2:
            score += 5
            reasons.append("Multiple hyphens in domain — common in lookalikes")
        if host_low in SHORTENERS:
            score += 18
            reasons.append(f"Shortened link ({host}) — final destination hidden")
        try:
            ipaddress.ip_address(host)
            score += 25
            reasons.append("URL uses raw IP address instead of domain")
        except ValueError:
            pass
        hits = [k for k in SUSPICIOUS_KW if k in low]
        if hits:
            score += min(20, 4 * len(hits))
            reasons.append("Suspicious keywords: " + ", ".join(hits[:5]))
        if re.search(r"(xn--)", host):
            score += 15
            reasons.append("Punycode domain — possible homograph attack")
        if parsed and parsed.path and len(parsed.path) > 40:
            score += 5
            reasons.append("Long URL path")

        for brand in BRANDS:
            if brand in host_low and brand not in host_low.replace("www.", "").split(".")[0]:
                continue
            if brand == host_low.replace("www.", ""):
                continue
            parts = host_low.replace("www.", "").split(".")
            if len(parts) >= 2 and parts[0] != brand and brand in parts[0]:
                score += 20
                reasons.append(f"Suspicious — domain contains '{brand}' but isn't official")
                break
            if len(parts[0]) <= 15 and brand != parts[0]:
                diff = sum(1 for a, b in zip(brand, parts[0]) if a != b) + abs(len(brand) - len(parts[0]))
                if 1 <= diff <= 2 and brand[:2] == parts[0][:2]:
                    score += 25
                    reasons.append(f"Typosquatting detected — '{parts[0]}' looks like '{brand}'")
                    break

        if parsed and parsed.hostname:
            for tld in SUSPICIOUS_TLDS:
                if parsed.hostname.endswith(tld):
                    score += 12
                    reasons.append(f"Suspicious TLD '{tld}' — commonly used for phishing")
                    break

        if not u.lower().startswith("https://"):
            score += 8
            reasons.append("No HTTPS — connection is not encrypted")

        return score, reasons

    def _predict_models(self, text: str, vec: Any, models: dict[str, Any], ml_weight: float) -> dict[str, Any]:
        """Run all loaded models and return individual results + consensus."""
        results: dict[str, float] = {}
        for suffix, clf in models.items():
            try:
                proba = clf.predict_proba(vec.transform([text]))[0][1]
                results[suffix] = round(float(proba), 4)
            except Exception:
                results[suffix] = 0.0
        if not results:
            return {"individual": {}, "avg_prob": 0.0, "best": "", "ml_score": 0.0}
        avg_prob = sum(results.values()) / len(results)
        best_suffix = max(results, key=results.get)
        ml_score = avg_prob * ml_weight
        return {
            "individual": results,
            "avg_prob": round(avg_prob, 4),
            "best": best_suffix,
            "ml_score": ml_score,
        }

    def predict_url(self, url: str) -> dict[str, Any]:
        h_score, reasons = self.url_features(url)
        ml = self._predict_models(url, self.url_vec, self.url_models, 60.0)
        risk = min(100.0, h_score + ml["ml_score"])
        result = self._verdict(risk, reasons, kind="url")
        result["algorithms"] = ml
        for suffix, proba in ml["individual"].items():
            reasons.append(f"{ALGO_LABELS.get(suffix, suffix)}: {proba * 100:.1f}%")
        if ml["best"]:
            reasons.append(f"Best model: {ALGO_LABELS.get(ml['best'], ml['best'])}")
        return result

    # ---------- Text (email/sms) ----------
    def text_features(self, text: str, kind: str = "text") -> tuple[float, list[str]]:
        t = text or ""
        reasons: list[str] = []
        score: float = 0.0
        low = t.lower()
        hits = [k for k in SPAM_KW if k in low]
        if hits:
            score += min(35, 5 * len(hits))
            reasons.append("Spam keywords: " + ", ".join(hits[:6]))
        ph = [p for p in PHISH_PHRASES if p in low]
        if ph:
            score += min(25, 8 * len(ph))
            reasons.append("Phishing phrases: " + ", ".join(ph[:3]))
        urls = re.findall(r"https?://\S+|www\.\S+", t)
        if urls:
            score += 8
            reasons.append(f"Contains {len(urls)} embedded link(s)")
            for u in urls[:3]:
                s2, _ = self.url_features(u)
                if s2 > 30:
                    score += 10
                    reasons.append(f"Embedded link looks risky: {u[:50]}")
        letters = sum(c.isalpha() for c in t)
        upp = sum(c.isupper() for c in t)
        if letters > 30 and upp / letters > 0.4:
            score += 8
            reasons.append("Excessive capitalization (shouting)")
        if t.count("!") >= 3:
            score += 6
            reasons.append("Multiple exclamation marks")
        if re.search(r"\b\d{4,}\b", t) and ("otp" in low or "code" in low):
            score += 10
            reasons.append("Mentions OTP/code — possible account-takeover attempt")

        if kind == "email":
            urgent_hits = [p for p in EMAIL_URGENT_PATTERNS if p in low]
            if urgent_hits:
                score += min(20, 5 * len(urgent_hits))
                reasons.append("Urgency language: " + ", ".join(urgent_hits[:4]))
            for brand in BRANDS:
                if brand in low:
                    score += 5
                    reasons.append(f"Mentions '{brand}' — possible impersonation")
                    break
            eph = [p for p in EMAIL_PHISH_PHRASES if p in low]
            if eph:
                score += min(30, 6 * len(eph))
                reasons.append("Email phishing language: " + ", ".join(eph[:4]))
            reply_to = re.findall(r"reply-to:\s*\S+@\S+", t, re.IGNORECASE)
            if reply_to:
                score += 10
                reasons.append("Reply-to header present — could redirect replies")
            if re.search(r"dear (customer|user|valued|account)", low):
                score += 8
                reasons.append("Generic greeting — legitimate services use your name")

        return score, reasons

    def predict_text(self, text: str, kind: str) -> dict[str, Any]:
        h_score, reasons = self.text_features(text, kind)
        vec = self.email_vec if kind == "email" else self.txt_vec
        models = self.email_models if kind == "email" else self.txt_models
        ml = self._predict_models(text, vec, models, 55.0)
        risk = min(100.0, h_score + ml["ml_score"])
        result = self._verdict(risk, reasons, kind=kind)
        result["algorithms"] = ml
        for suffix, proba in ml["individual"].items():
            reasons.append(f"{ALGO_LABELS.get(suffix, suffix)}: {proba * 100:.1f}%")
        if ml["best"]:
            reasons.append(f"Best model: {ALGO_LABELS.get(ml['best'], ml['best'])}")
        return result

    # ---------- Verdict ----------
    def _verdict(self, risk: float, reasons: list[str], kind: str) -> dict[str, Any]:
        if risk < 30:
            verdict, suggestions = "Safe", [
                "Looks clean, but always stay alert.",
                "Never share OTPs or passwords.",
                "Bookmark trusted sites instead of clicking links.",
            ]
        elif risk < 60:
            verdict, suggestions = "Medium", [
                "Treat with caution — verify the sender via another channel.",
                "Hover over links before clicking.",
                "Do not enter credentials unless you are sure of the site.",
            ]
        else:
            verdict, suggestions = "High Risk", [
                "Do NOT click any links or download attachments.",
                "Report the message to your IT/security team or provider.",
                "If you already interacted, visit the Recovery Center immediately.",
                "Change your password and enable 2FA on related accounts.",
            ]
        if not reasons:
            reasons = ["No strong indicators detected."]
        return {"risk_score": round(risk, 1), "verdict": verdict, "reasons": reasons, "suggestions": suggestions, "kind": kind}


detector: Detector = Detector()
