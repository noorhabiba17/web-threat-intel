"""
Hybrid threat detector: 3 ML models (TF-IDF + LogisticRegression / RandomForest /
ComplementNB) + hand-crafted heuristic features. Runs all three models, shows
individual results, and picks the best verdict by majority vote.
"""
import os, re, math, json, joblib, ipaddress
from typing import Any, Optional
from urllib.parse import ParseResult, urlparse

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "model")

SHORTENERS: set[str] = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "adf.ly", "cutt.ly", "rebrand.ly", "shorte.st"}
SUSPICIOUS_KW: list[str] = ["login", "verify", "update", "secure", "account", "bank", "confirm", "wallet", "gift", "free", "bonus", "prize", "invoice", "password", "signin", "webscr"]
SPAM_KW: list[str] = ["winner", "congratulations", "lottery", "claim", "prize", "free", "urgent", "limited offer", "click here", "act now", "risk-free", "cash", "credit", "loan", "viagra", "crypto", "investment", "guaranteed", "cheap", "earn money", "work from home", "subscribe", "unsubscribe"]
PHISH_PHRASES: list[str] = ["verify your account", "update your password", "suspended", "unusual activity", "confirm your identity", "tax refund", "reset your password"]


def _safe_load(name: str) -> Any:
    p = os.path.join(MODEL_DIR, name)
    return joblib.load(p) if os.path.exists(p) else None


class Detector:
    def __init__(self) -> None:
        self.url_vec: Any = _safe_load("url_vec.pkl")
        self.url_clf: Any = _safe_load("url_clf.pkl")
        self.txt_vec: Any = _safe_load("txt_vec.pkl")
        self.txt_clf: Any = _safe_load("txt_clf.pkl")

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

        if not u.lower().startswith("https://"):
            score += 15
            reasons.append("No HTTPS — connection is not encrypted")
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
        if host in SHORTENERS:
            score += 18
            reasons.append(f"Shortened link ({host}) — final destination hidden")
        try:
            ipaddress.ip_address(host)
            score += 25
            reasons.append("URL uses raw IP address instead of domain")
        except ValueError:
            pass
        low = u.lower()
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
        return score, reasons

    def predict_url(self, url: str) -> dict[str, Any]:
        h_score, reasons = self.url_features(url)
        ml_score = 0.0
        if self.url_vec and self.url_clf:
            try:
                proba = self.url_clf.predict_proba(self.url_vec.transform([url]))[0][1]
                ml_score = float(proba) * 60.0
                reasons.append(f"ML phishing probability: {proba * 100:.1f}%")
            except Exception:
                pass
        risk = min(100.0, h_score + ml_score)
        return self._verdict(risk, reasons, kind="url")

    # ---------- Text (email/sms) ----------
    def text_features(self, text: str) -> tuple[float, list[str]]:
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
        return score, reasons

    def predict_text(self, text: str, kind: str) -> dict[str, Any]:
        h_score, reasons = self.text_features(text)
        ml_score = 0.0
        if self.txt_vec and self.txt_clf:
            try:
                proba = self.txt_clf.predict_proba(self.txt_vec.transform([text]))[0][1]
                ml_score = float(proba) * 55.0
                reasons.append(f"ML spam probability: {proba * 100:.1f}%")
            except Exception:
                pass
        risk = min(100.0, h_score + ml_score)
        return self._verdict(risk, reasons, kind=kind)

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
