"""
Hybrid threat detector: 3 ML models (TF-IDF + LogisticRegression / RandomForest /
ComplementNB) + hand-crafted heuristic features. Runs all three models, shows
individual results, and picks the best verdict by majority vote.
"""
import os, re, math, json, joblib, ipaddress
from urllib.parse import urlparse

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "model")

SHORTENERS = {"bit.ly","tinyurl.com","goo.gl","t.co","ow.ly","is.gd","buff.ly","adf.ly","cutt.ly","rebrand.ly","shorte.st"}
SUSPICIOUS_KW = ["login","verify","update","secure","account","bank","confirm","wallet","gift","free","bonus","prize","invoice","password","signin","webscr"]
SPAM_KW = ["winner","congratulations","lottery","claim","prize","free","urgent","limited offer","click here","act now","risk-free","cash","credit","loan","viagra","crypto","investment","guaranteed","cheap","earn money","work from home","subscribe","unsubscribe"]
PHISH_PHRASES = ["verify your account","update your password","suspended","unusual activity","confirm your identity","tax refund","reset your password"]

CLF_KEYS = ["lr", "rf", "cnb"]
CLF_LABELS = {"lr": "Logistic Regression", "rf": "Random Forest", "cnb": "Complement Naive Bayes"}

def _safe_load(name):
    p = os.path.join(MODEL_DIR, name)
    return joblib.load(p) if os.path.exists(p) else None

class Detector:
    def __init__(self):
        self.url_vec = _safe_load("url_vec.pkl")
        self.txt_vec = _safe_load("txt_vec.pkl")
        self.url_clfs = {k: _safe_load(f"url_{k}.pkl") for k in CLF_KEYS}
        self.txt_clfs = {k: _safe_load(f"txt_{k}.pkl") for k in CLF_KEYS}

    def _ml_predict(self, text, vec, clfs):
        """Run all ML models, return list of {key, label, prob, risk, verdict}."""
        results = []
        if vec is None:
            return results
        X = vec.transform([text])
        for key in CLF_KEYS:
            clf = clfs.get(key)
            if clf is None:
                continue
            try:
                proba = float(clf.predict_proba(X)[0][1])
            except Exception:
                proba = 0.0
            risk = round(proba * 100.0, 1)
            results.append({
                "key": key,
                "label": CLF_LABELS[key],
                "prob": round(proba, 4),
                "risk": risk,
                "verdict": "Safe" if risk < 30 else ("Medium" if risk < 60 else "High Risk"),
            })
        return results

    def _pick_best(self, ml_results):
        """Majority vote on verdict, tiebreak by highest confidence."""
        if not ml_results:
            return None
        counts = {}
        for r in ml_results:
            counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
        max_votes = max(counts.values())
        top = [v for v, c in counts.items() if c == max_votes]
        if len(top) == 1:
            return top[0]
        # tiebreak: highest average prob among tied
        tied = [r for r in ml_results if r["verdict"] in top]
        return max(tied, key=lambda x: x["prob"])["verdict"]

    # ---------- URL ----------
    def url_features(self, url):
        u = url.strip()
        reasons, score = [], 0.0
        try: parsed = urlparse(u if "://" in u else "http://"+u)
        except Exception: parsed = None
        host = (parsed.hostname or "") if parsed else ""

        if not u.lower().startswith("https://"):
            score += 15; reasons.append("No HTTPS — connection is not encrypted")
        if len(u) > 75:
            score += 10; reasons.append(f"Unusually long URL ({len(u)} chars)")
        if "@" in u:
            score += 20; reasons.append("Contains '@' symbol — can hide real destination")
        if u.count(".") > 4:
            score += 10; reasons.append("Excessive number of dots in URL")
        if "-" in host and host.count("-") >= 2:
            score += 5; reasons.append("Multiple hyphens in domain — common in lookalikes")
        if host in SHORTENERS:
            score += 18; reasons.append(f"Shortened link ({host}) — final destination hidden")
        try:
            ipaddress.ip_address(host); score += 25; reasons.append("URL uses raw IP address instead of domain")
        except ValueError: pass
        low = u.lower()
        hits = [k for k in SUSPICIOUS_KW if k in low]
        if hits:
            score += min(20, 4*len(hits)); reasons.append("Suspicious keywords: " + ", ".join(hits[:5]))
        if re.search(r"(xn--)", host):
            score += 15; reasons.append("Punycode domain — possible homograph attack")
        if parsed and parsed.path and len(parsed.path) > 40:
            score += 5; reasons.append("Long URL path")
        return score, reasons

    def predict_url(self, url):
        h_score, reasons = self.url_features(url)
        ml_results = self._ml_predict(url, self.url_vec, self.url_clfs)
        ml_max = max([r["risk"] for r in ml_results]) if ml_results else 0.0
        if ml_results:
            best = max(ml_results, key=lambda x: x["prob"])
            reasons.append(f"Best ML model: {best['label']} ({best['prob']*100:.1f}% confidence)")
        risk = min(100.0, h_score + ml_max)
        verdict = self._pick_best(ml_results) if ml_results else self._heuristic_verdict(risk)
        return self._build_result(risk, verdict, reasons, ml_results, kind="url")

    # ---------- Text (email/sms) ----------
    def text_features(self, text):
        t = text or ""
        reasons, score = [], 0.0
        low = t.lower()
        hits = [k for k in SPAM_KW if k in low]
        if hits:
            score += min(35, 5*len(hits)); reasons.append("Spam keywords: " + ", ".join(hits[:6]))
        ph = [p for p in PHISH_PHRASES if p in low]
        if ph:
            score += min(25, 8*len(ph)); reasons.append("Phishing phrases: " + ", ".join(ph[:3]))
        urls = re.findall(r"https?://\S+|www\.\S+", t)
        if urls:
            score += 8; reasons.append(f"Contains {len(urls)} embedded link(s)")
            for u in urls[:3]:
                s2,_ = self.url_features(u)
                if s2 > 30:
                    score += 10; reasons.append(f"Embedded link looks risky: {u[:50]}")
        letters = sum(c.isalpha() for c in t)
        upp = sum(c.isupper() for c in t)
        if letters > 30 and upp/letters > 0.4:
            score += 8; reasons.append("Excessive capitalization (shouting)")
        if t.count("!") >= 3:
            score += 6; reasons.append("Multiple exclamation marks")
        if re.search(r"\b\d{4,}\b", t) and ("otp" in low or "code" in low):
            score += 10; reasons.append("Mentions OTP/code — possible account-takeover attempt")
        return score, reasons

    def predict_text(self, text, kind):
        h_score, reasons = self.text_features(text)
        ml_results = self._ml_predict(text, self.txt_vec, self.txt_clfs)
        ml_max = max([r["risk"] for r in ml_results]) if ml_results else 0.0
        if ml_results:
            best = max(ml_results, key=lambda x: x["prob"])
            reasons.append(f"Best ML model: {best['label']} ({best['prob']*100:.1f}% confidence)")
        risk = min(100.0, h_score + ml_max)
        verdict = self._pick_best(ml_results) if ml_results else self._heuristic_verdict(risk)
        return self._build_result(risk, verdict, reasons, ml_results, kind=kind)

    # ---------- Helpers ----------
    def _heuristic_verdict(self, risk):
        if risk < 30: return "Safe"
        if risk < 60: return "Medium"
        return "High Risk"

    def _build_result(self, risk, verdict, reasons, ml_results, kind):
        if risk < 30: suggestions = [
            "Looks clean, but always stay alert.",
            "Never share OTPs or passwords.",
            "Bookmark trusted sites instead of clicking links.",
        ]
        elif risk < 60: suggestions = [
            "Treat with caution — verify the sender via another channel.",
            "Hover over links before clicking.",
            "Do not enter credentials unless you are sure of the site.",
        ]
        else: suggestions = [
            "Do NOT click any links or download attachments.",
            "Report the message to your IT/security team or provider.",
            "If you already interacted, visit the Recovery Center immediately.",
            "Change your password and enable 2FA on related accounts.",
        ]
        if not reasons: reasons = ["No strong indicators detected."]

        algos = {}
        for r in ml_results:
            algos[r["key"]] = {"label": r["label"], "risk": r["risk"], "verdict": r["verdict"], "prob": r["prob"]}
        best_algo = max(ml_results, key=lambda x: x["prob"])["label"] if ml_results else "Heuristic"

        return {
            "risk_score": round(risk, 1),
            "verdict": verdict,
            "reasons": reasons,
            "suggestions": suggestions,
            "kind": kind,
            "algorithms": algos,
            "best_algorithm": best_algo,
        }

detector = Detector()
