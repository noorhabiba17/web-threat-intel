"""Tests for the hybrid threat detector heuristics."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from utils.detector import Detector

detector = Detector()


class TestURLFeatures:
    def test_no_https_adds_score(self):
        score, reasons = detector.url_features("http://example.com")
        assert score >= 8
        assert any("HTTPS" in r for r in reasons)

    def test_https_no_flag(self):
        score, reasons = detector.url_features("https://example.com")
        assert any("HTTPS" not in r for r in reasons) or score < 20

    def test_long_url_adds_score(self):
        url = "https://" + "a" * 80 + ".com"
        score, reasons = detector.url_features(url)
        assert score >= 10
        assert any("long" in r.lower() for r in reasons)

    def test_at_symbol_adds_score(self):
        score, reasons = detector.url_features("https://real.com@evil.com")
        assert score >= 20
        assert any("@" in r for r in reasons)

    def test_excessive_dots(self):
        score, reasons = detector.url_features("https://a.b.c.d.e.com")
        assert score >= 10
        assert any("dots" in r.lower() for r in reasons)

    def test_ip_address_url(self):
        score, reasons = detector.url_features("http://192.168.1.1/login")
        assert score >= 25
        assert any("IP" in r for r in reasons)

    def test_shortener_url(self):
        score, reasons = detector.url_features("http://bit.ly/xyz123")
        assert score >= 18
        assert any("Shortened" in r for r in reasons)

    def test_suspicious_keywords(self):
        score, reasons = detector.url_features("https://login-secure-bank.com/verify")
        assert score >= 8
        assert any("keywords" in r.lower() or "login" in r.lower() for r in reasons)

    def test_punycode_url(self):
        score, reasons = detector.url_features("http://xn--pple-43d.com")
        assert score >= 15
        assert any("Punycode" in r for r in reasons)

    def test_clean_url_low_score(self):
        score, reasons = detector.url_features("https://www.google.com")
        assert score < 30
        assert len(reasons) == 0 or all("No strong indicators" not in r for r in reasons)


class TestTextFeatures:
    def test_spam_keywords(self):
        score, reasons = detector.text_features("Congratulations! You won a free prize. Click here now!")
        assert score >= 15
        assert any("Spam keywords" in r for r in reasons)

    def test_phishing_phrases(self):
        score, reasons = detector.text_features("Please verify your account to avoid suspension.")
        assert score >= 8
        assert any("Phishing" in r for r in reasons)

    def test_excessive_caps(self):
        score, reasons = detector.text_features("URGENT: YOUR ACCOUNT HAS BEEN COMPROMISED. ACT NOW!!!")
        assert score >= 14  # 8 for caps + 6 for exclamation
        assert any("capitalization" in r.lower() or "shouting" in r.lower() for r in reasons)

    def test_otp_mention(self):
        score, reasons = detector.text_features("Your OTP code is 482910. Share with agent to verify.")
        assert score >= 10
        assert any("OTP" in r for r in reasons)

    def test_embedded_risky_link(self):
        score, reasons = detector.text_features("Check this out: http://bit.ly/xyz123")
        assert score >= 8
        assert any("embedded" in r.lower() or "link" in r.lower() for r in reasons)

    def test_clean_text_low_score(self):
        score, reasons = detector.text_features("Hi team, sharing the meeting notes from today.")
        assert score < 10
        assert not reasons or all("No strong indicators" not in r for r in reasons)


class TestVerdict:
    def test_safe_below_30(self):
        result = detector._verdict(15.0, ["Minor issue"], "url")
        assert result["verdict"] == "Safe"
        assert result["risk_score"] == 15.0

    def test_medium_30_to_60(self):
        result = detector._verdict(45.0, ["Some concerns"], "email")
        assert result["verdict"] == "Medium"
        assert 30 <= result["risk_score"] <= 60

    def test_high_risk_above_60(self):
        result = detector._verdict(85.0, ["Multiple threats"], "sms")
        assert result["verdict"] == "High Risk"
        assert result["risk_score"] >= 60

    def test_empty_reasons_fallback(self):
        result = detector._verdict(10.0, [], "url")
        assert "No strong indicators" in result["reasons"][0]

    def test_result_keys(self):
        result = detector._verdict(50.0, ["test"], "email")
        assert set(result.keys()) == {"risk_score", "verdict", "reasons", "suggestions", "kind"}


class TestPredictURL:
    def test_predict_phishing_url(self):
        result = detector.predict_url("http://bit.ly/free-gift-card")
        assert result["verdict"] in ("High Risk", "Medium")
        assert result["risk_score"] >= 18

    def test_predict_safe_url(self):
        result = detector.predict_url("https://www.python.org")
        assert result["risk_score"] < 50


class TestPredictText:
    def test_predict_spam(self):
        result = detector.predict_text("CONGRATULATIONS! You have WON a free iPhone. Click here now!", "sms")
        assert result["verdict"] in ("High Risk", "Medium")
        assert result["risk_score"] >= 20

    def test_predict_clean(self):
        result = detector.predict_text("Meeting at 3pm tomorrow.", "email")
        assert result["verdict"] == "Safe"
        assert result["risk_score"] < 30
