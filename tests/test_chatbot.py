"""Tests for the cybersecurity chatbot matching engine."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from utils.chatbot import extract_keywords, tokenize_question, reply, score_message, _direct_match, TOPICS


class TestExtractKeywords:
    def test_removes_stopwords(self):
        kws = extract_keywords("what is phishing")
        assert "what" not in kws
        assert "is" not in kws
        assert "phishing" in kws

    def test_short_words_filtered(self):
        kws = extract_keywords("a an to be")
        assert all(len(w) > 1 for w in kws)

    def test_case_insensitive(self):
        kws1 = extract_keywords("Phishing Attack")
        kws2 = extract_keywords("phishing attack")
        assert kws1 == kws2

    def test_extracts_multiple_keywords(self):
        kws = extract_keywords("how to create a strong password")
        assert "create" in kws
        assert "strong" in kws
        assert "password" in kws


class TestTokenizeQuestion:
    def test_what_is_phishing(self):
        qtype, target = tokenize_question("what is phishing")
        assert qtype == "what_is"
        assert "phishing" in target

    def test_how_to_create(self):
        qtype, target = tokenize_question("how to create a strong password")
        assert qtype == "how_to"
        assert "create" in target or "strong" in target

    def test_explain_topic(self):
        qtype, target = tokenize_question("explain two factor authentication")
        assert qtype == "explain"
        assert "two factor" in target or "authentication" in target

    def test_statement_fallback(self):
        qtype, target = tokenize_question("I think my account was hacked")
        assert qtype == "statement"
        assert target == ""

    def test_why_question(self):
        qtype, target = tokenize_question("why do hackers use phishing")
        assert qtype == "why"

    def test_recommend_question(self):
        qtype, target = tokenize_question("what is the best password manager")
        # "what is" pattern matches first; target still captures the topic
        assert qtype in ("what_is", "recommend")
        assert "password" in target or "best" in target


class TestDirectMatch:
    def test_clicked_link_triggers_recovery(self):
        topic = _direct_match("I clicked a phishing link")
        assert topic is not None
        assert topic["name"] == "recovery"

    def test_ransomware_triggers_malware(self):
        topic = _direct_match("I have ransomware")
        assert topic is not None
        assert topic["name"] == "malware"

    def test_public_wifi_triggers(self):
        topic = _direct_match("how to stay safe on public wifi")
        assert topic is not None
        assert topic["name"] == "public wifi"

    def test_no_match_returns_none(self):
        topic = _direct_match("hello world")
        assert topic is None


class TestScoreMessage:
    def test_matching_keywords_return_score(self):
        topic = TOPICS[0]  # phishing
        score, matched = score_message("I got a phishing email", topic)
        assert score > 0
        assert "phishing" in matched or "phishing email" in matched

    def test_non_matching_returns_zero(self):
        topic = TOPICS[0]  # phishing
        score, matched = score_message("hello world", topic)
        assert score == 0
        assert matched == []

    def test_multiple_matches_boost_score(self):
        topic = TOPICS[0]  # phishing
        score_single, _ = score_message("phishing", topic)
        score_multi, _ = score_message("phishing email scam fake email", topic)
        assert score_multi > score_single


class TestReply:
    def test_empty_message_returns_greeting(self):
        r = reply("")
        assert len(r) > 0
        assert "Ask me" in r or "help" in r or "cybersecurity" in r

    def test_phishing_question(self):
        r = reply("what is phishing")
        assert "phish" in r.lower()

    def test_password_question(self):
        r = reply("how to create a strong password")
        assert "password" in r.lower()

    def test_hello_returns_greeting(self):
        r = reply("hello")
        assert any(word in r.lower() for word in ["hello", "hi", "cybersecurity", "assistant", "help"])

    def test_thanks_reply(self):
        r = reply("thank you")
        assert any(word in r.lower() for word in ["welcome", "glad", "stay safe", "anytime"])

    def test_hacked_response(self):
        r = reply("my account was hacked")
        assert any(word in r.lower() for word in ["hack", "compromised", "breach", "password"])

    def test_2fa_question(self):
        r = reply("what is two factor authentication")
        assert "factor" in r.lower() or "2FA" in r or "authentication" in r.lower()

    def test_unknown_question_fallback(self):
        r = reply("purple monkey dishwasher")
        assert len(r) > 0
