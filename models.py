from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    security_question = db.Column(db.String(255))
    security_answer_hash = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    total_scans = db.Column(db.Integer, default=0)
    scans = db.relationship("Scan", backref="user", lazy=True, cascade="all, delete-orphan")
    logs = db.relationship("ActivityLog", backref="user", lazy=True, cascade="all, delete-orphan")
    chat_messages = db.relationship("ChatMessage", backref="user", lazy=True, cascade="all, delete-orphan")

    def set_password(self, pw): self.password_hash = generate_password_hash(pw)
    def check_password(self, pw): return check_password_hash(self.password_hash, pw)
    def set_answer(self, a): self.security_answer_hash = generate_password_hash(a.lower().strip())
    def check_answer(self, a): return check_password_hash(self.security_answer_hash, a.lower().strip())

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    scan_type = db.Column(db.String(20), nullable=False)  # url|email|sms
    input_text = db.Column(db.Text, nullable=False)
    risk_score = db.Column(db.Float, nullable=False)
    verdict = db.Column(db.String(20), nullable=False)    # Safe|Medium|High Risk
    reasons = db.Column(db.Text)                          # newline separated
    suggestions = db.Column(db.Text)
    description = db.Column(db.String(255))
    model_details = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    action = db.Column(db.String(120))
    ip = db.Column(db.String(60))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    message = db.Column(db.Text, nullable=False)
    reply = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class PageView(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    path = db.Column(db.String(255), nullable=False)
    ip = db.Column(db.String(60))
    user_agent = db.Column(db.String(255))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
