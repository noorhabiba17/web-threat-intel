"""Web Threat Intelligence System — Flask entry point."""
import os
import json
import logging
from datetime import datetime
from typing import Any, Optional

from dotenv import load_dotenv
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, send_file, abort, Response
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import func, desc, case

load_dotenv()

from config import Config
from models import db, User, Scan, ActivityLog, ChatMessage, PageView
from forms import RegisterForm, LoginForm, ForgotForm, ScanForm
from utils.detector import detector
from utils.chatbot import chatbot_reply
from utils.pdf import build_scan_pdf

logger = logging.getLogger(__name__)


def create_app() -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    app.logger.info("Starting Web Threat Intelligence System")

    db.init_app(app)
    Migrate(app, db)
    CSRFProtect(app)
    login_manager = LoginManager(app)
    login_manager.login_view = "login"
    login_manager.login_message_category = "warning"

    @app.template_filter("fromjson")
    def fromjson_filter(val): return json.loads(val) if val else {}

    @login_manager.user_loader
    def load_user(uid: str) -> Optional[User]:
        return db.session.get(User, int(uid))

    # ── Log actions ──
    def log(action: str) -> None:
        try:
            db.session.add(ActivityLog(user_id=current_user.id if current_user.is_authenticated else None,
                                       action=action, ip=request.remote_addr))
            db.session.commit()
        except Exception:
            db.session.rollback()

    # ── Security headers ──
    @app.after_request
    def add_security_headers(response: Response) -> Response:
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com 'unsafe-inline'; "
            "style-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self' https://cdn.jsdelivr.net; "
            "connect-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "frame-ancestors 'none';"
        )
        return response

    @app.route("/favicon.ico")
    def favicon():
        return redirect(url_for("static", filename="img/favicon.svg"))

    # ── Track every page visit ──
    @app.before_request
    def track_visit() -> None:
        if request.path.startswith("/static"):
            return
        try:
            ua = request.headers.get("User-Agent", "")[:255]
            pv = PageView(
                path=request.path,
                ip=request.remote_addr,
                user_agent=ua,
                user_id=current_user.id if current_user.is_authenticated else None,
            )
            db.session.add(pv)
            db.session.commit()
        except Exception:
            db.session.rollback()

    # ---------- Auth ----------
    @app.route("/")
    def index() -> str:
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        return render_template("index.html")

    @app.route("/register", methods=["GET", "POST"])
    def register() -> str:
        form = RegisterForm()
        if form.validate_on_submit():
            if User.query.filter((User.email == form.email.data) | (User.username == form.username.data)).first():
                flash("Username or email already in use.", "danger")
            else:
                u = User(username=form.username.data.strip(), email=form.email.data.lower().strip(),
                         security_question=form.security_question.data)
                u.set_password(form.password.data)
                u.set_answer(form.security_answer.data)
                if User.query.count() == 0:
                    u.is_admin = True
                db.session.add(u)
                db.session.commit()
                log("register")
                flash("Account created. Please sign in.", "success")
                return redirect(url_for("login"))
        return render_template("register.html", form=form)

    @app.route("/login", methods=["GET", "POST"])
    def login() -> str:
        form = LoginForm()
        if form.validate_on_submit():
            u = User.query.filter_by(email=form.email.data.lower().strip()).first()
            if u and u.check_password(form.password.data):
                login_user(u)
                log("login")
                u.last_login = datetime.utcnow()
                db.session.commit()
                flash("Welcome back!", "success")
                return redirect(url_for("dashboard"))
            flash("Invalid credentials.", "danger")
        return render_template("login.html", form=form)

    @app.route("/logout")
    @login_required
    def logout() -> str:
        log("logout")
        logout_user()
        flash("Signed out.", "info")
        return redirect(url_for("index"))

    @app.route("/forgot", methods=["GET", "POST"])
    def forgot() -> str:
        form = ForgotForm()
        if form.validate_on_submit():
            u = User.query.filter_by(email=form.email.data.lower().strip()).first()
            if u and u.check_answer(form.security_answer.data):
                u.set_password(form.new_password.data)
                db.session.commit()
                flash("Password reset. Sign in with the new password.", "success")
                return redirect(url_for("login"))
            flash("Could not verify identity.", "danger")
        return render_template("forgot.html", form=form)

    # ---------- Dashboard ----------
    @app.route("/dashboard")
    @login_required
    def dashboard() -> str:
        scans = Scan.query.filter_by(user_id=current_user.id)
        total = scans.count()
        safe = scans.filter_by(verdict="Safe").count()
        med = scans.filter_by(verdict="Medium").count()
        high = scans.filter_by(verdict="High Risk").count()
        recent = scans.order_by(desc(Scan.created_at)).limit(8).all()
        rows = db.session.query(func.date(Scan.created_at).label("d"), func.count().label("n"))\
            .filter(Scan.user_id == current_user.id)\
            .group_by("d").order_by("d").limit(14).all()
        chart = {"labels": [datetime.strptime(r.d, "%Y-%m-%d").strftime("%b %d") if isinstance(r.d, str) else r.d.strftime("%b %d") for r in rows], "data": [r.n for r in rows]}
        type_counts = dict(db.session.query(Scan.scan_type, func.count()).filter_by(user_id=current_user.id).group_by(Scan.scan_type).all())
        return render_template("dashboard.html",
                               total=total, safe=safe, med=med, high=high,
                               recent=recent, chart=chart, type_counts=type_counts)

    # ---------- Scan ----------
    @app.route("/scan", methods=["GET", "POST"])
    @login_required
    def scan() -> str:
        form = ScanForm()
        result = None
        if form.validate_on_submit():
            t = form.scan_type.data
            payload = form.payload.data.strip()
            if t == "url":
                result = detector.predict_url(payload)
            else:
                result = detector.predict_text(payload, t)
            s = Scan(user_id=current_user.id, scan_type=t, input_text=payload,
                     risk_score=result["risk_score"], verdict=result["verdict"],
                     reasons="\n".join(result["reasons"]),
                     suggestions="\n".join(result["suggestions"]),
                     description=form.description.data,
                     model_details=json.dumps(result.get("algorithms",{})))
            db.session.add(s)
            current_user.total_scans = Scan.query.filter_by(user_id=current_user.id).count()
            db.session.commit()
            log(f"scan:{t}:{result['verdict']}")
            result["scan_id"] = s.id
        return render_template("scan.html", form=form, result=result)

    @app.route("/api/scan", methods=["POST"])
    @login_required
    def api_scan() -> Response:
        data = request.get_json(silent=True) or {}
        t = data.get("type", "url")
        payload = (data.get("payload") or "").strip()
        if not payload:
            return jsonify({"error": "payload required"}), 400
        res = detector.predict_url(payload) if t == "url" else detector.predict_text(payload, t)
        return jsonify(res)

    # ---------- History ----------
    @app.route("/history")
    @login_required
    def history() -> str:
        page = request.args.get("page", 1, type=int)
        q = request.args.get("q", "").strip()
        verdict = request.args.get("verdict", "")
        query = Scan.query.filter_by(user_id=current_user.id)
        if q:
            query = query.filter(Scan.input_text.ilike(f"%{q}%") | Scan.description.ilike(f"%{q}%"))
        if verdict:
            query = query.filter_by(verdict=verdict)
        pagination = query.order_by(desc(Scan.created_at)).paginate(page=page, per_page=20, error_out=False)
        return render_template("history.html", scans=pagination, q=q, verdict=verdict)

    @app.route("/history/<int:sid>")
    @login_required
    def scan_detail(sid: int) -> str:
        s = db.session.get(Scan, sid)
        if not s or s.user_id != current_user.id:
            abort(404)
        return render_template("scan_detail.html", scan=s)

    @app.route("/history/<int:sid>/delete", methods=["POST"])
    @login_required
    def delete_scan(sid: int) -> str:
        s = db.session.get(Scan, sid)
        if not s or s.user_id != current_user.id:
            abort(404)
        db.session.delete(s)
        db.session.commit()
        flash("Scan deleted.", "info")
        return redirect(url_for("history"))

    @app.route("/history/<int:sid>/pdf")
    @login_required
    def scan_pdf(sid: int) -> Response:
        s = db.session.get(Scan, sid)
        if not s or s.user_id != current_user.id:
            abort(404)
        buf = build_scan_pdf(s, current_user)
        return send_file(buf, mimetype="application/pdf", as_attachment=True,
                         download_name=f"wti_scan_{s.id}.pdf")

    # ---------- Chatbot ----------
    @app.route("/chatbot")
    @login_required
    def chatbot_page() -> str:
        return render_template("chatbot.html")

    @app.route("/api/chat", methods=["POST"])
    @login_required
    def api_chat() -> Response:
        msg = (request.get_json(silent=True) or {}).get("message", "")
        reply = chatbot_reply(msg)
        db.session.add(ChatMessage(user_id=current_user.id, message=msg, reply=reply))
        db.session.commit()
        return jsonify({"reply": reply})

    @app.route("/api/chat/history")
    @login_required
    def api_chat_history() -> Response:
        msgs = ChatMessage.query.filter_by(user_id=current_user.id)\
            .order_by(ChatMessage.created_at.asc()).limit(100).all()
        return jsonify([{"id": m.id, "msg": m.message, "reply": m.reply, "at": m.created_at.isoformat()} for m in msgs])

    # ---------- Recovery ----------
    @app.route("/recovery")
    @login_required
    def recovery() -> str:
        return render_template("recovery.html")

    # ---------- Tips ----------
    @app.route("/tips")
    @login_required
    def tips() -> str:
        return render_template("tips.html")

    # ---------- Admin ----------
    def admin_required() -> None:
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)

    @app.route("/admin")
    @login_required
    def admin() -> str:
        admin_required()
        scan_page = request.args.get("scan_page", 1, type=int)
        log_page = request.args.get("log_page", 1, type=int)
        users = User.query.order_by(User.created_at.desc()).all()
        scans = Scan.query.order_by(desc(Scan.created_at)).paginate(page=scan_page, per_page=30, error_out=False)
        today = datetime.utcnow().date()

        unique_ips_all = db.session.query(func.count(func.distinct(PageView.ip))).scalar() or 0
        unique_ips_today = db.session.query(func.count(func.distinct(PageView.ip))).filter(
            func.date(PageView.created_at) == today).scalar() or 0
        total_visits = PageView.query.count()
        visits_today = PageView.query.filter(func.date(PageView.created_at) == today).count()

        top_pages = db.session.query(
            PageView.path,
            func.count(func.distinct(PageView.ip)).label("unique_ips"),
            func.count(PageView.id).label("hits"),
        ).group_by(PageView.path).order_by(desc("hits")).limit(10).all()

        stats: dict[str, Any] = {
            "users": User.query.count(),
            "scans": Scan.query.count(),
            "high": Scan.query.filter_by(verdict="High Risk").count(),
            "med": Scan.query.filter_by(verdict="Medium").count(),
            "safe": Scan.query.filter_by(verdict="Safe").count(),
            "today_logins": ActivityLog.query.filter(
                ActivityLog.action == "login",
                func.date(ActivityLog.created_at) == today).count(),
            "today_scans": Scan.query.filter(
                func.date(Scan.created_at) == today).count(),
            "today_users": db.session.query(func.count(func.distinct(ActivityLog.user_id))).filter(
                ActivityLog.action == "login",
                func.date(ActivityLog.created_at) == today).scalar() or 0,
            "total_chats": ChatMessage.query.count(),
            "unique_ips_all": unique_ips_all,
            "unique_ips_today": unique_ips_today,
            "total_visits": total_visits,
            "visits_today": visits_today,
        }
        user_scan_stats = db.session.query(
            User.id, User.username, User.email, User.last_login, User.total_scans,
            func.count(Scan.id).label("scan_count"),
            func.sum(case((Scan.verdict == "High Risk", 1), else_=0)).label("high_count"),
            func.sum(case((Scan.verdict == "Medium", 1), else_=0)).label("med_count"),
        ).outerjoin(Scan, User.id == Scan.user_id)\
         .group_by(User.id).order_by(desc("scan_count")).all()
        logs = ActivityLog.query.order_by(desc(ActivityLog.created_at)).paginate(page=log_page, per_page=40, error_out=False)
        return render_template("admin.html", users=users, scans=scans, stats=stats,
                               logs=logs, user_scan_stats=user_scan_stats, top_pages=top_pages)

    # ---------- Error handlers ----------
    @app.errorhandler(403)
    def e403(e: Exception) -> tuple[str, int]:
        return render_template("error.html", code=403, msg="Forbidden"), 403

    @app.errorhandler(404)
    def e404(e: Exception) -> tuple[str, int]:
        return render_template("error.html", code=404, msg="Not found"), 404

    # ---------- Context processor ----------
    @app.context_processor
    def inject() -> dict[str, Any]:
        return {"now": datetime.utcnow()}

    # ---------- robots.txt ----------
    @app.route("/robots.txt")
    def robots() -> Response:
        return Response(
            "User-agent: *\n"
            "Disallow: /admin\n"
            "Disallow: /api\n"
            "Disallow: /login\n"
            "Disallow: /register\n"
            "Disallow: /forgot\n"
            "Allow: /\n",
            mimetype="text/plain",
        )

    with app.app_context():
        import socket, time
        db_host = "ep-wild-lake-aozilfkb.c-2.ap-southeast-1.aws.neon.tech"
        for attempt in range(6):
            try:
                socket.gethostbyname(db_host)
                break
            except OSError:
                if attempt < 5:
                    app.logger.warning("DNS resolve failed for Neon DB, retrying in 5s... (attempt %d/6)", attempt+2)
                    time.sleep(5)
                else:
                    app.logger.warning("Could not resolve Neon DB host after 6 attempts — check internet/DNS")
        db.create_all()
        from model.train_models import main as train_main
        need = not all(os.path.exists(os.path.join("model", f)) for f in
                       ["url_vec.pkl", "url_clf.pkl", "txt_vec.pkl", "txt_clf.pkl"])
        if need:
            app.logger.info("Training ML models (first boot)...")
            try:
                train_main()
            except Exception as e:
                app.logger.warning("ML training skipped: %s", e)
            from utils import detector as det_mod
            det_mod.detector = det_mod.Detector()

    return app

app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
