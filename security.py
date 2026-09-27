"""Single-operator login. Keep credentials in instance/operator.json, not git."""

from datetime import timedelta
from pathlib import Path
import hashlib
import hmac
import json
import secrets
import time
from flask import (
    abort,
    current_app,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash


def token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def validate_csrf():
    expected = session.get("csrf_token", "")
    given = request.form.get("csrf_token", "")
    if (
        not expected
        or not given
        or not hmac.compare_digest(expected.encode(), given.encode())
    ):
        abort(400, "Refresh the page and submit again (CSRF token expired).")


def load_operator(root_path):
    credential_file = Path(root_path) / "instance/operator.json"
    return json.loads(credential_file.read_text()) if credential_file.exists() else None


def install(app):
    settings = load_operator(app.root_path)
    if settings:
        app.config["OPERATOR"] = settings
        app.secret_key = settings["session_secret"]
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=4),
        MAX_CONTENT_LENGTH=16 * 1024 * 1024,
    )
    if __import__("os").environ.get("AI_PT_HTTPS") == "1":
        app.config["SESSION_COOKIE_SECURE"] = True
    attempts = {}

    @app.before_request
    def authentication():
        operator = app.config.get("OPERATOR")
        if (
            operator
            and request.endpoint not in ("login", "static")
            and not session.get("operator")
        ):
            return redirect(url_for("login"))

    @app.after_request
    def headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'"
        )
        return response

    @app.context_processor
    def context():
        return {
            "csrf_token": token(),
            "operator_enabled": bool(app.config.get("OPERATOR")),
        }

    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        if request.method == "POST":
            validate_csrf()
            key = request.remote_addr or "local"
            now = time.monotonic()
            recent = [t for t in attempts.get(key, []) if t > now - 60]
            if len(recent) >= 5:
                return (
                    render_template(
                        "login.html", error="Wait one minute before retrying."
                    ),
                    429,
                )
            operator = app.config.get("OPERATOR")
            valid = operator and check_password_hash(
                operator["password_hash"], request.form.get("password", "")
            )
            valid = valid and hmac.compare_digest(
                operator["username"].encode(), request.form.get("username", "").encode()
            )
            if valid:
                session.clear()
                session["operator"] = operator["username"]
                session.permanent = True
                attempts.pop(key, None)
                return redirect("/")
            attempts[key] = recent + [now]
            error = "Invalid login"
        return render_template("login.html", error=error)

    @app.post("/logout")
    def logout():
        validate_csrf()
        session.clear()
        return redirect("/login")
