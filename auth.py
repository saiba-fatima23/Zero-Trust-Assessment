import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_user, logout_user, login_required, current_user
from flask_mail import Message
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from extensions import db, mail, limiter, login_manager
from models import User
from forms import RegisterForm, LoginForm, ResendVerificationForm

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

VERIFY_SALT = "email-verify"
TOKEN_MAX_AGE_SECONDS = 24 * 60 * 60  # 24 hours


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _as_aware_utc(dt):
    """SQLite drops tzinfo on round-trip; treat naive datetimes as UTC."""
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _demo_mode() -> bool:
    """True when no mail server is configured — skip email verification
    entirely so the app is usable end-to-end without SMTP credentials."""
    return not current_app.config.get("MAIL_USERNAME")


def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"])


def _issue_verification_token(user: User) -> str:
    """Create a verification token, store only its hash, return the raw token."""
    raw_token = _serializer().dumps(user.id, salt=VERIFY_SALT) + "." + secrets.token_urlsafe(8)
    user.verification_token_hash = _hash_token(raw_token)
    user.verification_token_expires_at = datetime.now(timezone.utc) + timedelta(
        seconds=TOKEN_MAX_AGE_SECONDS
    )
    return raw_token


def _send_verification_email(user: User, raw_token: str):
    verify_url = url_for("auth.verify_email", token=raw_token, _external=True)
    msg = Message(
        subject="Verify your ZeroTrust account",
        recipients=[user.email],
        body=(
            f"Hi {user.username},\n\n"
            f"Confirm your email address to activate your ZeroTrust account:\n"
            f"{verify_url}\n\n"
            f"This link expires in 24 hours. If you didn't create this account, "
            f"ignore this email."
        ),
        html=render_template("email/verify_email.html", user=user, verify_url=verify_url),
    )
    if current_app.config.get("MAIL_USERNAME"):
        mail.send(msg)
    else:
        # No mail credentials configured (e.g. local/demo run) — log instead of failing.
        current_app.logger.warning(
            "MAIL_USERNAME not set; skipping send. Verification link for %s: %s",
            user.email, verify_url
        )


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("scan.dashboard"))

    form = RegisterForm()
    if form.validate_on_submit():
        existing = User.query.filter(
            (User.email == form.email.data.lower()) | (User.username == form.username.data)
        ).first()
        if existing:
            flash("An account with that username or email already exists.", "danger")
            return render_template("auth/register.html", form=form)

        user = User(
            username=form.username.data,
            email=form.email.data.lower(),
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.flush()  # assign an id before generating the token

        if _demo_mode():
            # No SMTP configured — skip the email step entirely so the app
            # is fully usable for a demo/FYP walkthrough.
            user.email_verified = True
            user.is_active = True
            db.session.commit()
            login_user(user)
            flash(
                "Demo mode: no email server is configured, so your account "
                "was verified automatically.", "info"
            )
            return redirect(url_for("scan.dashboard"))

        raw_token = _issue_verification_token(user)
        db.session.commit()

        try:
            _send_verification_email(user, raw_token)
        except Exception:
            current_app.logger.exception("Failed to send verification email")
            flash(
                "Account created, but the verification email could not be sent. "
                "Try resending it below.", "warning"
            )
            return redirect(url_for("auth.resend_verification"))

        flash("Account created! Check your email to verify your account.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html", form=form)


@auth_bp.route("/verify/<token>")
def verify_email(token):
    try:
        user_id = _serializer().loads(token.rsplit(".", 1)[0], salt=VERIFY_SALT, max_age=TOKEN_MAX_AGE_SECONDS)
    except SignatureExpired:
        flash("That verification link has expired. Request a new one below.", "warning")
        return redirect(url_for("auth.resend_verification"))
    except (BadSignature, ValueError):
        flash("That verification link is invalid.", "danger")
        return redirect(url_for("auth.login"))

    user = User.query.get(user_id)
    if not user:
        flash("That verification link is invalid.", "danger")
        return redirect(url_for("auth.login"))

    if user.email_verified:
        flash("Your email is already verified. You can log in.", "info")
        return redirect(url_for("auth.login"))

    if (
        not user.verification_token_hash
        or user.verification_token_hash != _hash_token(token)
        or not user.verification_token_expires_at
        or _as_aware_utc(user.verification_token_expires_at) < datetime.now(timezone.utc)
    ):
        flash("That verification link is invalid or has already been used.", "danger")
        return redirect(url_for("auth.resend_verification"))

    user.email_verified = True
    user.is_active = True
    user.verification_token_hash = None
    user.verification_token_expires_at = None
    db.session.commit()

    flash("Email verified! You can now log in.", "success")
    return redirect(url_for("auth.login"))


@auth_bp.route("/resend-verification", methods=["GET", "POST"])
def resend_verification():
    form = ResendVerificationForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        # Always show the same message to avoid leaking which emails are registered.
        if user and not user.email_verified:
            raw_token = _issue_verification_token(user)
            db.session.commit()
            try:
                _send_verification_email(user, raw_token)
            except Exception:
                current_app.logger.exception("Failed to resend verification email")
        flash("If that account exists and isn't verified yet, a new link has been sent.", "info")
        return redirect(url_for("auth.login"))
    return render_template("auth/resend_verification.html", form=form)


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("scan.dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()

        if not user or not user.check_password(form.password.data):
            flash("Invalid email or password.", "danger")
            return render_template("auth/login.html", form=form)

        if not user.email_verified or not user.is_active:
            if _demo_mode():
                # Self-heal accounts created before demo mode was enabled,
                # or if MAIL_USERNAME was removed after registration.
                user.email_verified = True
                user.is_active = True
                db.session.commit()
            else:
                flash("Please verify your email before logging in.", "warning")
                return render_template("auth/login.html", form=form)

        login_user(user, remember=form.remember.data)
        next_page = request.args.get("next")
        return redirect(next_page or url_for("scan.dashboard"))

    return render_template("auth/login.html", form=form)


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))
