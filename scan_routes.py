import json

from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required, current_user

from extensions import db, limiter
from models import Scan
from forms import ScanForm
from scanner import run_scan, ScanError

scan_bp = Blueprint("scan", __name__)


@scan_bp.route("/dashboard")
@login_required
def dashboard():
    recent_scans = (
        Scan.query.filter_by(user_id=current_user.id)
        .order_by(Scan.created_at.desc())
        .limit(5)
        .all()
    )
    return render_template("dashboard.html", recent_scans=recent_scans)


@scan_bp.route("/scan/new", methods=["GET", "POST"])
@login_required
@limiter.limit("10 per hour")
def new_scan():
    form = ScanForm()
    if form.validate_on_submit():
        target = form.target.data.strip()
        try:
            result = run_scan(target)
        except ScanError as exc:
            flash(str(exc), "danger")
            return render_template("scan_form.html", form=form)

        scan = Scan(
            user_id=current_user.id,
            target=result["target"],
            status="completed",
            risk_score=result["risk_score"],
            risk_level=result["risk_level"],
            findings_json=json.dumps(result["findings"]),
        )
        db.session.add(scan)
        db.session.commit()
        return redirect(url_for("scan.scan_detail", scan_id=scan.id))

    return render_template("scan_form.html", form=form)


@scan_bp.route("/scan/history")
@login_required
def scan_history():
    scans = (
        Scan.query.filter_by(user_id=current_user.id)
        .order_by(Scan.created_at.desc())
        .all()
    )
    return render_template("scan_history.html", scans=scans)


@scan_bp.route("/scan/<int:scan_id>")
@login_required
def scan_detail(scan_id):
    scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    findings = json.loads(scan.findings_json) if scan.findings_json else []
    return render_template("scan_result.html", scan=scan, findings=findings)
