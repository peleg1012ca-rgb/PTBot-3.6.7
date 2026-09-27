"""Portfolio workbench UI, operator workflows and read-only exports."""

import io
import json
import sqlite3
import xml.etree.ElementTree as ET
from flask import (
    Blueprint,
    abort,
    current_app,
    redirect,
    render_template,
    request,
    session,
    url_for,
    Response,
    jsonify,
)
from config import DATABASE_PATH
import workbench_store as store
import engagement_store
from security import token, validate_csrf
from execution import execute
from importers import import_records
from pt_toolkit.request_plan import plan, raw_request
from scope_engine import check_scope

bp = Blueprint("workbench", __name__)


def db():
    return current_app.config.get("DATABASE_PATH", DATABASE_PATH)


def engagement(eid):
    data = engagement_store.get_engagement(db(), eid)
    if data is None:
        abort(404)
    return data


@bp.before_request
def csrf():
    if request.method == "POST":
        validate_csrf()


def dashboard():
    counts, recent = store.dashboard(db())
    with store.connect(db()) as c:
        legacy = [
            dict(r) for r in c.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 10")
        ]
    return render_template(
        "dashboard.html", counts=counts, recent=recent, legacy=legacy
    )


@bp.route("/workbench/<int:eid>", methods=["GET", "POST"])
def tools(eid):
    data = engagement(eid)
    error = None
    if request.method == "POST":
        try:
            ports = [
                int(p.strip())
                for p in request.form.get("ports", "").split(",")
                if p.strip()
            ]
            rid = execute(
                db(),
                eid,
                request.form.get("action", ""),
                request.form.get("target", "").strip(),
                request.form.get("method", "GET"),
                ports,
            )
            return redirect(url_for("workbench.run", eid=eid, rid=rid))
        except (ValueError, sqlite3.Error) as exc:
            error = (
                str(exc)
                if isinstance(exc, ValueError)
                else "Storage unavailable; inspect local logs."
            )
    return render_template("tools.html", data=data, error=error), 400 if error else 200


@bp.route("/engagements/<int:eid>/runs/<int:rid>")
def run(eid, rid):
    data = engagement(eid)
    item = store.detail(db(), eid, rid)
    if item is None:
        abort(404)
    if item["action_type"] == "website_recon":
        return redirect(url_for("recon.result", eid=eid, rid=rid))
    return render_template("run.html", data=data, run=item)


@bp.post("/engagements/<int:eid>/runs/<int:rid>/observations/<int:oid>/review")
def review(eid, rid, oid):
    engagement(eid)
    try:
        store.review(
            db(),
            eid,
            rid,
            oid,
            request.form.get("status", ""),
            request.form.get("note", ""),
            session.get("operator", "local operator"),
        )
    except ValueError as exc:
        abort(400, str(exc))
    except LookupError:
        abort(404)
    return redirect(url_for("workbench.run", eid=eid, rid=rid))


@bp.post("/engagements/<int:eid>/revoke")
def revoke(eid):
    engagement(eid)
    with store.connect(db()) as c:
        c.execute(
            "UPDATE engagements SET status='revoked' WHERE id=? AND status='approved'",
            (eid,),
        )
    return redirect(f"/engagements/{eid}")


@bp.route("/imports/<int:eid>", methods=["GET", "POST"])
def imports(eid):
    data = engagement(eid)
    error = None
    ids = []
    if request.method == "POST":
        try:
            upload = request.files.get("capture")
            if upload is None:
                raise ValueError("Choose a capture file")
            ids = import_records(
                db(),
                eid,
                request.form.get("kind", ""),
                upload.stream.read(8 * 1024 * 1024 + 1),
            )
        except (ValueError, IndexError, ET.ParseError, sqlite3.Error):
            error = "Import failed: verify format, size, and approved target scope."
    return render_template("imports.html", data=data, error=error, ids=ids), (
        400 if error else 200
    )


@bp.route("/plans/<int:eid>", methods=["GET", "POST"])
def plans(eid):
    data = engagement(eid)
    error = None
    result = None
    if request.method == "POST":
        target = request.form.get("target", "")
        try:
            if not check_scope(db(), eid, target).allowed:
                raise ValueError("Target must be in approved scope")
            result = plan(target)
            result["raw"] = [raw_request(v) for v in result["variants"]]
        except ValueError as exc:
            error = str(exc)
    return render_template("plans.html", data=data, error=error, result=result), (
        400 if error else 200
    )


@bp.get("/reports/<int:eid>")
def report(eid):
    data = store.report(db(), eid)
    if data is None:
        abort(404)
    if request.args.get("format") == "json":
        return Response(
            json.dumps(data, ensure_ascii=False, indent=2),
            mimetype="application/json",
            headers={
                "Content-Disposition": f"attachment; filename=engagement-{eid}.json"
            },
        )
    return render_template("report.html", report=data)


@bp.get("/catalog")
def catalog():
    return render_template("catalog.html")


@bp.get('/xss')
def xss_index():
    from recon_store import recent
    return render_template('assessments.html', engagements=engagement_store.list_engagements(db()), recent=recent(db()))


@bp.route('/xss/<int:eid>', methods=['GET', 'POST'])
def xss(eid):
    import xss_engine
    data = engagement(eid)
    error = None
    if request.method == 'POST':
        try:
            rid = xss_engine.start(db(), eid, request.form.get('target', '').strip(),
                request.form.get('parameters', ''), request.form.get('verify') == 'yes')
            return redirect(url_for('workbench.run', eid=eid, rid=rid))
        except (ValueError, sqlite3.Error) as exc:
            error = str(exc) if isinstance(exc, ValueError) else 'Local data could not be saved.'
    return render_template('xss.html', data=data, error=error), 400 if error else 200


@bp.get('/engagements/<int:eid>/runs/<int:rid>/status')
def run_status(eid, rid):
    engagement(eid)
    item = store.detail(db(), eid, rid)
    if item is None:
        abort(404)
    xss = item.get('xss') or {}
    return jsonify(status=item['status'], progress=xss.get('progress', ''),
                   requests=xss.get('requests_sent', 0), checks=len(xss.get('checks', [])))


@bp.post('/engagements/<int:eid>/runs/<int:rid>/cancel')
def cancel_run(eid, rid):
    item = store.detail(db(), eid, rid)
    if item is None or not item.get('xss'):
        abort(404)
    with store.connect(db()) as c:
        c.execute('UPDATE xss_runs SET cancel_requested=1 WHERE run_id=?', (rid,))
    return redirect(url_for('workbench.run', eid=eid, rid=rid))
